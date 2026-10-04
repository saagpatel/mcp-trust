"""Read-only, deterministic review surfaces for immutable refresh candidates.

The review room consumes the existing ``RefreshCandidateV1`` contract.  It does
not create, approve, publish, deploy, or schedule candidates.  Candidate values
are only rendered as escaped text through a closed component catalog.
"""

from __future__ import annotations

import hashlib
import html
import json
import os
import sqlite3
import stat
import unicodedata
from dataclasses import asdict, dataclass, replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from mcp_trust.core.drift import diff_latest
from mcp_trust.refresh import DEFAULT_MAX_AGE_HOURS, verify_refresh_candidate
from mcp_trust.store.repository import ScanRepository

ReviewStatus = Literal["reviewable", "fixture", "stale", "blocked"]

COMPONENT_CATALOG = (
    "authority-banner",
    "candidate-identity",
    "review-status",
    "decisive-unknowns",
    "validation-evidence",
    "fixed-lifecycle",
    "scan-evidence-table",
    "text-fallback",
)

_AUTHORITY_ORDER = (
    ("candidate_creation", "Candidate creation"),
    ("approval", "Approve"),
    ("publication", "Publish locally"),
    ("deployment", "Deploy"),
    ("schedule_change", "Schedule"),
)
_MAX_JSON_BYTES = 16 * 1024 * 1024
_MAX_CANDIDATE_BYTES = 128 * 1024 * 1024
_MAX_CELL_TEXT = 240


@dataclass(frozen=True)
class CandidateIdentity:
    """Host-owned identity and provenance displayed on every surface."""

    candidate_name: str
    manifest_sha256: str
    schema: str
    created_at: str
    expires_at: str
    candidate_state: str
    scan_mode: str
    engine_versions: tuple[str, ...]
    source_binding: str


@dataclass(frozen=True)
class EvidenceRow:
    """One public-safe candidate result prepared for an allowlisted table."""

    server_slug: str
    server_name: str
    state: str
    current_grade: str
    previous_grade: str
    transparency: str
    drift_summary: str
    receipt_state: str
    scanned_at: str
    changed: bool
    masked: bool
    flagged: bool
    flags: tuple[str, ...]


@dataclass(frozen=True)
class ReviewSurface:
    """Deterministic semantic surface independent of HTML presentation."""

    schema: str
    component_catalog: tuple[str, ...]
    identity: CandidateIdentity
    status: ReviewStatus
    status_label: str
    status_explanation: str
    publication_ready_after_separate_approval: bool
    authority: tuple[tuple[str, str, bool], ...]
    scan_counts: tuple[tuple[str, int], ...]
    decisive_unknowns: tuple[str, ...]
    validation_errors: tuple[str, ...]
    rows: tuple[EvidenceRow, ...]
    changed_count: int
    masked_count: int
    flagged_count: int
    review_conclusion: str

    def model_dump(self) -> dict[str, object]:
        """Return a JSON-serializable representation for tests and adapters."""
        return asdict(self)


def _short_text(value: object, *, fallback: str = "UNKNOWN") -> str:
    if not isinstance(value, str) or not value.strip():
        return fallback
    safe = "".join(
        character
        for character in value
        if character in "\t\n\r" or unicodedata.category(character) not in {"Cc", "Cf"}
    )
    normalized = " ".join(safe.split())
    if not normalized:
        return fallback
    if len(normalized) > _MAX_CELL_TEXT:
        return normalized[: _MAX_CELL_TEXT - 1] + "…"
    return normalized


def _timestamp_text(value: object) -> str:
    """Return a compact UTC timestamp without weakening unknown handling."""
    text = _short_text(value)
    if text == "UNKNOWN":
        return text
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return text
    return parsed.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _authority_state(key: str, available: bool) -> str:
    """Describe evidence about authority without granting an action."""
    if key == "candidate_creation" and available:
        return "recorded"
    return "available" if available else "unavailable"


def _read_stable_bytes(
    path: Path,
    *,
    max_bytes: int,
    require_read_only: bool,
) -> bytes:
    """Read one owner-controlled stable file without following links."""
    before = path.lstat()
    if (
        not stat.S_ISREG(before.st_mode)
        or path.is_symlink()
        or before.st_uid != os.geteuid()
        or (require_read_only and before.st_mode & 0o277)
        or before.st_size > max_bytes
    ):
        raise ValueError(f"unsafe stable artifact: {path.name}")
    flags = os.O_RDONLY
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as handle:
        opened = os.fstat(handle.fileno())
        content = handle.read(max_bytes + 1)
        after_read = os.fstat(handle.fileno())
    after_path = path.lstat()
    signatures = {
        (item.st_dev, item.st_ino, item.st_mode, item.st_size, item.st_mtime_ns)
        for item in (before, opened, after_read, after_path)
    }
    if len(signatures) != 1 or len(content) > max_bytes:
        raise ValueError(f"stable artifact changed during read: {path.name}")
    return content


def _read_immutable_json(path: Path) -> Any:
    """Read one owner-private immutable JSON artifact without following links."""
    content = _read_stable_bytes(
        path,
        max_bytes=_MAX_JSON_BYTES,
        require_read_only=True,
    )
    return json.loads(content.decode("utf-8"))


def _candidate_tree_fingerprint(candidate: Path) -> tuple[tuple[str, int, str], ...]:
    """Bind verification and projection to one stable immutable candidate tree."""
    root = candidate.lstat()
    if (
        not stat.S_ISDIR(root.st_mode)
        or candidate.is_symlink()
        or root.st_uid != os.geteuid()
        or root.st_mode & 0o277
    ):
        raise ValueError("unsafe candidate root")
    fingerprint: list[tuple[str, int, str]] = []
    total_bytes = 0
    for current, directories, files in os.walk(candidate, followlinks=False):
        current_path = Path(current)
        for directory in directories:
            path = current_path / directory
            metadata = path.lstat()
            if (
                not stat.S_ISDIR(metadata.st_mode)
                or path.is_symlink()
                or metadata.st_uid != os.geteuid()
                or metadata.st_mode & 0o277
            ):
                raise ValueError(f"unsafe candidate directory: {directory}")
        for filename in files:
            path = current_path / filename
            relative = path.relative_to(candidate).as_posix()
            content = _read_stable_bytes(
                path,
                max_bytes=_MAX_CANDIDATE_BYTES,
                require_read_only=True,
            )
            total_bytes += len(content)
            if total_bytes > _MAX_CANDIDATE_BYTES:
                raise ValueError("candidate tree exceeds review limit")
            fingerprint.append((relative, len(content), hashlib.sha256(content).hexdigest()))
    return tuple(sorted(fingerprint))


def _review_input_fingerprint(path: Path) -> tuple[int, int, int, str]:
    """Capture one stable reviewed input even when the working copy is writable."""
    content = _read_stable_bytes(
        path,
        max_bytes=_MAX_JSON_BYTES,
        require_read_only=False,
    )
    metadata = path.lstat()
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mtime_ns,
        hashlib.sha256(content).hexdigest(),
    )


def _load_candidate_projection(candidate: Path) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    manifest = _read_immutable_json(candidate / "MANIFEST.json")
    scan_payload = _read_immutable_json(candidate / "scan_results.json")
    catalog_payload = _read_immutable_json(candidate / "catalog_identity.json")
    if not isinstance(manifest, dict):
        raise ValueError("manifest is not an object")
    results = scan_payload.get("results") if isinstance(scan_payload, dict) else None
    catalog = catalog_payload.get("servers") if isinstance(catalog_payload, dict) else None
    if not isinstance(results, list) or not all(isinstance(row, dict) for row in results):
        raise ValueError("scan results are not an object list")
    if not isinstance(catalog, list) or not all(isinstance(row, dict) for row in catalog):
        raise ValueError("catalog identity is not an object list")
    names = {
        row.get("slug"): row.get("name")
        for row in catalog
        if isinstance(row.get("slug"), str) and isinstance(row.get("name"), str)
    }
    projected: list[dict[str, Any]] = []
    for result in results:
        projected.append({**result, "_server_name": names.get(result.get("server_slug"))})
    return manifest, projected


def _is_changed(result: dict[str, Any]) -> bool:
    drift = result.get("drift")
    if not isinstance(drift, dict):
        return False
    return bool(
        drift.get("cause") not in {None, "no-change"}
        or drift.get("surface_comparison") not in {None, "unchanged"}
        or (
            drift.get("previous_grade") is not None
            and drift.get("current_grade") is not None
            and drift.get("previous_grade") != drift.get("current_grade")
        )
    )


def _result_flags(result: dict[str, Any], *, changed: bool, masked: bool) -> tuple[str, ...]:
    flags: list[str] = []
    state = result.get("state")
    if state not in {"fresh", "masked"}:
        flags.append(f"result state: {_short_text(state)}")
    if masked:
        flags.append("grade, transparency, receipt, and drift are withheld")
    if changed:
        flags.append("grade or declared tool surface changed")
    if result.get("transparency") == "low":
        flags.append("low transparency")
    if result.get("receipt_visibility") not in {"reviewable", "withheld"}:
        flags.append("receipt visibility is unknown")
    return tuple(flags)


def _row_from_result(
    result: dict[str, Any],
    *,
    evidence_valid: bool = True,
) -> EvidenceRow:
    state = _short_text(result.get("state"))
    masked = state == "masked"
    changed = _is_changed(result) and not masked
    drift = result.get("drift")
    drift_summary = (
        _short_text(drift.get("summary"))
        if isinstance(drift, dict)
        else "WITHHELD" if masked else "No comparable drift evidence"
    )
    current_grade = "WITHHELD" if masked else _short_text(result.get("fresh_grade"))
    previous_grade = (
        "WITHHELD"
        if masked
        else _short_text(
            drift.get("previous_grade") if isinstance(drift, dict) else result.get("previous_grade")
        )
    )
    receipt_state = (
        "WITHHELD"
        if masked
        else "UNVERIFIED"
        if not evidence_valid
        else "BOUND"
        if result.get("receipt_visibility") == "reviewable" and result.get("receipt")
        else "MISSING"
    )
    flags = _result_flags(result, changed=changed, masked=masked)
    return EvidenceRow(
        server_slug=_short_text(result.get("server_slug")),
        server_name=_short_text(result.get("_server_name")),
        state=state,
        current_grade=current_grade,
        previous_grade=previous_grade,
        transparency="WITHHELD" if masked else _short_text(result.get("transparency")),
        drift_summary=drift_summary,
        receipt_state=receipt_state,
        scanned_at=_timestamp_text(result.get("scanned_at")),
        changed=changed,
        masked=masked,
        flagged=bool(flags),
        flags=flags,
    )


def _expected_drift_payload(candidate: Path, result: dict[str, Any]) -> dict[str, str] | None:
    slug = result.get("server_slug")
    if not isinstance(slug, str):
        raise ValueError("result slug is unavailable")
    database = (candidate / "registry.db").resolve()
    connection = sqlite3.connect(
        f"{database.as_uri()}?mode=ro&immutable=1",
        uri=True,
    )
    connection.row_factory = sqlite3.Row
    try:
        drift = diff_latest(ScanRepository(connection).history(slug, limit=2))
    finally:
        connection.close()
    if drift is None:
        return None
    return {
        "cause": str(drift.cause),
        "surface_comparison": str(drift.surface_comparison),
        "summary": drift.summary,
        "previous_grade": str(drift.previous_grade),
        "current_grade": str(drift.current_grade),
    }


def _projection_semantic_errors(
    candidate: Path,
    manifest: dict[str, Any],
    raw_rows: list[dict[str, Any]],
    *,
    now: datetime,
) -> tuple[tuple[str, ...], bool]:
    """Validate review claims not currently owned by the production verifier."""
    errors: list[str] = []
    explicitly_expired = False
    try:
        created_at = datetime.fromisoformat(str(manifest["created_at"]).replace("Z", "+00:00"))
        expires_at = datetime.fromisoformat(str(manifest["expires_at"]).replace("Z", "+00:00"))
        if created_at.tzinfo is None or expires_at.tzinfo is None:
            raise ValueError("candidate timestamps must be timezone-aware")
        expected_expiry = created_at.astimezone(UTC) + timedelta(hours=DEFAULT_MAX_AGE_HOURS)
        if expires_at.astimezone(UTC) != expected_expiry:
            errors.append("candidate_expiry_mismatch")
        explicitly_expired = now.astimezone(UTC) >= expires_at.astimezone(UTC)
    except (KeyError, TypeError, ValueError):
        errors.append("candidate_expiry_invalid")

    if manifest.get("candidate_state") == "complete" and not raw_rows:
        errors.append("complete_candidate_has_no_evidence")

    for result in raw_rows:
        if result.get("state") != "fresh":
            continue
        slug = _short_text(result.get("server_slug")).replace(":", "_")
        try:
            expected = _expected_drift_payload(candidate, result)
        except (OSError, sqlite3.Error, TypeError, ValueError):
            errors.append(f"drift_binding_unavailable:{slug}")
            continue
        if result.get("drift") != expected:
            errors.append(f"drift_binding_mismatch:{slug}")
    return tuple(sorted(set(errors))), explicitly_expired


def _scan_counts(
    verification: dict[str, object],
    rows: tuple[EvidenceRow, ...],
) -> tuple[tuple[str, int], ...]:
    raw = verification.get("scan_counts")
    values = raw if isinstance(raw, dict) else {}

    def count(name: str, fallback: int) -> int:
        value = values.get(name)
        return value if isinstance(value, int) and value >= 0 else fallback

    return (
        ("Total", count("total", len(rows))),
        ("Fresh", count("fresh", sum(row.state == "fresh" for row in rows))),
        ("Masked", count("masked", sum(row.masked for row in rows))),
        (
            "Failed",
            count("failed", sum(row.state not in {"fresh", "masked"} for row in rows)),
        ),
    )


def _status(
    verification: dict[str, object],
    *,
    extra_errors: tuple[str, ...],
    explicitly_expired: bool = False,
) -> tuple[ReviewStatus, str, str]:
    errors = verification.get("errors")
    has_errors = (
        bool(errors)
        or bool(extra_errors)
        or verification.get("structural_valid") is not True
    )
    state = verification.get("state")
    candidate_state = verification.get("candidate_state")
    if has_errors:
        return (
            "blocked",
            "BLOCKED",
            "Candidate evidence failed validation. Do not treat it as current or complete.",
        )
    if state == "stale" or explicitly_expired:
        return (
            "stale",
            "STALE",
            "Candidate evidence exceeded its review window. Fresh verification is required.",
        )
    if candidate_state == "fixture":
        return (
            "fixture",
            "FIXTURE",
            "Structurally valid deterministic fixture. It can never become publication-ready.",
        )
    if candidate_state == "complete":
        return (
            "reviewable",
            "REVIEWABLE",
            "Structurally valid and current evidence. Reviewable does not mean approved.",
        )
    return (
        "blocked",
        "BLOCKED",
        "Candidate state is not complete enough for a review conclusion.",
    )


def build_review_surface(
    candidate: Path,
    *,
    expected_seed_path: Path | None = None,
    expected_masked_path: Path | None = None,
    now: datetime | None = None,
) -> ReviewSurface:
    """Validate one candidate and compose a closed, deterministic review surface."""
    fixed_now = now or datetime.now(tz=UTC)
    if fixed_now.tzinfo is None:
        fixed_now = fixed_now.replace(tzinfo=UTC)
    projection_errors: list[str] = []
    candidate_before: tuple[tuple[str, int, str], ...] | None = None
    input_before: tuple[tuple[int, int, int, str], ...] | None = None
    try:
        candidate_before = _candidate_tree_fingerprint(candidate)
    except (OSError, ValueError):
        projection_errors.append("candidate_snapshot_unavailable")
    if expected_seed_path is not None and expected_masked_path is not None:
        try:
            input_before = (
                _review_input_fingerprint(expected_seed_path),
                _review_input_fingerprint(expected_masked_path),
            )
        except (OSError, ValueError):
            projection_errors.append("reviewed_input_snapshot_unavailable")
    safe_verifier_preflight = candidate_before is not None and not (
        expected_seed_path is not None
        and expected_masked_path is not None
        and input_before is None
    )
    try:
        if not safe_verifier_preflight:
            raise ValueError("safe verifier preflight failed")
        verification = verify_refresh_candidate(
            candidate,
            now=fixed_now,
            expected_seed_path=expected_seed_path,
            expected_masked_path=expected_masked_path,
        )
    except Exception as exc:  # noqa: BLE001 - hostile inputs must fail closed
        verification = {
            "structural_valid": False,
            "state": "invalid",
            "publication_ready": False,
            "errors": [f"verifier_unavailable:{type(exc).__name__}"],
        }
    try:
        if candidate_before is None or _candidate_tree_fingerprint(candidate) != candidate_before:
            projection_errors.append("candidate_changed_during_verification")
    except (OSError, ValueError):
        projection_errors.append("candidate_changed_during_verification")
    if (
        expected_seed_path is not None
        and expected_masked_path is not None
        and input_before is not None
    ):
        try:
            input_after = (
                _review_input_fingerprint(expected_seed_path),
                _review_input_fingerprint(expected_masked_path),
            )
            if input_after != input_before:
                projection_errors.append("reviewed_inputs_changed_during_verification")
        except (OSError, ValueError):
            projection_errors.append("reviewed_inputs_changed_during_verification")

    try:
        manifest, raw_rows = _load_candidate_projection(candidate)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
        manifest = {}
        raw_rows = []
        projection_errors.append(f"projection_unavailable:{type(exc).__name__}")

    provisional_rows = tuple(
        sorted(
            (_row_from_result(row) for row in raw_rows),
            key=lambda row: row.server_slug,
        )
    )
    semantic_errors, explicitly_expired = _projection_semantic_errors(
        candidate,
        manifest,
        raw_rows,
        now=fixed_now,
    )
    projection_errors.extend(semantic_errors)
    try:
        if candidate_before is None or _candidate_tree_fingerprint(candidate) != candidate_before:
            projection_errors.append("candidate_changed_during_projection")
    except (OSError, ValueError):
        projection_errors.append("candidate_changed_during_projection")

    verification_errors = verification.get("errors")
    validation_errors = tuple(
        sorted(
            {
                _short_text(error)
                for error in (
                    list(verification_errors) if isinstance(verification_errors, list) else []
                )
                + projection_errors
            }
        )
    )
    status, status_label, status_explanation = _status(
        verification,
        extra_errors=tuple(projection_errors),
        explicitly_expired=explicitly_expired,
    )
    evidence_valid = status not in {"blocked", "stale"}
    rows = tuple(
        replace(
            row,
            receipt_state=(
                row.receipt_state
                if row.masked or evidence_valid
                else "UNVERIFIED"
            ),
        )
        for row in provisional_rows
    )

    authority_payload = manifest.get("authority")
    authority_values = authority_payload if isinstance(authority_payload, dict) else {}
    authority = tuple(
        (
            key,
            label,
            bool(authority_values.get(key)) if status != "blocked" else False,
        )
        for key, label in _AUTHORITY_ORDER
    )
    engine_versions = manifest.get("engine_versions")
    engines = (
        tuple(sorted(_short_text(value) for value in engine_versions if isinstance(value, str)))
        if isinstance(engine_versions, list)
        else ()
    )
    identity = CandidateIdentity(
        candidate_name=_short_text(candidate.name),
        manifest_sha256=_short_text(verification.get("manifest_sha256")),
        schema=_short_text(manifest.get("schema")),
        created_at=_timestamp_text(manifest.get("created_at")),
        expires_at=_timestamp_text(manifest.get("expires_at")),
        candidate_state=_short_text(verification.get("candidate_state")),
        scan_mode=_short_text(manifest.get("scan_mode")),
        engine_versions=engines or ("UNKNOWN",),
        source_binding=(
            "BOUND TO REVIEWED INPUTS"
            if status != "blocked" and verification.get("reviewed_inputs_bound") is True
            else "UNBOUND OR UNVERIFIED"
        ),
    )

    changed_count = sum(row.changed for row in rows)
    masked_count = sum(row.masked for row in rows)
    flagged_count = sum(row.flagged for row in rows)
    decisive_unknowns: list[str] = []
    if validation_errors:
        decisive_unknowns.append(
            f"{len(validation_errors)} validation rule(s) failed; the candidate is blocked."
        )
    if masked_count:
        decisive_unknowns.append(
            f"{masked_count} result(s) withhold grade, transparency, receipt, and drift evidence."
        )
    nonterminal = sum(row.state not in {"fresh", "masked"} for row in rows)
    if nonterminal:
        decisive_unknowns.append(
            f"{nonterminal} result(s) are neither fresh nor masked and require separate evidence."
        )
    if verification.get("reviewed_inputs_bound") is not True:
        decisive_unknowns.append(
            "Reviewed seed and masking inputs are not both bound to this review."
        )
    if not decisive_unknowns:
        decisive_unknowns.append(
            "No decisive unknowns were detected by this surface; that is not approval."
        )

    if status == "blocked":
        conclusion = "Stop: validation or candidate-state failures prevent a reliable review."
    elif status == "stale":
        conclusion = "Stop: the evidence is outside its review window."
    elif changed_count:
        conclusion = (
            f"Review {changed_count} changed result(s) before seeking any separate approval."
        )
    elif masked_count:
        conclusion = (
            "No material visible drift was found, but masked results limit the conclusion."
        )
    else:
        conclusion = "No material grade or declared tool-surface drift was detected."

    return ReviewSurface(
        schema="RefreshCandidateReviewSurfaceV1",
        component_catalog=COMPONENT_CATALOG,
        identity=identity,
        status=status,
        status_label=status_label,
        status_explanation=status_explanation,
        publication_ready_after_separate_approval=bool(
            status == "reviewable" and verification.get("publication_ready") is True
        ),
        authority=authority,
        scan_counts=_scan_counts(verification, rows),
        decisive_unknowns=tuple(decisive_unknowns),
        validation_errors=validation_errors,
        rows=rows,
        changed_count=changed_count,
        masked_count=masked_count,
        flagged_count=flagged_count,
        review_conclusion=conclusion,
    )


def render_review_room_text(surface: ReviewSurface) -> str:
    """Render the complete semantic surface as an accessible text fallback."""
    lines = [
        "REFRESH CANDIDATE ADJUDICATION ROOM",
        "READ-ONLY REVIEW — No approval, publication, deployment, or scheduling authority",
        "",
        f"Candidate: {surface.identity.candidate_name}",
        f"Manifest SHA-256: {surface.identity.manifest_sha256}",
        f"Schema: {surface.identity.schema}",
        f"Created: {surface.identity.created_at}",
        f"Expires: {surface.identity.expires_at}",
        f"Source binding: {surface.identity.source_binding}",
        f"Status: {surface.status_label}",
        surface.status_explanation,
        f"Review conclusion: {surface.review_conclusion}",
        "",
        "AUTHORITY",
    ]
    lines.extend(
        f"- {label}: {_authority_state(key, available)}"
        for key, label, available in surface.authority
    )
    lines.extend(("", "DECISIVE UNKNOWNS"))
    lines.extend(f"- {unknown}" for unknown in surface.decisive_unknowns)
    lines.extend(("", "VALIDATION"))
    lines.extend(
        (f"- {error}" for error in surface.validation_errors)
        if surface.validation_errors
        else ("- No validation errors.",)
    )
    lines.extend(("", "SCAN EVIDENCE"))
    for row in surface.rows:
        lines.append(
            " | ".join(
                (
                    row.server_slug,
                    row.server_name,
                    f"state={row.state}",
                    f"grade={row.current_grade}",
                    f"previous={row.previous_grade}",
                    f"transparency={row.transparency}",
                    f"receipt={row.receipt_state}",
                    f"drift={row.drift_summary}",
                )
            )
        )
        lines.extend(f"  - flag: {flag}" for flag in row.flags)
    if not surface.rows:
        lines.append("- No trustworthy scan projection is available.")
    return "\n".join(lines) + "\n"


def _escape(value: object) -> str:
    return html.escape(str(value), quote=True)


def _status_mark(status: ReviewStatus) -> str:
    return {
        "reviewable": "✓",
        "fixture": "◇",
        "stale": "◷",
        "blocked": "!",
    }[status]


def _row_html(row: EvidenceRow) -> str:
    classes = ["evidence-row"]
    if row.changed:
        classes.append("row-changed")
    if row.masked:
        classes.append("row-masked")
    if row.flagged:
        classes.append("row-flagged")
    flags = "; ".join(row.flags) if row.flags else "None"
    return (
        f'<tr class="{" ".join(classes)}">'
        f'<th scope="row"><strong>{_escape(row.server_name)}</strong>'
        f'<span class="slug">{_escape(row.server_slug)}</span></th>'
        f'<td><span class="state state-{_escape(row.state)}">{_escape(row.state)}</span></td>'
        f"<td>{_escape(row.current_grade)}</td>"
        f"<td>{_escape(row.previous_grade)}</td>"
        f"<td>{_escape(row.transparency)}</td>"
        f"<td>{_escape(row.drift_summary)}</td>"
        f"<td>{_escape(row.receipt_state)}</td>"
        f"<td>{_escape(row.scanned_at)}</td>"
        f'<td><span class="sr-only">Review flags: </span>{_escape(flags)}</td>'
        "</tr>"
    )


def render_review_room_html(surface: ReviewSurface) -> str:
    """Render a self-contained, no-script review room from the closed catalog."""
    identity = surface.identity
    count_items = "".join(
        f"<div><dt>{_escape(label)}</dt><dd>{count}</dd></div>"
        for label, count in surface.scan_counts
    )
    unknown_items = "".join(
        f"<li>{_escape(item)}</li>" for item in surface.decisive_unknowns
    )
    validation_items = (
        "".join(f"<li>{_escape(item)}</li>" for item in surface.validation_errors)
        if surface.validation_errors
        else "<li>No validation errors.</li>"
    )
    lifecycle = [
        (
            "Create",
            "complete" if surface.status != "blocked" else "unavailable",
            "Candidate bytes verified" if surface.status != "blocked" else "Unverified",
        ),
        (
            "Review",
            "current" if surface.status not in {"blocked", "stale"} else "unavailable",
            "This read-only room" if surface.status not in {"blocked", "stale"} else "Blocked",
        ),
        ("Approve", "unavailable", "Unavailable"),
        ("Publish locally", "unavailable", "Unavailable"),
        ("Deploy", "unavailable", "Unavailable"),
        ("Schedule", "unavailable", "Unavailable"),
    ]
    lifecycle_html = "".join(
        f'<li class="life-{state}"><span class="life-dot" aria-hidden="true">'
        f"{index}</span><strong>{_escape(label)}</strong><small>{_escape(detail)}</small></li>"
        for index, (label, state, detail) in enumerate(lifecycle, start=1)
    )
    authority_html = "".join(
        f"<li><span>{_escape(label)}</span>"
        f'<strong class="authority-{_authority_state(key, available)}">'
        f"{_authority_state(key, available).upper()}</strong></li>"
        for key, label, available in surface.authority
    )
    rows_html = "".join(_row_html(row) for row in surface.rows)
    if not rows_html:
        rows_html = (
            '<tr><td colspan="9" class="empty">'
            "No trustworthy scan projection is available.</td></tr>"
        )
    text_fallback = _escape(render_review_room_text(surface))
    engines = ", ".join(identity.engine_versions)
    status_class = _escape(surface.status)
    ready_label = (
        "Verifier reports publication-ready after a separate bound approval."
        if surface.publication_ready_after_separate_approval
        else "Verifier does not report publication-ready."
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy"
        content="default-src 'none'; style-src 'unsafe-inline'; img-src 'none';
                 font-src 'none'; connect-src 'none'; frame-src 'none';
                 form-action 'none'; base-uri 'none'">
  <title>Refresh Candidate Adjudication Room</title>
  <style>
    *,*::before,*::after{{box-sizing:border-box}}
    :root{{--ink:#172033;--muted:#526173;--line:#cbd5e1;--soft:#f4f7fa;
      --navy:#0b2d5c;--blue:#175cd3;--amber:#9a6700;--amber-bg:#fff3c4;
      --red:#b42318;--red-bg:#fff1f0;--green:#176b3a;--green-bg:#edf8f1;
      --focus:#ffbf47}}
    html{{max-width:100%;overflow-x:hidden;scroll-behavior:smooth}}
    @media(prefers-reduced-motion:reduce){{html{{scroll-behavior:auto}}}}
    body{{max-width:100%;margin:0;overflow-x:hidden;background:#fff;color:var(--ink);
      font:14px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif}}
    a{{color:var(--blue)}}
    a:focus-visible,input:focus-visible+label,summary:focus-visible{{
      outline:3px solid var(--focus);outline-offset:3px}}
    main:focus{{outline:3px solid var(--focus);outline-offset:-3px}}
    .skip{{position:absolute;left:-999px;top:8px;background:#fff;padding:10px;z-index:9}}
    .skip:focus{{left:12px}}
    header{{height:64px;display:flex;align-items:center;gap:14px;padding:0 28px;
      border-bottom:1px solid var(--line);background:var(--soft)}}
    .mark{{display:grid;place-items:center;width:42px;height:42px;background:var(--navy);
      color:#fff;font-size:16px;font-weight:800;letter-spacing:.04em}}
    .brand strong{{display:block;font-size:17px}} .brand span{{color:var(--muted)}}
    main{{max-width:1440px;margin:0 auto;padding:28px}}
    h1{{font-size:30px;line-height:1.15;margin:0 0 18px;letter-spacing:-.02em}}
    h2{{font-size:18px;margin:0 0 12px}} h3{{font-size:14px;margin:0 0 8px}}
    .authority-banner{{display:flex;gap:12px;align-items:flex-start;background:var(--amber-bg);
      color:#392d00;border:1px solid #d6a900;padding:13px 16px;font-weight:750}}
    .identity{{display:grid;grid-template-columns:1.25fr 1fr 1fr;gap:0;margin:14px 0 24px;
      border:1px solid var(--line);background:#fff}}
    .identity section{{padding:16px 18px;border-right:1px solid var(--line)}}
    .identity section:last-child{{border-right:0}}
    dl{{margin:0}} .identity dl div{{display:grid;grid-template-columns:132px 1fr;gap:10px;
      padding:4px 0}} dt{{color:var(--muted);font-weight:650}} dd{{margin:0}}
    code{{font:12px/1.45 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
      overflow-wrap:anywhere}}
    .workspace{{display:grid;grid-template-columns:150px minmax(0,1fr);gap:0;min-width:0}}
    .spine{{border-right:2px solid var(--navy);padding:8px 18px 0 0}}
    .spine ol{{list-style:none;margin:0;padding:0;position:sticky;top:18px}}
    .spine li{{margin:0 0 24px}} .spine a{{display:block;color:var(--ink);
      font-weight:700;text-decoration:none;padding:7px 8px}}
    .content{{padding-left:28px;min-width:0}}
    .panel{{border:1px solid var(--line);margin:0 0 14px;background:#fff;min-width:0}}
    .panel-body{{padding:18px}}
    .status-grid{{display:grid;grid-template-columns:minmax(220px,.7fr) 1.3fr 260px}}
    .status-main,.status-copy,.counts{{padding:20px;border-right:1px solid var(--line)}}
    .counts{{border-right:0}} .status-main{{display:flex;align-items:center;gap:15px}}
    .status-mark{{display:grid;place-items:center;width:56px;height:56px;border:3px solid;
      border-radius:50%;font-size:30px;font-weight:800}}
    .status-label{{font-size:34px;line-height:1;font-weight:800;letter-spacing:.01em}}
    .status-reviewable .status-mark,.status-reviewable .status-label{{color:var(--green)}}
    .status-fixture .status-mark,.status-fixture .status-label{{color:var(--blue)}}
    .status-stale .status-mark,.status-stale .status-label{{color:var(--amber)}}
    .status-blocked .status-mark,.status-blocked .status-label{{color:var(--red)}}
    .status-copy p{{margin:0 0 8px}} .status-copy strong{{display:block}}
    .counts dl div{{display:flex;justify-content:space-between;gap:24px;padding:2px 0}}
    .counts dd{{font-variant-numeric:tabular-nums;font-weight:750}}
    .two-col{{display:grid;grid-template-columns:1.5fr .8fr}}
    .two-col>section{{padding:18px;border-right:1px solid var(--line)}}
    .two-col>section:last-child{{border-right:0}}
    ul{{margin:7px 0 0;padding-left:20px}}
    .validation-errors{{color:var(--red)}} .validation-ok{{color:var(--green)}}
    .authority-list{{list-style:none;padding:0;margin:0}}
    .authority-list li{{display:flex;justify-content:space-between;gap:20px;padding:5px 0;
      border-bottom:1px solid #e7edf3}}
    .authority-list .authority-recorded{{color:var(--navy)}}
    .authority-list .authority-available{{color:var(--green)}}
    .authority-list .authority-unavailable{{color:var(--red)}}
    .lifecycle{{list-style:none;display:grid;grid-template-columns:repeat(6,1fr);
      padding:18px;margin:0;gap:12px}}
    .lifecycle li{{position:relative;text-align:center;padding-top:36px}}
    .lifecycle li::before{{content:"";position:absolute;top:13px;left:-50%;right:50%;
      height:2px;background:var(--line)}} .lifecycle li:first-child::before{{display:none}}
    .life-dot{{position:absolute;top:0;left:50%;transform:translateX(-50%);display:grid;
      place-items:center;width:28px;height:28px;border-radius:50%;background:#d9e0e8;
      font-weight:800;z-index:1}}
    .life-complete .life-dot{{background:var(--navy);color:#fff}}
    .life-current .life-dot{{background:var(--blue);color:#fff}}
    .lifecycle strong,.lifecycle small{{display:block}} .lifecycle small{{color:var(--muted)}}
    .evidence-head{{display:flex;justify-content:space-between;gap:20px;align-items:flex-end;
      padding:17px 18px;border-bottom:1px solid var(--line)}}
    .evidence-head p{{margin:2px 0 0;color:var(--muted)}}
    .filters{{display:flex;flex-wrap:wrap;gap:7px;padding:12px 18px;background:var(--soft);
      border-bottom:1px solid var(--line)}}
    .filters input{{position:absolute;opacity:0;pointer-events:none}}
    .filters label{{border:1px solid #9aa8b7;background:#fff;padding:7px 10px;cursor:pointer;
      font-weight:650}} .filters input:checked+label{{background:var(--navy);color:#fff;
      border-color:var(--navy)}}
    .table-wrap{{flex:1 1 100%;min-width:0;width:100%;overflow:auto;max-width:100%;
      max-height:620px}}
    table{{border-collapse:collapse;width:100%;min-width:1180px;font-size:13px}}
    caption{{text-align:left;padding:10px 18px;color:var(--muted)}}
    th,td{{border-bottom:1px solid #e1e7ee;padding:10px 12px;text-align:left;vertical-align:top}}
    thead th{{position:sticky;top:0;background:#f8fafc;z-index:2;color:#405166}}
    tbody th{{min-width:225px}} .slug{{display:block;color:var(--muted);font:11px/1.4
      ui-monospace,SFMono-Regular,Menlo,monospace;margin-top:2px}}
    .state{{font-weight:750;text-transform:uppercase}} .state-masked{{color:var(--amber)}}
    .state-scan-failed,.state-missing-receipt{{color:var(--red)}}
    .empty{{padding:30px;text-align:center;color:var(--muted)}}
    #filter-changed:checked~.table-wrap tbody tr:not(.row-changed),
    #filter-masked:checked~.table-wrap tbody tr:not(.row-masked),
    #filter-flagged:checked~.table-wrap tbody tr:not(.row-flagged){{display:none}}
    details{{border-top:1px solid var(--line);padding:14px 18px}}
    summary{{cursor:pointer;font-weight:750;color:var(--blue)}}
    pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:var(--soft);padding:16px;
      border:1px solid var(--line);font:12px/1.55 ui-monospace,SFMono-Regular,Menlo,monospace}}
    footer{{color:var(--muted);padding:10px 0 0;font-size:12px}}
    .sr-only{{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;
      clip:rect(0,0,0,0);white-space:nowrap;border:0}}
    @media(max-width:900px){{
      main{{padding:18px}} .identity,.status-grid,.two-col{{grid-template-columns:1fr}}
      .identity section,.status-main,.status-copy,.counts,.two-col>section{{
        border-right:0;border-bottom:1px solid var(--line)}}
      .workspace{{grid-template-columns:minmax(0,1fr)}}
      .spine{{border-right:0;border-bottom:2px solid var(--navy);padding:0;margin-bottom:18px}}
      .spine ol{{display:flex;overflow:auto;
        position:static}} .spine li{{margin:0;flex:0 0 auto}} .content{{padding-left:0}}
      .lifecycle{{grid-template-columns:repeat(3,1fr);row-gap:22px}}
      .lifecycle li::before{{display:none}}
    }}
    @media(max-width:560px){{
      header{{padding:0 14px}} h1{{font-size:24px}} main{{padding:14px}}
      .identity dl div{{grid-template-columns:1fr}} .status-main{{align-items:flex-start}}
      .status-label{{font-size:27px}} .lifecycle{{grid-template-columns:repeat(2,1fr)}}
      .evidence-head{{display:block}} .filters{{gap:5px}} .filters label{{flex:1 1 45%;
        text-align:center}}
    }}
  </style>
</head>
<body>
  <a class="skip" href="#review-content">Skip to review evidence</a>
  <header>
    <span class="mark" aria-hidden="true">MCP</span>
    <div class="brand"><strong>MCP Trust Registry</strong><span>Local evidence review</span></div>
  </header>
  <main id="review-content" tabindex="-1">
    <h1>Refresh Candidate Adjudication Room</h1>
    <div class="authority-banner" role="note">
      <span aria-hidden="true">▲</span>
      <span>READ-ONLY REVIEW — No approval, publication, deployment, or scheduling authority</span>
    </div>

    <div class="identity" id="identity">
      <section><h2>Candidate identity</h2><dl>
        <div><dt>Candidate</dt><dd>{_escape(identity.candidate_name)}</dd></div>
        <div><dt>Manifest SHA-256</dt>
          <dd><code>{_escape(identity.manifest_sha256)}</code></dd></div>
        <div><dt>Schema</dt><dd>{_escape(identity.schema)}</dd></div>
      </dl></section>
      <section><h2>Review window</h2><dl>
        <div><dt>Created</dt><dd>{_escape(identity.created_at)}</dd></div>
        <div><dt>Expires</dt><dd>{_escape(identity.expires_at)}</dd></div>
        <div><dt>Input binding</dt><dd>{_escape(identity.source_binding)}</dd></div>
      </dl></section>
      <section><h2>Source and engine</h2><dl>
        <div><dt>Candidate state</dt><dd>{_escape(identity.candidate_state)}</dd></div>
        <div><dt>Scan mode</dt><dd>{_escape(identity.scan_mode)}</dd></div>
        <div><dt>Engine versions</dt><dd>{_escape(engines)}</dd></div>
      </dl></section>
    </div>

    <div class="workspace">
      <nav class="spine" aria-label="Review sections"><ol>
        <li><a href="#identity">Identity</a></li>
        <li><a href="#unknowns">Unknowns</a></li>
        <li><a href="#validation">Validation</a></li>
        <li><a href="#lifecycle">Lifecycle</a></li>
        <li><a href="#evidence">Evidence</a></li>
      </ol></nav>
      <div class="content">
        <section class="panel status-{status_class}" aria-labelledby="status-heading">
          <div class="status-grid">
            <div class="status-main">
              <span class="status-mark" aria-hidden="true">{_status_mark(surface.status)}</span>
              <div><h2 id="status-heading">Candidate state</h2>
                <div class="status-label">{_escape(surface.status_label)}</div></div>
            </div>
            <div class="status-copy"><h2>Review conclusion</h2>
              <p>{_escape(surface.status_explanation)}</p>
              <strong>{_escape(surface.review_conclusion)}</strong>
              <p>{_escape(ready_label)}</p>
            </div>
            <div class="counts"><h2>Scan summary</h2><dl>{count_items}</dl></div>
          </div>
        </section>

        <section class="panel two-col" id="unknowns" aria-labelledby="unknowns-heading">
          <section><h2 id="unknowns-heading">Decisive unknowns</h2>
            <ul>{unknown_items}</ul></section>
          <section><h2>Why this matters</h2><p>Unknown does not mean safe or dangerous.
            It limits what this candidate can prove.</p></section>
        </section>

        <section class="panel two-col" id="validation" aria-labelledby="validation-heading">
          <section><h2 id="validation-heading">Validation evidence</h2>
            <ul class="{'validation-errors' if surface.validation_errors else 'validation-ok'}">
              {validation_items}</ul></section>
          <section><h2>Authority boundary</h2>
            <ul class="authority-list">{authority_html}</ul></section>
        </section>

        <section class="panel" id="lifecycle" aria-labelledby="lifecycle-heading">
          <div class="panel-body"><h2 id="lifecycle-heading">Fixed candidate lifecycle</h2>
            <p>Generation may organize evidence. It cannot move the candidate
              through this lifecycle.</p>
          </div>
          <ol class="lifecycle">{lifecycle_html}</ol>
        </section>

        <section class="panel" id="evidence" aria-labelledby="evidence-heading">
          <div class="evidence-head"><div><h2 id="evidence-heading">Server evidence</h2>
            <p>{len(surface.rows)} rows · {surface.changed_count} changed ·
              {surface.masked_count} masked · {surface.flagged_count} flagged</p></div>
            <a href="#text-fallback">Jump to text fallback</a></div>
          <div class="filters" aria-label="Evidence filters">
            <input type="radio" name="evidence-filter" id="filter-all" checked>
            <label for="filter-all">All ({len(surface.rows)})</label>
            <input type="radio" name="evidence-filter" id="filter-changed">
            <label for="filter-changed">Changed ({surface.changed_count})</label>
            <input type="radio" name="evidence-filter" id="filter-masked">
            <label for="filter-masked">Masked ({surface.masked_count})</label>
            <input type="radio" name="evidence-filter" id="filter-flagged">
            <label for="filter-flagged">Flagged ({surface.flagged_count})</label>
            <div class="table-wrap" tabindex="0" aria-label="Scrollable server evidence table">
              <table>
                <caption>Candidate evidence; masked values remain withheld.</caption>
                <thead><tr><th scope="col">Server</th><th scope="col">State</th>
                  <th scope="col">Grade</th><th scope="col">Previous</th>
                  <th scope="col">Transparency</th><th scope="col">Drift</th>
                  <th scope="col">Receipt</th><th scope="col">Scanned</th>
                  <th scope="col">Review flags</th></tr></thead>
                <tbody>{rows_html}</tbody>
              </table>
            </div>
          </div>
          <details id="text-fallback"><summary>Complete text fallback</summary>
            <pre>{text_fallback}</pre></details>
        </section>
        <footer>Generated from immutable candidate bytes. No action was performed.</footer>
      </div>
    </div>
  </main>
</body>
</html>
"""


def render_review_room_json(surface: ReviewSurface) -> str:
    """Render the portable semantic surface with stable key ordering."""
    return json.dumps(surface.model_dump(), indent=2, sort_keys=True) + "\n"
