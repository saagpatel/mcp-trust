"""WCAG AA contrast guarantees for the grade pill and transparency chip.

The grade pill is the product: a public trust registry whose signal is only
useful if it is legible. This module recomputes WCAG 2.x relative luminance and
contrast ratios from first principles and asserts that every (text, background)
pair the site actually emits clears 4.5:1 -- the AA floor for normal-size text.
Both `.pill` (0.78rem bold) and `.chip` (0.75rem medium) are normal-size at
every supported zoom, so neither qualifies for the 3:1 large-text exemption.

The pairs are harvested from rendered HTML rather than from the palette dicts,
so a hardcoded hex inline in a template is caught the same as a bad dict entry.

Scope note: these assertions cover computed contrast for the pill and chip.
They are not a full WCAG audit of the site.
"""

from __future__ import annotations

import inspect
import math
import re

import pytest

from mcp_trust.api import web
from mcp_trust.api.web import (
    _GRADE_CSS,
    _PAGE_STYLE,
    _TRANSPARENCY_CSS,
    _grade_pill,
    _transparency_chip,
)

AA_NORMAL_TEXT = 4.5

# Every surface a pill or chip is painted on: the page background and the card
# and table-row backgrounds that sit on top of it.
PAGE_SURFACES = ("#ffffff", "#f6f8fa")


# ---------------------------------------------------------------------------
# WCAG 2.x colour maths (https://www.w3.org/TR/WCAG21/#dfn-relative-luminance)
# ---------------------------------------------------------------------------


def _hex_to_rgb(value: str) -> tuple[int, int, int]:
    digits = value.lstrip("#")
    if len(digits) == 3:
        digits = "".join(c * 2 for c in digits)
    if len(digits) != 6:
        raise ValueError(f"not a hex colour: {value!r}")
    return int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16)


def _linear_rgb(value: str) -> tuple[float, float, float]:
    def channel(raw: int) -> float:
        c = raw / 255
        return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4

    r, g, b = (channel(c) for c in _hex_to_rgb(value))
    return r, g, b


def _relative_luminance(value: str) -> float:
    r, g, b = _linear_rgb(value)
    return 0.2126 * r + 0.7152 * g + 0.0722 * b


def _to_lab(value: str) -> tuple[float, float, float]:
    """sRGB to CIELAB under a D65 white point."""
    r, g, b = _linear_rgb(value)
    x = (0.4124 * r + 0.3576 * g + 0.1805 * b) / 0.95047
    y = 0.2126 * r + 0.7152 * g + 0.0722 * b
    z = (0.0193 * r + 0.1192 * g + 0.9505 * b) / 1.08883

    def f(t: float) -> float:
        return t ** (1 / 3) if t > 0.008856 else (7.787 * t) + (16 / 116)

    fx, fy, fz = f(x), f(y), f(z)
    return (116 * fy) - 16, 500 * (fx - fy), 200 * (fy - fz)


def _delta_e(first: str, second: str) -> float:
    """CIE76 colour difference. A just-noticeable difference is about 2.3."""
    return math.dist(_to_lab(first), _to_lab(second))


def contrast_ratio(foreground: str, background: str) -> float:
    lighter, darker = sorted(
        (_relative_luminance(foreground), _relative_luminance(background)), reverse=True
    )
    return (lighter + 0.05) / (darker + 0.05)


def _composite(foreground: str, background: str, alpha: float) -> str:
    """Flatten a semi-transparent colour onto its backdrop (simple alpha-over)."""
    fore = _hex_to_rgb(foreground)
    back = _hex_to_rgb(background)
    blended = (round(f * alpha + b * (1 - alpha)) for f, b in zip(fore, back, strict=True))
    return "#" + "".join(f"{channel:02x}" for channel in blended)


def test_contrast_maths_matches_published_wcag_values() -> None:
    """Anchor the implementation against ratios published in the WCAG spec."""
    assert contrast_ratio("#ffffff", "#000000") == pytest.approx(21.0, abs=0.01)
    assert contrast_ratio("#ffffff", "#ffffff") == pytest.approx(1.0, abs=0.01)
    # #767676 / #777777 straddle the AA boundary on white and are the canonical
    # published pair for it -- one shade apart, one passing and one failing.
    assert contrast_ratio("#ffffff", "#767676") == pytest.approx(4.54, abs=0.01)
    assert contrast_ratio("#ffffff", "#777777") == pytest.approx(4.48, abs=0.01)


def test_lab_conversion_matches_published_values() -> None:
    """Anchor the CIELAB conversion the separation guard depends on."""
    assert _to_lab("#ffffff") == pytest.approx((100.0, 0.0, 0.0), abs=0.05)
    assert _to_lab("#000000") == pytest.approx((0.0, 0.0, 0.0), abs=0.05)
    # sRGB primary red: L*53.24, a*80.09, b*67.20.
    assert _to_lab("#ff0000") == pytest.approx((53.24, 80.09, 67.20), abs=0.1)
    assert _delta_e("#000000", "#ffffff") == pytest.approx(100.0, abs=0.05)


# ---------------------------------------------------------------------------
# Harvest what the stylesheet and the renderers actually emit
# ---------------------------------------------------------------------------


def _style_rule(selector: str) -> str:
    match = re.search(rf"{re.escape(selector)}\s*\{{(.*?)\}}", _PAGE_STYLE, re.DOTALL)
    assert match is not None, f"no {selector} rule found in _PAGE_STYLE"
    return match.group(1)


def _declared(selector: str, prop: str) -> str | None:
    match = re.search(rf"\b{prop}\s*:\s*([^;]+);", _style_rule(selector))
    return match.group(1).strip() if match else None


def _text_colour(selector: str) -> str:
    colour = _declared(selector, "color")
    assert colour is not None, f"{selector} must declare an explicit text colour"
    return colour


def _opacity(selector: str) -> float:
    raw = _declared(selector, "opacity")
    return 1.0 if raw is None else float(raw)


def _backgrounds(html: str) -> list[str]:
    return re.findall(r"background\s*:\s*(#[0-9a-fA-F]{3,6})", html)


def _rendered_pills() -> dict[str, str]:
    """Every distinct pill the site can emit, keyed by a human label."""
    rendered = {f"grade {grade}": _grade_pill(grade) for grade in _GRADE_CSS}
    rendered["grade A (stale)"] = _grade_pill("A", stale=True)
    rendered["grade masked"] = _grade_pill("A", masked=True)
    rendered["grade unknown"] = _grade_pill("Z")
    return rendered


def _rendered_chips() -> dict[str, str]:
    rendered = {
        f"transparency {level or 'empty'}": _transparency_chip(level) for level in _TRANSPARENCY_CSS
    }
    rendered["transparency unknown"] = _transparency_chip("nonsense")
    return rendered


def _emitted_pairs() -> list[tuple[str, str, str, float]]:
    """(label, text colour, background, ratio) for every emitted pill and chip.

    A semi-transparent element composites both its own text and its background
    onto the page surface, so both sides are flattened before measuring.
    """
    pairs: list[tuple[str, str, str, float]] = []
    for selector, rendered in ((".pill", _rendered_pills()), (".chip", _rendered_chips())):
        text = _text_colour(selector)
        alpha = _opacity(selector)
        for label, html in rendered.items():
            backgrounds = _backgrounds(html)
            assert backgrounds, f"{label} rendered no background colour: {html}"
            for background in backgrounds:
                for surface in PAGE_SURFACES:
                    fore = _composite(text, surface, alpha)
                    back = _composite(background, surface, alpha)
                    pairs.append((f"{label} on {surface}", fore, back, contrast_ratio(fore, back)))
    return pairs


# ---------------------------------------------------------------------------
# The guarantees
# ---------------------------------------------------------------------------


def test_every_emitted_pill_and_chip_meets_aa() -> None:
    failures = [
        f"{label}: {fore} on {back} = {ratio:.2f}:1"
        for label, fore, back, ratio in _emitted_pairs()
        if ratio < AA_NORMAL_TEXT
    ]
    assert not failures, "below WCAG AA 4.5:1 for normal text:\n  " + "\n  ".join(failures)


def test_inline_pill_and_chip_literals_meet_aa() -> None:
    """Not every pill or chip is painted through the palette helpers.

    Some templates inline a hex directly. Those bypass ``_GRADE_CSS`` and
    ``_TRANSPARENCY_CSS`` entirely, so they are harvested from the module source
    and held to the same floor rather than being trusted by omission.
    """
    source = inspect.getsource(web)
    literals = re.findall(r'class="(pill|chip)"\s+style="background:(#[0-9a-fA-F]{3,6})', source)
    assert literals, "expected at least one inline pill/chip literal to check"

    failures = []
    for selector, background in literals:
        text = _text_colour(f".{selector}")
        alpha = _opacity(f".{selector}")
        for surface in PAGE_SURFACES:
            fore = _composite(text, surface, alpha)
            back = _composite(background, surface, alpha)
            ratio = contrast_ratio(fore, back)
            if ratio < AA_NORMAL_TEXT:
                failures.append(f"inline .{selector} {background} on {surface} = {ratio:.2f}:1")
    assert not failures, "inline literals below WCAG AA:\n  " + "\n  ".join(failures)


def test_chip_is_a_solid_colour() -> None:
    """Chips must bake their tint into the hex, not composite through opacity.

    Opacity silently lightens both the chip and its own label against whatever
    is behind it, so a hex that measures fine in isolation can ship illegible.
    """
    assert _opacity(".chip") == 1.0, "chip opacity must be 1; bake the tint into the hex instead"


def test_chip_backgrounds_come_from_the_palette() -> None:
    """No hardcoded hexes inline in a template, where the palette cannot reach."""
    palette = {c.lower() for c in _TRANSPARENCY_CSS.values()}
    for label, html in _rendered_chips().items():
        for background in _backgrounds(html):
            assert background.lower() in palette, (
                f"{label} paints {background}, which is not in _TRANSPARENCY_CSS"
            )


def test_grade_is_carried_by_text_not_colour_alone() -> None:
    """Colour is reinforcement. The letter itself must always be readable.

    WCAG 1.4.1: colour must not be the only means of conveying information.
    Masked is the deliberate exception -- it withholds the letter by policy and
    says so in words.
    """
    for grade in ("A", "B", "C", "D", "F"):
        assert f">{grade}<" in _grade_pill(grade)
        assert f">{grade} (stale)<" in _grade_pill(grade, stale=True)
    assert ">masked<" in _grade_pill("A", masked=True)


def test_palette_keeps_five_distinguishable_grade_steps() -> None:
    """The five letter grades must not collapse into each other.

    Contrast alone is trivially satisfiable by painting every grade the same
    near-black, which would pass AA and destroy the signal. Two properties keep
    the ramp honest: no grade is crushed so dark it stops reading as its own
    colour, and every pair stays perceptually far apart.

    Separation is measured as CIE76 dE in CIELAB, where 2.3 is the just-
    noticeable difference. The floor here is 20 -- an order of magnitude above
    JND, chosen because these are 12px pills read at a glance in a table, not
    swatches compared side by side. For reference, the palette this replaced had
    an A-to-B distance of 6.9: two greens almost nobody could tell apart.
    """
    letters = ["A", "B", "C", "D", "F"]
    colours = [_GRADE_CSS[letter] for letter in letters]
    assert len(set(colours)) == len(letters), "grade colours must be distinct"

    for letter, colour in zip(letters, colours, strict=True):
        assert _relative_luminance(colour) >= 0.05, (
            f"grade {letter} ({colour}) is crushed to near-black; darken only as far as AA requires"
        )

    for i, first in enumerate(letters):
        for second in letters[i + 1 :]:
            distance = _delta_e(_GRADE_CSS[first], _GRADE_CSS[second])
            assert distance >= 20, (
                f"grades {first} ({_GRADE_CSS[first]}) and {second} "
                f"({_GRADE_CSS[second]}) are only {distance:.1f} apart in CIELAB; "
                "adjacent steps must stay tellable apart at pill size"
            )
