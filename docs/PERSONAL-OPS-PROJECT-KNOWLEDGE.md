# Personal Ops project knowledge authority

`integrations/personal-ops/project-knowledge.json` is the repository-owned,
explicit admission artifact for Personal Ops project knowledge queries using the
exact project key `saagpatel/mcp-trust`.

Its authority is deliberately narrow. It declares stable product and interface
facts already owned by this repository. It does not publish or summarize scan
records, grades, findings, deployment state, launch readiness, provider state,
adoption, or generated portfolio data. Those claims remain with their existing
owners and evidence.

Personal Ops reads the file as untrusted source data. It verifies the bounded
manifest contract, file identity and permissions, exact project identity, and a
SHA-256 observation binding. Fact metadata is available in ordinary project
queries. Optional fact content is available only through the existing
operator-authorized content path. Personal Ops does not copy source facts into
its own store.

To correct or delete a fact, change or remove it in the manifest and update
`generated_at` plus the affected `observed_at`. Consumers observe that owner
change on their next query. The manifest ages after seven days and becomes stale
after thirty days so an abandoned projection cannot remain silently fresh.
