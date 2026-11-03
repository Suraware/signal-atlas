# Contributing to Signal Atlas

Keep contributions small, independently testable, and within the local-first security model.

## Setup and verification

Follow the [README](README.md#quick-start), then run:

```bash
.venv/bin/python -m pytest -q
.venv/bin/ruff check backend tests scripts
npm --prefix frontend run build
npm --prefix frontend exec -- playwright install firefox
npm --prefix frontend test
```

Use a separate `--data-dir` for experiments. Never commit research notes, manifests, packet captures, executable samples, credentials, or the local SQLite database. Tests must use synthetic or sanitized fixtures, not real confidential artifacts.

## Change boundaries

- Add a failing regression test before a behavior change. Keep external HTTP fixtures below the real parser/service/API boundary.
- Preserve source IDs, original evidence, fetch dates, and alias correlation. Do not fill missing CVSS/EPSS values with invented defaults.
- New connectors need public no-key endpoints, bounded payloads, timeouts, cache windows, conservative request budgets, schema checks, terms links, and documented coverage. No arbitrary URL fetching or silently followed redirects.
- Uploaded bytes and manifests must never be executed, loaded as code, or sent to third-party reputation or AI services.
- Use parameterized SQLite queries and revision checks. A failed refresh or stale edit must not destroy usable local data.
- Keep browser assets local. Follow `DESIGN.md`, use visible labels and keyboard-operable controls, and provide a readable equivalent for diagrams.
- Do not add permissive CORS or describe host checks as authentication. Changes to LAN exposure, account systems, or TLS require an explicit design and threat model.

## Dependencies and documentation

Update Python ranges in `pyproject.toml`, run `uv lock`, and re-run the tests. Use `npm --prefix frontend install` for intentional frontend dependency changes and include the updated lockfile. Normal setup uses `uv sync --frozen` and `npm ci`; do not silently regenerate locks.

Document new source coverage and limitations in `docs/sources.md`, new security boundaries in `docs/security.md`, and user-visible behavior in `README.md`. Describe the actual checks and results in a proposed change; “should work” is not evidence.

## Security reports

Do not post secrets or weaponized artifacts in public issues. Arrange a private disclosure channel with the project owner before sharing sensitive details. No hosted security intake or public repository is configured in this initial local build.
