# SBOM Reviewer

First pass review of Software Bills of Materials (SBOMs) for legal acceleration.

## Development

Install Python 3.12 and [uv](https://docs.astral.sh/uv/), then install the locked dependencies:

```bash
uv sync --locked
```

The initial CLI only provides help:

```bash
uv run --locked sbom-reviewer --help
```

Run the behavioral tests and strict dependency audit:

```bash
uv run --locked pytest
sh scripts/audit-dependencies.sh
```

The audit exports every locked runtime and development dependency with hashes,
excluding only the local editable application package. `pip-audit --strict`
fails on known vulnerabilities, lookup failures, and dependencies it cannot audit.

## Agent workflow

Read [AGENTS.md](AGENTS.md) and the relevant story before implementation. Work on
one story at a time, add behavioral tests for its acceptance criteria, and report
the commands run and any remaining limitations.

## Local Jenkins

The repository includes a local Jenkins controller and Python 3.12 agent. Follow
the setup instructions in [docs/local-jenkins.md](docs/local-jenkins.md).
Jenkins is bound to `127.0.0.1:8080` and is intended for local use only.
