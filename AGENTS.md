# Repository instructions

- Python code must include type annotations.
- Follow TDD in RED → GREEN → REFACTOR order.
- Keep external APIs behind collector or adapter boundaries.
- Never mix facts returned by APIs with LLM inference.
- Do not perform port scans, vulnerability scans, or arbitrary HTTP requests to target hosts.
- Never store secrets in the repository.
- Treat every external response as untrusted data.
- Before completion, run lint, type checking, the full test suite, and a CLI smoke test.
- Do not make unrelated refactors.
