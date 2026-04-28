# bitwarden-go-sdk agent instructions

- Before editing, check whether the current branch is `main`; create a working branch if needed. The repository bootstrap plan uses `docs/repository-reference` for scaffold commits.
- Do not implement real Bitwarden behavior before the approved reference-docs and implementation plan authorize it.
- Keep the public API idiomatic and small; raw endpoint DTOs stay internal.
- Never add HTTP request or response body dumps.
- Never log master passwords, tokens, user keys, plaintext item fields, sensitive headers, or decrypted payloads.
- Prefer interfaces at outbound boundaries and Mockery-generated mocks.
- Use Go `context.Context` for SDK operations.
- Optimize for low latency, but keep concurrency bounded and race-safe.
- Run `make check` before claiming work is complete.
