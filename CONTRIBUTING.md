# Contributing

Thank you for considering a contribution to SentinelAI.

## Before opening a pull request

1. Open an issue or discussion for substantial changes so the scope can be agreed.
2. Create a focused branch from `main`.
3. Keep changes small and explain any security or research-method implications.
4. Add or update tests for changed behaviour.
5. Run the backend test suite from `backend/`:
   `python -m pytest tests -q`
6. Run the frontend production build from `frontend/`:
   `npm ci && npm run build`
7. Update documentation when commands, configuration, endpoints, or research assumptions change.

## Data and security rules

- Never commit secrets, `.env` files, access tokens, private keys, database files, personal data, or restricted datasets.
- Do not commit raw CERT archives, derived private data, trained model binaries, or generated result directories.
- Do not describe the current AES-GCM or Ed25519 demonstration modules as ML-KEM, ML-DSA, or quantum-resistant cryptography.
- Do not describe simulator outputs as real-world enforcement or as causal evidence.
- Report vulnerabilities privately as described in `SECURITY.md`.

## Pull request description

Include the problem being solved, the implementation summary, tests run, screenshots for UI changes, and known limitations.
