# Security Policy

## Scope

SentinelAI is a research and demonstration project, not a production security product.

## Reporting a vulnerability

Please do not publish credentials, exploit instructions, personal data, or other sensitive details in a public issue. Contact the repository owner privately through the contact method available on the GitHub profile and include:

- A concise description of the affected component.
- The potential impact.
- Reproduction steps or a minimal proof of concept, where safe.
- Any suggested mitigation.

Allow reasonable time for investigation and remediation before public disclosure.

## Deployment guidance

- Never commit `.env` files, credentials, API tokens, private keys, database files, or personal data.
- Generate a unique high-entropy `SECRET_KEY` for each environment.
- Use unique bootstrap passwords and rotate them after initial account creation.
- Use HTTPS, restrict CORS origins, protect the database, and keep dependencies updated.
- Do not rely on the cryptography demonstration modules as post-quantum or production-grade cryptography.
- Do not expose the prototype to untrusted networks without an independent security review.
