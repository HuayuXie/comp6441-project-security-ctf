# Security Notice

This repository is an intentionally vulnerable educational lab created for COMP6441.

- Run the application only on `127.0.0.1` in a local environment.
- Do not expose the Flask development server to the internet or a shared network.
- Do not use the vulnerable examples as production code.
- Use only the included test data and flags; the project is not designed to target any real system.

The `/secure/challenge/*` routes are defensive comparisons. They are included to connect each exploit to a practical mitigation, not to claim that this small teaching application is production-ready. Challenge 6 displays a generated reset token only so the local control can be tested; a real service must deliver such a token through a verified out-of-band channel and must never expose it on the reset page.
