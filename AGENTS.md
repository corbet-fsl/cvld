# cvld development

One Rust package, library and binary. Compose cglb and cmnt; domain decisions
belong in their facades and leaves. Define actions once in src/api. HTTP,
OpenAPI, CLI and MCP must expose exactly that registry. Keep generated clients
in sync. Never publish to npm or crates.io.

Keep global and community databases, keys and authentication isolated. Never log
requests, identifiers, handles, IPs, bodies, secrets or dependency errors. No
cryptographic primitives here. Inputs are hostile; authenticate roles and exact
hosts before executing actions. Credentials come only from supplied configuration.

Do not run cargo on the workstation. Validate on GitHub Actions using current
stable Rust, real libSQL and WebAuthn/credential round trips. No deployment.
Use explicit-path commits, plain English imperative messages, no AI attribution.
