# Licensing

Copyright 2026 Julian Y. Richard Corbet.

The browser coverage runtime is licensed under **LGPL-3.0-only WITH LGPL-3.0-linking-exception**.
This covers the library's Rust implementation, tests and documentation. The complete
[LGPL version 3](LICENSES/LGPL-3.0-only.txt) incorporates
[GPL version 3](LICENSES/GPL-3.0-only.txt); the
[linking exception](LICENSES/LGPL-3.0-linking-exception.txt) waives the
Minimal Corresponding Source, Minimal Application Code and
installation-information duties (LGPLv3 §§4d/4e) for combined works that
link statically or dynamically.

Applications may use the library under different licenses subject to the LGPL's
conditions. Distribution must preserve the library's notices and the openness
of library modifications, including reverse engineering to debug such changes.
The application license must not restrict those library rights. No relinking
route or object files are required for combined works under the exception.

## Test-only Veilid reference material

`tests/unit/veilid_reference.rs` and `tests/fixtures/rfc9180_a2_base.json` are
separate [MPL-2.0](LICENSES/MPL-2.0.txt) reference material adapted/copied from
[Veilid at dd8e2cdd72b5bf817172ac31c20872b168c5c8fc](https://gitlab.com/veilid/veilid/-/tree/dd8e2cdd72b5bf817172ac31c20872b168c5c8fc).
The fixture reproduces RFC 9180 Appendix A.2.1. These files are compiled only in
tests; the production library does not depend on or embed veilid-core.
