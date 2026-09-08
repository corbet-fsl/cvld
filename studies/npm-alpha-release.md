# First npm alpha

Published on 2026-09-08 as [`@corbet-labs/cvld@0.1.0-alpha.0`](https://www.npmjs.com/package/@corbet-labs/cvld/v/0.1.0-alpha.0), with the `alpha` distribution tag. The registry also assigned `latest` on this initial publication; the version is still explicitly experimental. Use the documented version or `alpha` tag when selecting this release. The unscoped `cvld` name was rejected by npm's similarity policy even though the registry returned no existing package. The repository and component name remain cvld.

The exact package was produced and consumed in [manual CI run 2](https://crow.corbet.ch/repos/11/pipeline/2), source `32c5416c6b0064de7d3b2122f7ee59438e45318c`. All 44 behavioral tests passed. A separate temporary consumer installed the actual tarball with lifecycle scripts disabled, explicitly installed the checksum-pinned native library, and exercised all five published import paths. The release contains 16 files and no cvld installation lifecycle hook.

| Artifact | Value |
|---|---|
| Filename | `corbet-labs-cvld-0.1.0-alpha.0.tgz` |
| Compressed size | 16,280 bytes |
| SHA-256 | `72b53435892a38d9b5aec49519c29c42b0c967495462e4f01e19aff5632e23b0` |
| npm SHA-1 | `316ff5e3efd11c77fbeebdf5bcbc94ed6cac122f` |
| npm maintainer | `julian-corbet` |

After publication, the version metadata and package archive were retrieved anonymously from the registry. The downloaded bytes matched the tested SHA-256 and the registry's SHA-512 integrity value. Registry package-index responses briefly returned cached 404 responses while the version and archive were already available; publication verification used the version endpoint and actual archive.

The published cryptographic source, explicit native installer and browser test are unchanged from the earlier [Chromium virtual-authenticator run](https://github.com/corbet-labs/cvld/actions/runs/34258786567). The manual worker did not run a browser or mobile device. This alpha supports the documented Linux x64/glibc Node experiment; native mobile holder adapters, compatible live providers and production privacy guarantees remain incomplete. See the [README](../README.md) for installation and boundaries.
