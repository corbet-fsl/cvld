# Releasing

`@corbet-labs/cvld` ships to npm only. A pushed `vX.Y.Z` tag is the one release
trigger; `.github/workflows/release.yml` never holds a registry token.

## What CI does

1. Checks that the tag equals `v` + the `package.json` version and that
   `package-lock.json` records the same version.
2. Runs `test.yml` as a reusable workflow: behavioral tests, the browser PRF
   test, the holder WebAssembly build and the packed-consumer check, which
   installs the actual tarball outside the checkout.
3. Verifies that evidence, then attaches `corbet-labs-cvld-X.Y.Z.tgz` and a
   `SHA256SUMS` file to a GitHub release created with `--verify-tag`. Tags
   containing `-` become prereleases. An existing release is never modified.

The tarball must come from CI: `generated/holder/` is built there and is not
committed, so `npm publish` from a checkout would ship an incomplete package.

A rehearsal runs everything except the release:
`gh workflow run release.yml -R cmtymeet/cvld --ref main`. The verified bundle
is kept as the `cvld-release-X.Y.Z` workflow artifact. To recreate a missing
release, dispatch on the tag: `gh workflow run release.yml --ref vX.Y.Z -f tag=vX.Y.Z`.

## Steps for a release

1. Bump `version` in `package.json` and `package-lock.json` (both entries) and
   the README install line; push to `main`.
2. Push the tag: `git tag vX.Y.Z && git push origin vX.Y.Z`, then wait for the
   Release workflow to finish.
3. Publish the attached tarball with the npm token from sops:

   ```sh
   gh release download vX.Y.Z -R cmtymeet/cvld -D cvld-release
   cd cvld-release && sha256sum --check --strict SHA256SUMS
   umask 077; rc=$(mktemp)
   printf '//registry.npmjs.org/:_authToken=%s\n' \
     "$(sops --decrypt ~/agents/knowledge/secrets/npm.yml | yq -r .api_token)" > "$rc"
   npm publish ./corbet-labs-cvld-X.Y.Z.tgz --userconfig "$rc" --access public --tag alpha
   shred -u "$rc"
   ```

   Use `--tag alpha` for prereleases (it matches `publishConfig.tag`) and
   `--tag latest` for stable versions. While no stable version exists, also
   move `latest` so plain installs do not stay on an older alpha:
   `npm dist-tag add @corbet-labs/cvld@X.Y.Z latest --userconfig "$rc"`
   (before `shred`).
4. Confirm the registry holds the same bytes:
   `npm view @corbet-labs/cvld@X.Y.Z dist.integrity` must equal
   `sha512-$(openssl dgst -sha512 -binary corbet-labs-cvld-X.Y.Z.tgz | base64 -w0)`.

## Trusted publishing

Once npm trusted publishing is configured for `cmtymeet/cvld` with the workflow
file `release.yml` (it needs the owner's 2FA; planned for December 2026 when
the stored token expires), add an OIDC `npm publish` job to `release.yml` and
drop step 3.
