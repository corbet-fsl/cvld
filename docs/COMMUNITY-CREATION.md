# Community creation, hosting and ending

A platform process hosts many communities. The **registry** (global scope of
the global database) records every incarnation: id, address, founding
fingerprint, state (`being_created`, `live`, `ending`, `ended`), expiry, hold and
end reason. Each community's own data is a separate scope of the shared
community database, keyed by its address while it lives. A **hub** opens a door
per registered community and one **Host-routing front** serves the global door
and all community doors on a single listener. Hostnames are
`<address>.<base>` (static community app), `vault.<address>.<base>` (static
vault) and `api.<address>.<base>` / `api.admin.<address>.<base>` (this door).

`cvld serve platform --config FILE` enables hosting with a `hub` section:
`template_config` (a complete community configuration used as template),
`master_secret_file` (platform charter master secret, at least 32 bytes),
`token_issuer_file` (RSA private key, DER, for creation tokens only),
`reserved_file` (Root-maintained reserved addresses, JSON array), `shell_seconds`,
optional `per_week` / `per_year` token limits (defaults 1 and 12) and a
`provisioner` (`noop` or `cloudflare`). Statically listed communities keep
working beside the hub; they are not registry entries.

## Addresses

`^[a-z0-9]{8,30}$`, not on the reserved list, not offensive (`rustrict`), unique
among communities that are not ended and not held or blocked. Shorter names are
reserved by length. The same module (`cvld::address`) validates and suggests
names (`any_ascii` transliteration) for the server and for the browser.

## Creation

1. **Token.** A signed-in wallet member asks `creation_token_issue` for a blind
   token (RFC 9474). The service counts per person: at most one per rolling
   7 days and 12 per rolling 365 days. `creation_token_key` publishes the key.
2. **Create.** `community_create` takes no session, only the finished token and
   the address, so the platform cannot link person and community. Order:
   validate address, verify token, reserve its nullifier, insert the shell
   (`being_created`), open the community door (its founding key derives from the
   master secret and the fresh random id; the signer writes its genesis document
   before anything else), record the fingerprint, provision hostnames. Any
   failure rolls back: door closed, hostnames removed, data purged, shell
   removed, nullifier released. The response carries a bearer **claim** secret.
3. **Claim.** The creator registers in the new community like any person, then
   calls `community_creation_claim` with the secret. Membership records the
   creator's commitment (first claim wins).
4. **Admission.** `credential_issue` with `creation: <id>` passes every
   configured gate of the community. The creator becomes the first **admin**
   (the Root board community's first seat is Root). The hub then marks the
   community `live` and spends the token. An abandoned shell expires after
   `shell_seconds`: it is removed and the token is released.

Roots join the new community like any member through the root-board path; no
Root action, bootstrap voucher or special label exists.

## Name and gates at creation

`community_create` carries `display_name` and `gates` with the address and token.
They are checked before anything is created (`legal` is required; every other
gate must be offered by the platform template: `voucher` is the community voucher
gate) and written into the community's founding rulebook as community-layer
values: the admission policy keeps the template's global requirements and only the
chosen community gates, and `community.display_name` holds the name. A community
therefore never exists without them; admins may change them later like any setting.
The hub gives each community its own service record in the shared database.

## Ending

* `community_dissolve` (admins) and `community_terminate` (Root:
  `address`, `reason` legal|terms|name, optional `hold_until` for legal orders,
  optional `block_name`) set the registry state `ending`. From that moment
  nothing is served, the door is closed and hostnames are removed. The community
  scope is then deleted in one transaction and the state becomes `ended`; under a
  hold the deletion happens when the hold passes (the address stays unavailable
  until then). `GET /registry/finished?since=N` lists ending and ended ids and
  returns the newest counter in `x-registry-cursor`.
* `GET /registry/by-host?host=H` returns `{id, state, origins, trust_origin,
  fingerprint}` for a serving community and 404 otherwise. Keys are not served
  by the registry; they come from each community's signed feed, verified against
  the fingerprint.

## Security notes

The creation id presented in `credential_issue` only works for the member whose
commitment `community_creation_claim` recorded. The claim secret is stored only
as a hash. The token key signs creation tokens and nothing else.
