# Key and secret management

Nothing secret is in the repository. Every secret is configuration read at start-up from environment variables
(`Section__Key` maps to `Section:Key`), and in production those come from a secret store, not from files in an image.
`.env`, `*.pfx`, `*.pem` and `*.key` are git-ignored, `.dockerignore` keeps them out of images, and CI runs gitleaks over
the full history.

## What exists

| Secret | Config key | Used for | If it leaks |
| --- | --- | --- | --- |
| Token signing key(s) (RSA 2048, X.509 in a PFX) | `Signing:Certificates:N:Pfx` / `:Password` | Sign access tokens, ID tokens and refresh tokens (RS256) | An attacker can mint tokens the ledger accepts. **Highest impact.** |
| Token encryption key (256-bit) | `Signing:EncryptionKey` | Encrypts refresh tokens and authorization codes (they are JWEs) | Refresh tokens become readable; they still need the signing key to be forged |
| MFA secret key (256-bit) | `Mfa:EncryptionKey` | AES-256-GCM encryption of TOTP secrets in the database | Combined with a database leak, TOTP secrets are recoverable |
| Database password | `ConnectionStrings:Identity` | PostgreSQL | Read and write everything except the audit log's immutability (triggers), which a DB owner can still drop |
| Bootstrap admin password | `Bootstrap:AdminPassword` | Creates the first admin, only when no users exist | Remove it from configuration after first start |

The public half of the signing key is published at `/.well-known/jwks`. That is by design; the private half never leaves the
identity service.

## Production layout (Azure)

- **Azure Key Vault** holds every secret above. The signing PFX is stored as a Key Vault *secret* (base64 PFX) or a
  *certificate*; the app's **managed identity** is granted `get` on secrets only. No client secret is needed to read them.
- **Container Apps secrets reference Key Vault** (`az containerapp secret set --secrets name=keyvaultref:<secret-uri>,identityref:<mi>`),
  and environment variables reference those secrets (`secretref:`). Rotating a value in Key Vault takes effect on the next
  revision/restart. Values never appear in the image, the compose file, the workflow logs or the repo.
- The database runs on Azure Database for PostgreSQL Flexible Server, private endpoint or VNet integration, TLS required.
  Use **two roles**: a migration role (owner, used only by the migration job) and a runtime role with `SELECT, INSERT, UPDATE,
  DELETE` on application tables but **only `SELECT, INSERT` on `audit_log`**. The audit trigger is then a second lock, not the
  only one.
- GitHub Actions authenticates to Azure with **OIDC federation**: no long-lived Azure credentials are stored in GitHub.

## Rotating the signing key (zero downtime)

OpenIddict signs with the registered certificate that **expires last**, and publishes every registered key in the JWKS.
That gives a safe overlap:

1. **Create** a new certificate with a later expiry than the current one (`openssl req -x509 -newkey rsa:2048 -days 90 ...`,
   export as PFX) and store it in Key Vault.
2. **Add it as a second entry**: `Signing__Certificates__1__Pfx` / `__Password`, keeping entry 0. Deploy.
   New tokens are now signed with the new key; the JWKS lists both; tokens signed by the old key still verify.
3. **Wait** for the old key's tokens to expire. Access tokens live 10 minutes, but refresh tokens (7 days) are also signed, so
   keep the old key for at least the refresh-token lifetime.
4. **Remove** entry 0 (and its Key Vault secret) and deploy. The JWKS now lists only the new key.

The ledger needs no change: it caches the JWKS, and an unknown `kid` triggers a rate-limited refetch, so it picks the new key up
on its own. `Key_rotation_new_key_signs_and_old_tokens_still_verify` in the test suite exercises steps 2-3.

Rotate on a schedule (every 60-90 days) and immediately on suspected compromise. On compromise, skip the overlap: remove the old
key at once (all sessions end, users sign in again) and revoke sessions from the admin console.

## Rotating the other secrets

- **Token encryption key:** rotating it invalidates outstanding refresh tokens and authorization codes (everyone signs in again).
  Acceptable for a scheduled maintenance window; there is no overlap mechanism.
- **MFA encryption key:** the current design uses one key, so rotating it needs a re-encryption pass over `users.mfa_secret`
  (decrypt with the old key, encrypt with the new). A key id prefix on the blob and a two-key configuration would make this online;
  it is listed under limitations.
- **Database password:** rotate in Key Vault, restart the app. Prefer Entra ID authentication for PostgreSQL to remove the
  password entirely.

## Development

`scripts/dev-secrets.sh` generates a throwaway `.env` (random passwords, a fresh self-signed certificate, fresh keys) for docker
compose. In `Development` only, the app falls back to an **ephemeral** signing key when none is configured (tokens die on restart);
any other environment refuses to start without real keys. `Mfa:EncryptionKey` has no fallback anywhere:

```bash
dotnet user-secrets set "Mfa:EncryptionKey" "$(openssl rand -base64 32)"
```
