# Deploying to Azure Container Apps

These are notes for a first deployment, written to be followed with the Azure CLI. They have **not** been executed
against a real subscription; treat resource names and SKUs as starting points. Pick your own values for the variables.

```bash
RG=identity-rg; LOC=westeurope; ENV=identity-env; ACR=identityacr$RANDOM; KV=identity-kv-$RANDOM
PG=identity-pg-$RANDOM; MI=identity-mi
```

## Topology

```
Internet ── HTTPS ingress ──> admin-console  (nginx, static, external)
        └─ HTTPS ingress ──> identity-api    (external: browsers and the ledger reach OIDC/JWKS here)
                                 │  managed identity ──> Key Vault (secrets)
                                 └────────────────────> PostgreSQL Flexible Server (private)
ledger (internal ingress) ── fetches JWKS ──> identity-api
```

## One-time setup

```bash
az group create -n $RG -l $LOC
az acr create -g $RG -n $ACR --sku Basic --admin-enabled false
az identity create -g $RG -n $MI
az keyvault create -g $RG -n $KV --enable-rbac-authorization true
az containerapp env create -g $RG -n $ENV -l $LOC            # also creates Log Analytics

# PostgreSQL, TLS on by default. Prefer private access in production (--vnet/--subnet).
az postgres flexible-server create -g $RG -n $PG -l $LOC --tier Burstable --sku-name Standard_B1ms \
  --database-name identity --admin-user identityadmin --admin-password "$(openssl rand -base64 24)"

# Let the app's managed identity read secrets and pull images (least privilege: read secrets only).
MI_ID=$(az identity show -g $RG -n $MI --query principalId -o tsv)
az role assignment create --assignee $MI_ID --role "Key Vault Secrets User" \
  --scope $(az keyvault show -n $KV --query id -o tsv)
az role assignment create --assignee $MI_ID --role AcrPull --scope $(az acr show -n $ACR --query id -o tsv)
```

Generate the signing certificate and keys and put them in Key Vault (see [key-management.md](key-management.md)):

```bash
az keyvault secret set --vault-name $KV -n signing-pfx           --value "$(base64 -w0 signing.pfx)"
az keyvault secret set --vault-name $KV -n signing-pfx-password  --value "$PFX_PASSWORD"
az keyvault secret set --vault-name $KV -n token-encryption-key  --value "$(openssl rand -base64 32)"
az keyvault secret set --vault-name $KV -n mfa-encryption-key    --value "$(openssl rand -base64 32)"
az keyvault secret set --vault-name $KV -n identity-db-connection --value "Host=$PG.postgres.database.azure.com;Database=identity;Username=...;Password=...;SSL Mode=Require"
```

Create the app. Secrets are Key Vault references resolved through the managed identity, never literal values:

```bash
KVURI=https://$KV.vault.azure.net/secrets
az containerapp create -g $RG -n identity-api --environment $ENV \
  --image mcr.microsoft.com/k8se/quickstart:latest --target-port 8080 --ingress external \
  --user-assigned $MI --registry-server $ACR.azurecr.io --registry-identity $(az identity show -g $RG -n $MI --query id -o tsv) \
  --min-replicas 1 --max-replicas 1 \
  --secrets signing-pfx=keyvaultref:$KVURI/signing-pfx,identityref:$(az identity show -g $RG -n $MI --query id -o tsv) \
            signing-pfx-password=keyvaultref:$KVURI/signing-pfx-password,identityref:$(az identity show -g $RG -n $MI --query id -o tsv) \
            token-encryption-key=keyvaultref:$KVURI/token-encryption-key,identityref:$(az identity show -g $RG -n $MI --query id -o tsv) \
            mfa-encryption-key=keyvaultref:$KVURI/mfa-encryption-key,identityref:$(az identity show -g $RG -n $MI --query id -o tsv) \
            db=keyvaultref:$KVURI/identity-db-connection,identityref:$(az identity show -g $RG -n $MI --query id -o tsv) \
  --env-vars ASPNETCORE_ENVIRONMENT=Production \
    Server__Issuer=https://<identity-fqdn>/ \
    Server__TrustForwardedHeaders=true \
    Cors__AllowedOrigins__0=https://<console-fqdn> \
    OAuthClients__0__ClientId=admin-console \
    OAuthClients__0__RedirectUris__0=https://<console-fqdn>/auth/callback \
    Signing__Certificates__0__Pfx=secretref:signing-pfx \
    Signing__Certificates__0__Password=secretref:signing-pfx-password \
    Signing__EncryptionKey=secretref:token-encryption-key \
    Mfa__EncryptionKey=secretref:mfa-encryption-key \
    ConnectionStrings__Identity=secretref:db
```

For the **first** start only, also set `Bootstrap__AdminEmail` and `Bootstrap__AdminPassword` (a Key Vault secret), then
remove both and redeploy once the admin exists.

The admin console app is a second Container App from the `admin-console` image with `API_URL` and `API_ORIGIN` set to the identity
app's URL. The ledger runs as an *internal* Container App with
`IDENTITY_JWKS_URI=https://<identity-fqdn>/.well-known/jwks` and `IDENTITY_ISSUER=https://<identity-fqdn>/`.

### CI/CD identity (no stored credentials)

Create an Entra app registration with a **federated credential** for this repository and environment `production`
(`subject: repo:<owner>/<repo>:environment:production`), grant it `Contributor` on the resource group and `AcrPush` on
the registry, then set these **repository variables** (they are IDs, not secrets): `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
`AZURE_SUBSCRIPTION_ID`, `AZURE_RESOURCE_GROUP`, `ACR_NAME`, `IDENTITY_APP`, `CONSOLE_APP`. Add required reviewers to the
`production` environment to gate deployments. The workflow is `.github/workflows/deploy.yml`.

## Things that matter behind the ingress

- **TLS terminates at the ingress**, so the app sees plain HTTP. `Server__TrustForwardedHeaders=true` makes it honour
  `X-Forwarded-Proto` (so cookies are `Secure` and OpenIddict's HTTPS requirement is satisfied) and `X-Forwarded-For` (so per-IP
  rate limits see the client, not the ingress). Only enable it when the ingress is the sole path to the container.
- **Run one replica** (`--min-replicas 1 --max-replicas 1`) until the rate limiter has a shared store. Its counters are in memory,
  so N replicas allow N times the limit. Lockout is in the database and is already correct at any scale.
- **Migrations run on start** (`Database:InitializeOnStart`, default true). With several replicas, prefer a separate migration job
  with the owner role and set `Database__InitializeOnStart=false` on the app.
- **Health probes:** liveness `GET /health` (no database call, so a DB blip does not restart the app).
- **Logs** go to Log Analytics through the environment. The audit log is in PostgreSQL, not in logs; export it on a schedule to
  write-once storage if you need an independent copy.
- **Egress and networking:** put PostgreSQL and Key Vault behind private endpoints and give the environment a VNet.
