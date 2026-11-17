# Pattern B across two Okta orgs

The demo runs Pattern B in one Okta org: no authorization server trusts another, so each hop uses an ID-JAG. This guide shows how to make Pattern B's **second hop** cross into a second Okta org, as it would with a third party or SaaS provider that runs its own Okta. Pattern A and Pattern B's first hop don't change.

Source: Okta's guide [Configure Cross App Access with an external IdP](https://developer.okta.com/docs/guides/xaa-external-idp/main/).

## What changes

| Hop | Today (one org) | Across orgs |
|---|---|---|
| 1 · your backend: T1 → ID-JAG → T2 | Org A: `anyco-agent-b-as` trusts no other server | unchanged, Org A |
| 2 · the agent: T2 → ID-JAG → T3 | Org A: `anyco-gateway-as` redeems the ID-JAG | **Org A issues the ID-JAG; Org B's server redeems it for T3** |

The ID-JAG always comes from the user's home org (Org A). Org B never issues one; it only redeems it.

| Org | Role | Needs |
|---|---|---|
| **Org A** (issuing org, the IdP) | Ada, Alan, your backend, the agent, every ID-JAG | API Access Management, Okta for AI Agents, the **Okta Org2Org** app from the Okta Integration Network catalog |
| **Org B** (resource org) | the authorization server for T3 | API Access Management; an identity provider for Org A. If that IdP is a generic OpenID Connect provider rather than an Okta Integration one, Org B also needs Okta for AI Agents |

> **Okta Integrator Free Plan orgs can't do this.** They don't include the app catalog, so Org A can't add the Org2Org app (the API answers `E0000015 You do not have permission to access the feature you are requesting`). Without that app, Org A has nothing to address the ID-JAG to, and step 1 is refused: `invalid_target: Token Exchange requests must include a valid audience of the authorization server`. Use an Okta org whose plan includes the Okta Integration Network catalog.

## Names
The demo's naming rule applies: `-as` for authorization servers, `-app` for apps, `-oai` for AI agents, and `api://<name>-aud` for audiences.

| Object | Org | Name |
|---|---|---|
| Authorization server for T3 | B | `anyco-gateway-b-as`, audience `api://anyco-gateway-b-aud` |
| The agent's client | B | `anyco-pr-review-agent-b-app` |
| Identity provider for Org A | B | `anyco-orga-idp` |
| Org2Org app (represents Org B) | A | `anyco-orgb-org2org-app` |

## Org B: the resource side

### 1. Authorization server
Security > API > Authorization Servers > **Add Authorization Server**: Name `anyco-gateway-b-as`, Audience `api://anyco-gateway-b-aud`.
- Scopes: `pr:read`, `pr:review`, `pr:merge`, `context:search` (as on `anyco-gateway-as`; no rule grants `pr:merge`).
- Trusted servers: none.

It must be a custom authorization server. Okta's org authorization server doesn't accept external ID-JAGs.

### 2. The agent's client
**Create App Integration** > **API Services**, named `anyco-pr-review-agent-b-app`.
- Grant types: **JWT Bearer**. Okta also keeps Client Credentials on for service apps; no rule grants it.
- Client authentication: **Public key / Private key**. Add the agent's public key, `build/jwks/anyco-pr-review-agent-b.json`, the same KMS key the agent uses in Org A.

→ Note its **client ID**. Org A's resource connection (step 8) and AgentCore Identity (step 10) both use it.

### 3. Users and group
Create Ada, Alan and Grace, and a group `anyco-engineers` with Ada and Alan. They never sign in to Org B; they exist so Org A's identities can be linked to them (step 6).

### 4. Identity provider for Org A
This needs the Org2Org app's client ID and secret, so do step 7 first if you haven't.

Security > **Identity Providers** > Add identity provider > **Okta Integration**.
- Name `anyco-orga-idp`; Org A's URL; the client ID and secret of Org A's Org2Org app (step 7).
- **IdP Usage: Cross App Access only.** Okta trusts ID-JAGs only from identity providers set to *Cross App Access only* or *SSO and Cross App Access*, and you can't change this setting after saving: to change it, delete the IdP and create a new one.

Okta checks each ID-JAG's signature with the identity provider's keys, and requires its `iss` to match exactly one such identity provider.

### 5. Access policy and rule
On `anyco-gateway-b-as` > Access Policies > Add New Access Policy `anyco-pr-review-agent-b-app`, assigned to that client.
- Rule `delegated-for-engineers`: grant type **JWT Bearer**, group `anyco-engineers`, scopes `pr:read pr:review`, access token lifetime 5 minutes.
- Restrict it to Org A's identity provider. This condition is set through the API: replace the rule (`PUT /api/v1/authorizationServers/{authServerId}/policies/{policyId}/rules/{ruleId}`, sending the whole rule) with this added to its `conditions`:
```json
"xaaSupportedIdentityProvider": {"provider": "SPECIFIC_IDP", "idpIds": ["<anyco-orga-idp ID>"]}
```

### 6. Link the users
With *Cross App Access only*, users are linked by hand, one API call each:
```
POST /api/v1/idps/<anyco-orga-idp ID>/users/<Org B user ID>
{"externalId": "<the user's Org A user ID>"}
```
The `externalId` must equal the ID-JAG's `sub`, which is the user's Okta user ID in Org A (`00u…`). If no linked user matches, Org B refuses the ID-JAG.

## Org A: the issuing side

### 7. Org2Org app
Applications > **Browse App Catalog** > **Okta Org2Org** > Add.
- Label `anyco-orgb-org2org-app`; Base URL = Org B's URL.
- **Sign On** tab: OpenID Connect. Note its client ID and secret for Org B's identity provider (step 4).

### 8. Cross App Access on the Org2Org app
- **General** tab: **Custom Authorization Server ID** = the ID of `anyco-gateway-b-as`. Until it's set, the XAA settings on the **Machine Assignments** tab aren't available.
- **Machine Assignments** tab: enable **Cross App Access**; **Issuer URL** = `anyco-gateway-b-as`'s issuer (`https://<org-b>.okta.com/oauth2/<ID>`).

### 9. The agent's resource connection
On the AI agent `anyco-pr-review-agent-b-oai` > **Resource connections** > Add:
- Resource type **Application instance** > `anyco-orgb-org2org-app`.
- The AI agent's client ID registered in this app: the client ID from step 2.
- Scopes: `pr:read`, `pr:review`.

Org A now issues ID-JAGs for this agent with `anyco-gateway-b-as` as the audience. The agent's machine access (the delegation link from the backend agent) doesn't change, so T2 is still accepted as step 1's subject.

## AWS: Pattern B only

### 10. Changes
- **A Gateway for Pattern B.** A Gateway's CUSTOM_JWT authorizer takes one issuer, and Pattern A keeps Org A's `anyco-gateway-as`. Pattern B's Gateway uses the same tool targets, interceptor and policy engine, with:
  - discovery URL: `anyco-gateway-b-as`;
  - audience: `api://anyco-gateway-b-aud`.
- **AgentCore Identity, step 1 (`anyco-xaa-step1`):** unchanged (Org A's org server). The agent's step-1 `audience` parameter (`XAA_CUSTOM_AS_ISSUER`) becomes `anyco-gateway-b-as`'s issuer.
- **AgentCore Identity, step 2 (`anyco-xaa-step2`):**
  - discovery URL: `anyco-gateway-b-as`;
  - client ID: `anyco-pr-review-agent-b-app` (Org B);
  - still `PRIVATE_KEY_JWT` with the same KMS key.
- **Cedar B:** `cid` = Org B's client ID. Check what Org B puts in T3's `act` before keeping the rule that the backend agent appears in it.
- **Runtime B:** its `GATEWAY_URL` points at Pattern B's Gateway.

Pattern A, hop 1 and Pattern C need no change.

## What the ID-JAG must carry
Org B accepts the ID-JAG only if:

| Claim | Must be |
|---|---|
| `iss` | Org A's org server, matching exactly one identity provider set to Cross App Access |
| `aud` | `anyco-gateway-b-as` |
| `client_id` | the client making the request at Org B (`anyco-pr-review-agent-b-app`) |
| `sub` | the `externalId` of a linked user in Org B |
| lifetime | no more than 5 minutes; usable once |

## Testing hop 2 against Okta, before AWS
1. Get T1 and the backend's T2 as today (`scripts/headless_login.py`, then hop 1 of `scripts/xaa_test.py`).
2. As `anyco-pr-review-agent-b-oai`, at Org A's `/oauth2/v1/token`: token exchange, subject T2, `requested_token_type` id-jag, `audience` = `anyco-gateway-b-as`'s issuer, scope `pr:read pr:review`.
3. As `anyco-pr-review-agent-b-app`, at `anyco-gateway-b-as`'s `/v1/token`: JWT bearer with the ID-JAG as `assertion`.
   - Both client assertions are signed by the same KMS key. Step 2's has `iss` and `sub` = the Org B client ID.
4. Check T3: `iss` = `anyco-gateway-b-as`, `aud` = `api://anyco-gateway-b-aud`, `sub` = the linked Org B user, and whatever Org B puts in `act`.

## Limits
- **Pattern C can't cross orgs.** Its subject is an app, not a user, and Org B links ID-JAGs only to users.
- **The `act` chain across orgs** isn't covered in Okta's guide. Check T3 before relying on it in Cedar.
- **Okta for AI Agents is in beta**, and the console labels above can change. Match them by meaning.
