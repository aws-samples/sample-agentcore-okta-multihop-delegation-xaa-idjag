# Okta setup (by hand, in the Admin Console)

This guide creates every Okta object the demo uses, in your own Okta org. Nothing here needs an Okta API token: you click through the Admin Console, then copy a few IDs into `.env`.

**Prefer a script?** `okta_setup.py` does these same steps (parts 1 to 4, same names) with the Okta Admin API, if you give it an Okta admin's API token as `OKTA_API_TOKEN` in `.env`. It writes the IDs into `.env` for you. `okta_setup.py --check` only reports what exists. See the README, step 3.

Use the names exactly as written. The audiences and scope names are fixed in the code.

| Part | Needed for | Okta features |
|---|---|---|
| [1 · Users, group, sign-in](#part-1--users-group-sign-in) | everything | — |
| [2 · Pattern A · OBO/Delegation (token exchange)](#part-2--pattern-a--obodelegation-token-exchange) | Pattern A | API Access Management (custom authorization servers) |
| [3 · Pattern B · Cross App Access (user)](#part-3--pattern-b--cross-app-access-user) | Pattern B | + Okta for AI Agents |
| [4 · Pattern C · Cross App Access (machine)](#part-4--pattern-c--cross-app-access-machine) | Pattern C | + Okta for AI Agents (machine access) |

**Before you start**
- Run `.venv/bin/python kms_keys.py` (see the README). It creates four AWS KMS signing keys and prints their public JWKs; they are also saved in `build/jwks/`. Parts 3 and 4 paste these public keys into Okta. The private keys never leave KMS.
- Okta for AI Agents is in beta, and Okta changes its console labels from time to time. If a label below differs, match it by meaning.
- Every token request in this demo is a plain bearer request. If an app shows **Require Demonstrating Proof of Possession (DPoP) header in token requests**, clear it.

---

## Part 1 · Users, group, sign-in

**1.1 Users** (Directory > People > Add person). Set a password for each user.

| User | Role in the demo |
|---|---|
| `ada.lovelace@example.com` | engineer |
| `alan.turing@example.com` | engineer |
| `grace.hopper@example.com` | not an engineer (gets refused) |

**1.2 Group** (Directory > Groups > Add group): `anyco-engineers`. Add Ada and Alan, not Grace.

**1.3 Sign-in policy (demo convenience).** The test scripts and a quick demo are easier when these three users can sign in with a password only.
1. Go to Security > Authentication Policies > **Add a policy**, named `anyco-demo-password`.
2. Add a rule that allows password-only sign-in for these users.
3. In part 2 you assign this policy to the sign-in app, `anyco-eng-login-app`.

Your org's global session policy must also allow password-only sign-in. Don't use this policy outside a demo org. If you skip it, sign-in still works; the users just complete MFA.

---

## Part 2 · Pattern A · OBO/Delegation (token exchange)

Two one-step token exchanges, each by a **service** app:
1. **Your backend** exchanges the engineer's sign-in token (T1, from `anyco-users-as`) at `anyco-agent-a-as`, getting T2 for the agent.
2. **The agent** exchanges T2 at `anyco-gateway-as`, getting T3 for the Gateway.

Each authorization server trusts the one before it, and each token's `act` keeps the trail.

### 2.1 App `anyco-eng-login-app` (the console's engineer sign-in)
Applications > Applications > **Create App Integration** > OIDC - OpenID Connect > **Web Application**.

| Field | Value |
|---|---|
| App integration name | `anyco-eng-login-app` |
| Grant type | Authorization Code |
| Sign-in redirect URI | `http://localhost:8010/callback` |
| Sign-out redirect URI | `http://localhost:8010/` |
| Client authentication | Client secret |
| Assignments | Ada, Alan, Grace |

On the **Sign On** tab, set the authentication policy to `anyco-demo-password` (optional, see 1.3).

→ `.env`: `OKTA_LOGIN_CLIENT_ID` and `ANYCO_LOGIN_CLIENT_SECRET`.

### 2.2 App `anyco-pr-review-agent-app` (the agent's identity for the token exchange)
**Create App Integration** > **API Services**, named `anyco-pr-review-agent-app`.
1. On the General tab, click **Edit** in General Settings.
2. Under Grant type, open **Advanced** and select **Token Exchange**. Okta keeps Client Credentials on for service apps; no rule grants it.
3. Client authentication: **Client secret**.

→ `.env`: `OKTA_AGENT_CLIENT_ID` and `OKTA_AGENT_CLIENT_SECRET`.

### 2.3 App `anyco-console-backend-app` (your backend's identity for its token exchange)
**Create App Integration** > **API Services**, named `anyco-console-backend-app`.
1. On the General tab, click **Edit** in General Settings.
2. Under Grant type, open **Advanced** and select **Token Exchange**.
3. Client authentication: **Client secret**.

It has to be a service app. Okta refuses an on-behalf-of exchange requested by a web app ("web app to web app isn't supported"), so the backend can't reuse `anyco-eng-login-app` for this.

→ `.env`: `OKTA_BACKEND_CLIENT_ID` and `ANYCO_BACKEND_CLIENT_SECRET`.

### 2.4 Authorization server `anyco-users-as` (where engineers sign in)
Security > API > Authorization Servers > **Add Authorization Server**.

| Field | Value |
|---|---|
| Name | `anyco-users-as` |
| Audience | `api://anyco-pr-agent-aud` |

- **Scopes** tab > Add Scope: `pr-agent.invoke` (Invoke the PR Review Agent). Set user consent to Implicit.
- **Access Policies** > Add New Access Policy `anyco-sign-in`, assigned to **The following clients** > `anyco-eng-login-app`.
  - Rule `engineers-may-invoke`:
    - Grant type: **Authorization Code**.
    - User is a member of group `anyco-engineers`.
    - Scopes: `openid`, `profile`, `email`, `pr-agent.invoke`.
    - Access token lifetime: 1 hour.
  - Rule `everyone-sign-in-only`:
    - Grant type: **Authorization Code**.
    - Any user assigned the app.
    - Scopes: `openid`, `profile`, `email`.

Grace matches only the second rule. Okta refuses her request for `pr-agent.invoke`, so she can sign in but can't call the agent.

### 2.5 Authorization server `anyco-agent-a-as` (tokens for the Pattern A agent)
**Add Authorization Server**: Name `anyco-agent-a-as`, Audience `api://anyco-agent-a-aud`.

- **Scopes**: add `agent-a.invoke` (Call the Pattern A agent). Set user consent to Implicit.
- **Trusted servers**: click **Edit** on its settings, then under **Trusted servers** click **Add Server** and add `anyco-users-as`. This lets it accept T1 as the subject of the backend's exchange.
- **Access Policies** > Add New Access Policy `anyco-console-backend-app`, assigned to the client `anyco-console-backend-app`.
  - Rule `backend-for-engineers`:
    - Grant type: **Token Exchange** (under Advanced).
    - User is a member of group `anyco-engineers`.
    - Scopes: `agent-a.invoke`.
    - Access token lifetime: 5 minutes.

Only this server issues tokens that Runtime A accepts, and only to the backend. A token Ada got at sign-in is refused by Runtime A (wrong issuer).

### 2.6 Authorization server `anyco-gateway-as` (what AgentCore Gateway trusts)
**Add Authorization Server**: Name `anyco-gateway-as`, Audience `api://anyco-gateway-aud`.

- **Scopes**: add `pr:read`, `pr:review`, `pr:merge`, `context:search`.
  - No rule ever grants `pr:merge`. It exists so a merge request is visibly refused.
- **Trusted servers**: open the server, click **Edit** on its settings, and under **Trusted servers** click **Add Server**. Add `anyco-agent-a-as`.
  - This lets `anyco-gateway-as` accept T2, issued by `anyco-agent-a-as`, as the subject of the agent's token exchange. It doesn't trust `anyco-users-as`, so Ada's sign-in token can't be exchanged here directly.
- **Access Policies** > Add New Access Policy `anyco-pr-review-agent-app`, assigned to the client `anyco-pr-review-agent-app`.
  - Rule `on-behalf-of-engineers`:
    - Grant type: **Token Exchange** (under Advanced).
    - User is a member of group `anyco-engineers`.
    - Scopes: `pr:read`, `pr:review`.
    - Access token lifetime: 5 minutes.

### 2.7 IDs to copy
→ `.env`: `OKTA_USERS_AS_ID`, `OKTA_AGENT_A_AS_ID` and `OKTA_GATEWAY_AS_ID`. These are the IDs in each server's issuer URL, `https://<your-org>.okta.com/oauth2/<ID>`.

---

## Part 3 · Pattern B · Cross App Access (user)

Same sign-in as Pattern A, but no authorization server trusts another. Your backend and the agent are each a registered **Okta AI agent**, and each gets its next token with an ID-JAG (Cross App Access):

| Hop | Who asks | Subject | ID-JAG for | Token |
|---|---|---|---|---|
| 1 | your backend, AI agent `anyco-backend-agent-oai` | T1 (Ada's sign-in token) | `anyco-agent-b-as` | T2 |
| 2 | the agent, AI agent `anyco-pr-review-agent-b-oai` | T2 | `anyco-gateway-as` | T3 |

Both AI agents use **machine access**: a delegation link lets an access token issued to another client be the subject of their token exchange.

### 3.1 Authorization server `anyco-agent-b-as` (tokens for the Pattern B agent)
**Add Authorization Server**: Name `anyco-agent-b-as`, Audience `api://anyco-agent-b-aud`.
- **Scopes**: add `agent-b.invoke`. Set user consent to Implicit.
- **Trusted servers**: leave empty. A token exchange of T1 here is refused ("The 'subject_token' issuer isn't a trusted authorization server"); only an ID-JAG gets in.
- The access policy comes in 3.4, after the backend agent exists.

→ `.env`: `OKTA_AGENT_B_AS_ID`.

### 3.2 Register your backend as the AI agent `anyco-backend-agent-oai`
Directory > AI Agents > **Register AI agent** > **Register manually**.
1. Name `anyco-backend-agent-oai`.
2. User access: turn **Allow users to access this agent** off. Users sign in through `anyco-eng-login-app`, not this agent.
3. On the **Client registration** tab, configure **Public/private key**, managed in Okta: **Add public key**, paste `build/jwks/anyco-backend-agent.json`, **Done**, then **Activate** > **Enable**. Don't click "Generate new key": the key has to be the KMS one.

→ `.env`:
- `OKTA_BACKEND_AGENT_CLIENT_ID`: its Client ID.
- `OKTA_BACKEND_AGENT_KID`: the key's Key ID, as Okta shows it.

### 3.3 Machine access for the backend agent: T1 may be its subject
On the backend agent's **Machine access** tab:
1. **Configure**:
   - Authorization server: `anyco-users-as`.
   - Audience/resource URL: `api://anyco-pr-agent-aud`. That's T1's audience, and Okta doesn't let you change it later.
   - **Save**.
2. **Add caller** > **Application or service** > `anyco-eng-login-app`.

This delegation link lets the backend agent use T1, which was issued to `anyco-eng-login-app`, as the subject of step 1.

### 3.4 Resource connection to `anyco-agent-b-as`, and its access policy
1. On the backend agent's **Resource connections** tab > **Add resource connection**: **Authorization server** `anyco-agent-b-as`, scope `agent-b.invoke`.
2. Open `anyco-agent-b-as` > Access Policies > Add New Access Policy `anyco-backend-agent-oai`, assigned to the AI agent `anyco-backend-agent-oai`.
   - Rule `backend-agent-for-engineers`:
     - Grant type: **JWT Bearer**.
     - User is a member of group `anyco-engineers`.
     - Scopes: `agent-b.invoke`.
     - Access token lifetime: 5 minutes.
3. **Actions > Activate** the backend agent.

### 3.5 Register the agent as the AI agent `anyco-pr-review-agent-b-oai`
The same steps as 3.2: name `anyco-pr-review-agent-b-oai`, user access off, public key `build/jwks/anyco-pr-review-agent-b.json`.

→ `.env`:
- `OKTA_AGENT_B_CLIENT_ID`: its Client ID.
- `OKTA_AGENT_B_KID`: the key's Key ID.

### 3.6 Machine access for the agent: T2 may be its subject
On the agent's **Machine access** tab:
1. **Configure**:
   - Authorization server: `anyco-agent-b-as`.
   - Audience/resource URL: `api://anyco-agent-b-aud`. It must equal the server's audience.
   - **Save**.
2. **Add caller**: the AI agent `anyco-backend-agent-oai`. T2 is issued to it.

### 3.7 Resource connection to `anyco-gateway-as`, and its access policy
1. On the agent's **Resource connections** tab > **Add resource connection**: **Authorization server** `anyco-gateway-as`, scopes `pr:read` and `pr:review` only.
2. Open `anyco-gateway-as` > Access Policies > Add New Access Policy `anyco-pr-review-agent-b-oai`, assigned to the AI agent `anyco-pr-review-agent-b-oai`.
   - Rule `delegated-for-engineers`:
     - Grant type: **JWT Bearer**.
     - User is a member of group `anyco-engineers`.
     - Scopes: `pr:read`, `pr:review`.
     - Access token lifetime: 5 minutes.
   - `anyco-gateway-as` already trusts `anyco-agent-a-as` (Part 2) for Pattern A. It doesn't need to trust `anyco-agent-b-as`.
3. **Actions > Activate** the agent.

---

## Part 4 · Pattern C · Cross App Access (machine)

No user. An app (the event source) gets its own token for the agent, and the agent acts for that app.

### 4.1 App `anyco-event-source-app` (the app that fires the events)
**Create App Integration** > **API Services**, named `anyco-event-source-app`.
1. Client authentication: **Public key / Private key**.
2. **Add key**, and paste `build/jwks/anyco-event-source.json`.
3. Grant type: Client Credentials.

→ `.env`:
- `OKTA_EVENT_SOURCE_CLIENT_ID`: its Client ID.
- `OKTA_EVENT_SOURCE_KID`: the key's **KID**, as Okta shows it.

### 4.2 Authorization server `anyco-event-agent-as` (tokens for calling the agent)
**Add Authorization Server**: Name `anyco-event-agent-as`, Audience `api://anyco-event-agent-aud`.
- **Scopes**: add `agent.invoke`.
- **Access Policies** > `anyco-event-source-app`, assigned to the client `anyco-event-source-app`.
  - Rule `event-source`:
    - Grant type: **Client Credentials**.
    - Scopes: `agent.invoke`.

→ `.env`: `OKTA_EVENT_AGENT_AS_ID`.

### 4.3 Register the event AI agent
Directory > AI Agents > **Register AI agent** > **Register manually**.
1. Name `anyco-event-agent-oai`.
2. User access: turn **Allow users to access this agent** off, since nobody signs in to it.
3. On the **Client registration** tab, configure **Public/private key**, managed in Okta: **Add public key**, paste `build/jwks/anyco-event-agent.json`, **Done**, then **Activate** > **Enable**.

→ `.env`:
- `OKTA_EVENT_AGENT_CLIENT_ID`: its Client ID.
- `OKTA_EVENT_AGENT_KID`: the key's Key ID.

### 4.4 Machine access: register the agent as a resource and allow the caller
On the agent's **Machine access** tab:
1. **Configure**:
   - Authorization server: `anyco-event-agent-as`.
   - Audience/resource URL: `api://anyco-event-agent-aud`. It must equal the server's audience, and Okta doesn't let you change it later.
   - **Save**.
2. **Add caller** > **Application or service** > `anyco-event-source-app` > **Add caller**.

This is the delegation link. Okta now accepts the event source's access token (its `aud` must be `api://anyco-event-agent-aud`) as the subject of the agent's token exchange.

### 4.5 Authorization server `anyco-partner-mcp-as` (the partner's issuer)
**Add Authorization Server**: Name `anyco-partner-mcp-as`, Audience `api://anyco-partner-mcp-aud`.
- **Scopes**: add `partner:read` and `partner:write`.
- **Access Policies** > `anyco-event-agent-oai`, assigned to the AI agent `anyco-event-agent-oai`.
  - Rule `event-agent-delegated`:
    - Grant type: **JWT Bearer**.
    - Scopes: `partner:read`, `partner:write`.

→ `.env`: `OKTA_PARTNER_AS_ID`.

### 4.6 Resource connection, then activate
1. On the agent's **Resource connections** tab > **Add resource connection**: **Authorization server** `anyco-partner-mcp-as`, scope `partner:read` only.
   - `partner:write` is never allowed. The demo shows that refusal.
2. **Actions > Activate**.

---

## Record the values
```bash
.venv/bin/python okta_values.py
```
It reads the `.env` values above and checks that each authorization server answers at `https://<your-org>.okta.com/oauth2/<ID>`. Then it writes `state.json` for the AWS deploy.

A part whose values are all empty is skipped, so you can start with Pattern A only.

## Clean up
To remove the demo from your org, delete these objects. `okta_teardown.py` does the same with the Admin API (it lists them and asks first; `--users` also deletes the demo users):
1. **AI agents** (deactivate each first): `anyco-backend-agent-oai`, `anyco-pr-review-agent-b-oai` and `anyco-event-agent-oai`.
2. **Apps:** `anyco-eng-login-app`, `anyco-pr-review-agent-app`, `anyco-console-backend-app`, `anyco-event-source-app`.
3. **Authorization servers:** `anyco-users-as`, `anyco-agent-a-as`, `anyco-agent-b-as`, `anyco-gateway-as`, `anyco-event-agent-as`, `anyco-partner-mcp-as`.
4. **Group and policy:** the `anyco-engineers` group, the `anyco-demo-password` policy, and the three users, if you created them only for this demo. (`okta_teardown.py` leaves the `anyco-demo-password` policy alone, since it doesn't create it.)
