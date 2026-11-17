# Agent Identity POC: an agent acting for someone else, with Amazon Bedrock AgentCore and Okta

A Strands agent on AgentCore Runtime acts for someone else, with Okta as the identity provider. There are three patterns:

- **Pattern A · OBO/Delegation (token exchange):** two one-step RFC 8693 exchanges. Your backend exchanges the engineer's sign-in token for the agent's audience; the agent exchanges that for the Gateway's. The token at each hop names the engineer (`sub`) and every actor so far (`act`).
- **Pattern B · Cross App Access (user):** the same chain, but no authorization server trusts another. Your backend and the agent are each a registered Okta AI agent, and each gets its next token with an ID-JAG (token exchange at the org server, then a jwt-bearer grant). It is built to cross trust domains; here every server happens to be in one Okta org.
- **Pattern C · Cross App Access (machine):** there's no user. An event wakes the agent, and it acts for the app that fired the event (Okta machine access), with the same two XAA grants as Pattern B.

> **This is a demo, not for production use.** It shows how the identity patterns work. It isn't hardened, load-tested or supported; run it only in a non-production AWS account and a demo Okta org, with demo users and no real data.

A local console (http://localhost:8010) explains each pattern, runs it live, and shows the real request, response and JWT at every hop. JWT signatures are never shown.

## What you need

| | |
|---|---|
| **AWS account** | A region with AgentCore Runtime, Gateway, Identity and Policy (the default is `us-west-2`), and Amazon Bedrock access to Claude Sonnet 4.6 (`us.anthropic.claude-sonnet-4-6`; set `ANYCO_MODEL_ID` to change it). The deploy creates IAM roles, Lambda, DynamoDB, S3, SNS, KMS and AgentCore resources, so use credentials that may create those, in a non-production account. |
| **Okta org** | **API Access Management** (custom authorization servers) for Pattern A. **Okta for AI Agents** (beta) for Patterns B and C. An admin who can manage users, groups, apps, authorization servers and AI agents (and, for `okta_setup.py`, create an API token). |
| **Your machine** | Python 3.12 or later, an AWS CLI profile or credentials for the account, and Google Chrome (only for the optional browser checks in `scripts/`; they drive your installed Chrome). |

## Set up

Okta and AWS are set up, and removed, by separate scripts. Nothing in AWS touches Okta, and nothing in Okta touches AWS.

| Step | Okta | AWS |
|---|---|---|
| Set up | by hand ([docs/okta-setup.md](docs/okta-setup.md)), or `okta_setup.py` | `kms_keys.py`, then `deploy.py` |
| Remove | by hand (the doc's **Clean up**), or `okta_teardown.py` | `teardown.py` |

### 1. Install and configure
```bash
git clone <this repo> && cd AgentCoreOktaMultiHopDelegationXaaIdJag
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cp .env.example .env
```
Fill in the first block of `.env`:
- `ANYCO_OKTA_DOMAIN`, for example `https://your-org.okta.com`
- `ANYCO_AWS_PROFILE` and `ANYCO_AWS_REGION`
- `DEMO_USER_PASSWORD`: the demo users' password. The test scripts use it, and `okta_setup.py` gives it to the users it creates.

### 2. Create the signing keys (AWS KMS)
```bash
.venv/bin/python kms_keys.py
```
This creates four asymmetric KMS keys, one per Okta client that signs with `private_key_jwt`: the three AI agents and the event source app. It prints their public JWKs and saves them in `build/jwks/`. The private keys never leave KMS. AgentCore Identity, the trigger Lambda and the console ask KMS to sign each client assertion.

Whoever may call `kms:Sign` with a key can act as that Okta client, so each key gets its own key policy:
- only its Runtime or Lambda role may sign;
- the console operator (the AWS identity in `ANYCO_AWS_PROFILE`) may sign for your backend and for the Pattern B agent (Scenario A1, the test scripts);
- the account keeps an administration statement without `kms:Sign`, as the recovery path.

The role grants are added by `deploy.py`, once the roles exist. `kms_keys.py --operator-test` also lets the operator sign with the two Pattern C keys, for `scripts/event_test.py`.

### 3. Set up Okta (pick one)

**By hand:** follow [docs/okta-setup.md](docs/okta-setup.md) in the Okta Admin Console.
1. Users, group and sign-in.
2. Pattern A: three apps (web sign-in, your backend, the agent) and three authorization servers, chained by trusted servers.
3. Pattern B: two AI agents (your backend and the agent), each with machine access, a resource connection and a JWT Bearer rule, and an authorization server that trusts no other.
4. Pattern C: a service app, an AI agent with machine access, and two authorization servers.

Copy the IDs it lists into the second block of `.env`. You can stop after part 2 and run Pattern A alone.

**Automatically:** `okta_setup.py` does the same steps with the Okta Admin API, if you give it an API token of an Okta admin.
1. Create the token in the Admin Console: Security > API > Tokens > **Create token**.
2. Add it to `.env` as `OKTA_API_TOKEN=...`.
3. Run:
```bash
.venv/bin/python okta_setup.py --check   # read-only: which demo objects exist, which are missing
.venv/bin/python okta_setup.py           # create what's missing (safe to re-run), and write the IDs into .env
```
It creates the objects with the names in the doc and writes every ID into `.env`. It also writes the client secrets of the apps it creates. It doesn't create the optional password-only sign-in policy (doc part 1.3), which depends on your org's session policies; without it, the demo users sign in with MFA. When you're done, remove `OKTA_API_TOKEN` from `.env` and revoke the token.

### 4. Record the Okta values
```bash
.venv/bin/python okta_values.py
```
This checks that each authorization server answers at its issuer URL, then writes `state.json` for the deploy. It uses no Okta API token.

### 5. Deploy to AWS
```bash
.venv/bin/python deploy.py
```
One command, about 10 minutes, and safe to re-run. It packages the agents for AgentCore Runtime (linux/arm64, Python 3.13; pip downloads the wheels, no Docker), then deploys in order:
1. the shared base: the DynamoDB table, the tool and interceptor Lambdas, the policy engine and the code bucket;
2. Pattern A: the Gateway, its token-exchange provider, Runtime A and its Cedar permits;
3. Pattern B: two AgentCore Identity providers, a workload identity, Runtime B and its Cedar permits;
4. Pattern C: the partner MCP Runtime, the event agent Runtime, their providers, the SNS topic and the trigger Lambda.

A pattern whose Okta values are missing is skipped. Use `--skip-build` to reuse the packages from the last run.

### 6. Run the console
```bash
./run.sh            # http://localhost:8010, bound to 127.0.0.1 only
./run.sh --restart  # stop the one already running, then start
```

Pick a screen from the menu under the **AC** logo (top left). The console only reads and runs; it never creates or deletes AWS or Okta resources.

| Screen | What to do |
|---|---|
| **1 · The three patterns** | The overview: what each pattern solves for and shows, with buttons to its concept and live screens. The console opens here. |
| **2 · Pattern A · OBO/Delegation** | The architecture. Click any block for its key points. |
| **3 · Live: token exchange** | Sign in as Ada. Use the chips to post a review, then list reviews. Sign out, sign in as Alan, and list: he sees only his own. **Scenario A1** (same screen) tries the agent's exchange with the Okta AI agent as the client; Okta refuses it. |
| **4 · Where A stops** | One slide: the four cases Pattern A can't handle, and how Pattern B (and C) covers each. |
| **5 · Pattern B · XAA (user)** | The same chain as Pattern A, with Cross App Access at both hops: your backend (T1 → ID-JAG → T2) and the agent (T2 → ID-JAG → T3). |
| **6 · Live: XAA user** | Sign in as Ada and post. Click each token chip to trace T1 → T2 → ID-JAG → T3; T3's `act` reads agent → backend agent → `anyco-eng-login-app`. A merge request is refused. |
| **7 · Where B stops** | One slide: the three cases Pattern B can't handle (no person, work after they're gone, a system is accountable), and how Pattern C covers each. |
| **8 · Pattern C · XAA (machine)** | The event flow. Click a block for its key points; the agent's block has its code. |
| **9 · Live: XAA event** | No sign-in. Pick `pr.opened` or `pr.approved` and click **Publish to SNS**. Click a token chip (T1, ID-JAG, partner token) to see it. |

Every token drawer shows the whole token (the signature only as a length) and a **Who is who** table that names the Okta object behind `iss`, `aud`, `sub`, `cid` and each `act`. Grace (not an engineer) can sign in but can't call the agent.

### Test scripts
```bash
.venv/bin/python scripts/headless_login.py ada.lovelace@example.com   # sign in without a browser (password-only policy); saves T1
.venv/bin/python scripts/xaa_test.py                                  # Pattern B's two XAA hops straight against Okta (after headless_login)
.venv/bin/python scripts/event_test.py                                # Pattern C's token chain straight against Okta
RUNTIME=b .venv/bin/python scripts/invoke_agui.py                     # Pattern A's Runtime without the console (RUNTIME=c: Pattern B)
.venv/bin/python scripts/ui_check_b2.py                               # Pattern A end to end in Chrome
.venv/bin/python scripts/ui_check_c.py                                # Pattern B end to end in Chrome
.venv/bin/python scripts/ui_check_e.py                                # Pattern C end to end in Chrome (publishes one event)
.venv/bin/python scripts/reset_demo.py                                # clear posted reviews and traces
.venv/bin/python scripts/kms_sign_check.py                            # who may sign with each KMS key; tries kms:Sign as the console operator
.venv/bin/python scripts/console_csrf_check.py                        # requests from another localhost port, without the CSRF token, or with a foreign Host are refused
```

### Notebooks: each pattern's token flow, step by step
No agent and no app: [notebooks/](notebooks/) runs each pattern's token flow from Python.
- **Sign-in:** `requests` signs Ada in (authorization code + PKCE). Pattern C has no user and gets T1 by client credentials.
- **The next tokens:** AgentCore Identity's `@requires_access_token` decorator gets them, the same one the agents use on AgentCore Runtime.
- **What's shown:** every bearer token, as header and claims, and each `act` chain.
- **One refusal per pattern:** a direct exchange that no server trusts, or a scope Okta never grants.
- **Reference:** [docs/token-flows.md](docs/token-flows.md) shows each kind of request the notebooks make, with its parameters and response.

```bash
.venv/bin/pip install -r notebooks/requirements.txt
.venv/bin/python -m ipykernel install --user --name anyco-agentid --display-name "Python (anyco-agentid .venv)"
.venv/bin/jupyter lab notebooks/
```

Pick the **Python (anyco-agentid .venv)** kernel, in JupyterLab or VS Code. Another Python's boto3 may be too old for the KMS-signed client assertion; the first cell checks for that and names the Python the kernel is running.

| Notebook | Shows |
|---|---|
| `pattern-a-token-exchange.ipynb` | T1 → T2 (your backend) → T3 (the agent), two RFC 8693 exchanges |
| `pattern-b-cross-app-access.ipynb` | T1 → ID-JAG → T2 → ID-JAG → T3: both hops through Okta's org server, with no trust between servers |
| `pattern-c-machine-to-machine.ipynb` | T1 by client credentials (no user) → ID-JAG → the partner token |

**Before you run them:** run `deploy.py` first; the notebooks reuse the agents' AgentCore Identity providers.

**What they create and change:**
- Each notebook creates a workload identity, `anyco-notebook-workload`.
- Pattern A creates one provider for your backend, and Pattern B two.
- Each notebook's last cell removes what it created.
- AgentCore Identity signs with **your** AWS identity. The key policies already let the console operator sign for your backend and the Pattern B agent.
- Pattern C's notebook lets you sign with the two Pattern C keys while it runs (`kms_keys.apply_policies(operator_test=True)`), and puts the policies back in its last cell.
- Outputs hold real token claims: don't commit an executed notebook.

## Clean up

**AWS**

| Goal | Command |
|---|---|
| Remove the pattern resources, keep the shared base (quick redeploy) | `.venv/bin/python teardown.py --patterns` |
| Remove the demo from AWS | `.venv/bin/python teardown.py` |
| Also schedule the KMS keys for deletion (7-day recovery window) | `.venv/bin/python teardown.py --keys` |
| Fresh AWS deploy, same Okta | `teardown.py`, then `deploy.py` |

Without `--keys` the KMS keys stay, so the public keys registered in Okta stay valid for a redeploy. Everything in AWS is tagged `project=anyco-agentid`. Idle Runtimes, Lambdas and the table cost little, but remove them when you're done.

**Okta**

| Goal | Command |
|---|---|
| Remove the demo's Okta objects | `.venv/bin/python okta_teardown.py` (needs `OKTA_API_TOKEN`; lists what it will delete and asks first), or by hand from the doc's **Clean up** |
| Also remove the three demo users | `.venv/bin/python okta_teardown.py --users` |

To start over completely, clean up both, delete `state.json`, then repeat steps 2 to 5.

`.env` (your org and secrets) and `state.json` (the IDs of what you created) are git-ignored. So is `build/` (packages, JWKs, deploy logs, captured calls, test tokens).

### Data the demo keeps

| Where | What | How long | Remove it |
|---|---|---|---|
| DynamoDB table `anyco-agentid-records` | posted reviews (review text, author, acting agent, actor chain), the Gateway interceptor's record of each tool call (tool arguments, token claims, the Cedar outcome), and each Pattern C event run (token claims, tool calls, answer). No tokens: claims only. | Each record expires about a day after it's written (DynamoDB TTL on `ttl`). TTL deletion is asynchronous, usually within a few days of expiry, so it isn't an exact 24-hour guarantee. | `scripts/reset_demo.py` deletes them all now; `teardown.py` deletes the table |
| `build/` on your machine | the last captured call and tokens shown in the console (`last_*.json`, as header and claims only), the test sign-in token (`build/.user_token`, a real bearer token), deploy logs, packages | until you delete them | `rm -rf build/` (`deploy.py` rebuilds what it needs) |
| CloudWatch Logs | Lambda and Runtime logs | the log groups' retention | `teardown.py` |

---

## How each pattern works

The OAuth requests behind these patterns (what each one takes in and gives back) are drawn in [docs/token-flows.md](docs/token-flows.md).

### Pattern A · OBO/Delegation (token exchange: backend, then agent)

```
Engineer ──signs in (anyco-eng-login-app, web app)──▶ anyco-users-as → T1 (aud api://anyco-pr-agent-aud). T1 stays in your backend.
Your backend (service app anyco-console-backend-app) ──token exchange, subject T1──▶ anyco-agent-a-as (trusts anyco-users-as)
     → T2: sub = engineer, aud = api://anyco-agent-a-aud, cid = backend, act = backend → anyco-eng-login-app
     ──Bearer T2──▶ Runtime A (accepts only anyco-agent-a-as tokens with cid = the backend)
         └─ AgentCore Identity, as anyco-pr-review-agent-app ──token exchange, subject T2──▶ anyco-gateway-as (trusts anyco-agent-a-as)
            → T3: sub = engineer, aud = api://anyco-gateway-aud, cid = agent, act = agent → backend → anyco-eng-login-app
         ──Bearer T3──▶ the Gateway (CUSTOM_JWT) → interceptor (caller.user) → Cedar (backend in act) → tools act as the engineer
```

- **Each hop gets a token for its own audience.** No agent accepts the sign-in token: Runtime A refuses T1 (*"Claim 'iss' value mismatch"*). `anyco-gateway-as` refuses to exchange T1 directly, because it trusts only `anyco-agent-a-as` (*"The 'subject_token' issuer isn't a trusted authorization server"*).
- **The trail grows at each exchange.** Okta adds the requesting client as the outermost `act` and nests the earlier ones, up to five. The Gateway sees agent → backend → the web app Ada signed in to.
- **Both exchanges are made by service apps.** Okta's on-behalf-of exchange refuses a web app as the requester ("web app to web app isn't supported"), so the backend uses its own service app, not the web app it signs users in with.
- **One step each, no actor token.** This is Okta's documented on-behalf-of exchange: Okta takes the actor from the client that authenticates, not from an RFC 8693 `actor_token`. Okta's custom authorization server rejects an `actor_token` (`'subject_token' is invalid`, or `'actor_token_type' is invalid or not supported`).
- **Scenario A1 · can an Okta AI agent do the agent's exchange itself?** No. With T2 as the subject and the AI agent as the client (`private_key_jwt`, its KMS key), Okta answers `403 access_denied`: *The Token Exchange flow from service app to web app isn't supported.* (With Ada's sign-in token as the subject it says "web app to web app": the message names the subject token's client type, then the requester's.) Okta treats the AI agent as a web app, with or without a linked sign-in app. Okta's on-behalf-of exchange takes a service app as the client; an AI agent acts for a user through Cross App Access (Pattern B).
- **How it differs from Cross App Access:** there the actor in `act` is the registered Okta AI agent, and the token comes from two grants; here it's the agent's regular Okta app, in one exchange.
- **Cedar permits:** `cid` = the agent's Okta app, AND the backend in `act` (the call came through your backend), AND `uid` present, AND the tool's scope.
- **Switching users:** "Sign out / switch user" also ends the Okta session (`/logout`), so you can switch Ada ↔ Alan in one browser.

### Pattern B · Cross App Access with a user (ID-JAG at both hops, Okta for AI Agents)

```
Engineer ──signs in (anyco-eng-login-app, web app)──▶ anyco-users-as → T1 (aud api://anyco-pr-agent-aud). T1 stays in your backend.
Your backend = Okta AI agent anyco-backend-agent-oai (private_key_jwt, its KMS key)
     step 1  org AS: token exchange, subject T1 → ID-JAG for anyco-agent-b-as   (machine access: link anyco-eng-login-app → backend agent)
     step 2  anyco-agent-b-as: jwt-bearer ID-JAG → T2   (anyco-agent-b-as trusts no other server)
     → T2: sub = engineer, aud = api://anyco-agent-b-aud, cid = backend agent, act = backend agent → anyco-eng-login-app
     ──Bearer T2──▶ Runtime B (accepts only anyco-agent-b-as tokens with cid = the backend agent)
         └─ AgentCore Identity, as the Okta AI agent anyco-pr-review-agent-b-oai (its KMS key)
            step 1  org AS: token exchange, subject T2 → ID-JAG for anyco-gateway-as   (machine access: link backend agent → agent)
            step 2  anyco-gateway-as: jwt-bearer ID-JAG → T3
            → T3: sub = engineer, aud = api://anyco-gateway-aud, cid = agent, act = agent → backend agent → anyco-eng-login-app
         ──Bearer T3──▶ the Gateway (shared) → interceptor (caller.user + acting_agent + act_chain) → Cedar → tools
```

- **No authorization server trusts another.** `anyco-agent-b-as` has no trusted servers, so a plain token exchange of T1 there is refused (*"The 'subject_token' issuer isn't a trusted authorization server"*). `anyco-gateway-as` doesn't trust `anyco-agent-b-as` either. Each hop gets in only with an ID-JAG signed by the IdP.
- **Both clients are Okta AI agents.** Only an AI agent may request an ID-JAG, so your backend is registered as one too (`anyco-backend-agent-oai`). Okta names each in `act` with `sub_profile` `ai_agent`.
- **Machine access makes the subject token acceptable.** Each AI agent's delegation link names the client whose token it may use as a subject, and that token's `aud` must equal the agent's resource URL: T1 (`api://anyco-pr-agent-aud`) for the backend agent, T2 (`api://anyco-agent-b-aud`) for the agent.
- **Resource connections decide where each may go:** the backend agent → `anyco-agent-b-as` (`agent-b.invoke`); the agent → `anyco-gateway-as` (`pr:read pr:review`). A JWT Bearer rule on each server allows `anyco-engineers` only.
- **Credential providers** (AgentCore Identity), both `PRIVATE_KEY_JWT` with the agent's KMS key and no client secret:
  - `anyco-xaa-step1`: Okta org authorization server, `TOKEN_EXCHANGE`, `subject_token_type=access_token`, `requested_token_type=id-jag`.
  - `anyco-xaa-step2`: `anyco-gateway-as`, `JWT_AUTHORIZATION_GRANT`.
- **Workload identity:** step 1's subject is T2, which the Runtime binds itself. A standalone `anyco-pr-agent-xaa-delegate` binds the ID-JAG for step 2; the Runtime's own workload identity refuses `GetWorkloadAccessTokenForJWT` from code.
- **KMS permission:** AgentCore Identity signs the assertion with the caller's credentials, so Runtime B's role needs `kms:Sign` on the key. The console signs the backend agent's assertions with your AWS profile.
- **Inbound authorizer:** the Runtime's `allowedClients` checks `client_id`, but Okta access tokens carry `cid`, so a `customClaims` rule on `cid` is used instead.
- **Cedar permits:** `cid` = the agent, AND `act` names the agent AND the backend agent, AND `uid`, AND the scope. A Pattern A token names other clients, so neither pattern's token matches the other's permits.
- **Audit trail:** `post_review` records `author` (the engineer), `acting_agent` and the whole `act_chain`.
- **Across two Okta orgs:** the demo keeps Pattern B in one org. [docs/cross-org-xaa.md](docs/cross-org-xaa.md) shows how to move its second hop into a second org (an Org2Org app with Cross App Access in Org A, an identity provider for Org A in Org B), and what changes in AWS.

### Pattern C · Cross App Access machine-to-machine (event-triggered, Okta machine access)

No user. An event wakes the agent, and the agent acts for the app that fired it. It reaches a partner MCP server protected by another authorization server, so it needs Cross App Access. It calls that server directly; there's no Gateway in this pattern.

```
SNS anyco-pr-events ──▶ trigger Lambda = the event source (Okta service app, private_key_jwt with its own KMS key)
     T1: client credentials at anyco-event-agent-as, resource = the agent's URL   (sub = event source, aud = the agent)
     ──InvokeAgentRuntime, Authorization: Bearer T1, {event}──▶ event agent (Runtime; no Okta code, no key)
         Runtime JWT authorizer: issuer anyco-event-agent-as, aud = the agent, cid = the event source, agent.invoke
         step 1  GetResourceOauth2Token(anyco-event-step1)   (the Runtime already bound T1 to the agent)
                 → AgentCore Identity → Okta org AS: token-exchange T1 (access_token) → ID-JAG
         step 2  bind(ID-JAG) + GetResourceOauth2Token(anyco-event-step2)
                 → AgentCore Identity → anyco-partner-mcp-as: jwt-bearer ID-JAG → partner token
                   (sub = event source, act.sub = the agent, cid = the agent, aud api://anyco-partner-mcp-aud)
     ──Bearer partner token──▶ partner MCP server (Runtime, MCP; inbound only anyco-partner-mcp-as tokens, cid = the agent)
         each tool checks act.sub = the agent and its scope
```

- **What makes machine access work:** the agent is registered as a resource (its resource URL, set once), and the event source is allowed as a caller. Together these are the delegation link. Okta accepts T1 as a subject only if T1's `aud` equals that resource URL.
- **The token keeps the chain:** `sub` = the event source, `act.sub` = the agent, and the nested `act` = the event source.
- **Refusals the demo shows:**
  - `record_compliance_result` needs `partner:write`. The resource connection never allows it (Okta answers `invalid_scope`), and the partner tool refuses the call.
  - An ID-JAG sent to the partner MCP server gets 401 (wrong issuer).
  - An ID-JAG passed as T1 is refused by the agent.

## Files

| File | What |
|---|---|
| `kms_keys.py` | The four KMS signing keys; prints the public JWKs for Okta |
| `docs/okta-setup.md` | The Okta setup, step by step in the Admin Console |
| `docs/cross-org-xaa.md` | How Pattern B's second hop would cross into a second Okta org |
| `docs/token-flows.md` | Each kind of OAuth token request, drawn: parameters in, response out, what the server checks; and how the AgentCore Identity decorator fills them in (`docs/images/make_token_flows.py` draws the diagrams) |
| `okta_setup.py`, `okta_teardown.py` | Optional: the same Okta setup and clean-up through the Okta Admin API (needs `OKTA_API_TOKEN`) |
| `okta_values.py` | Reads the Okta IDs from `.env`, checks them, writes `state.json` |
| `deploy.py` | Packages and deploys everything in order |
| `teardown.py` | Removes the AWS side (`--patterns`: keep the shared base; `--keys`: the KMS keys too) |
| `stack.py` | Shared base: table, tool + interceptor Lambdas, policy engine, Gateway service role, code bucket |
| `stack_a.py` | Pattern A: the Gateway, token-exchange provider, Runtime A, Cedar A |
| `stack_b.py` | Pattern B: AgentCore Identity providers + workload identity, Runtime B, Cedar B |
| `stack_c.py` | Pattern C: partner MCP Runtime, event agent Runtime, providers, SNS + trigger Lambda |
| `deploy_aws.py`, `release.py` | Shared helpers: IAM roles, Lambda packaging, waiters, tool schemas, Cedar sync |
| `agent/main.py` | The Strands agent (Runtimes A and B), streaming AG-UI events to the console; `AGENT_MODE=obo` or `xaa` |
| `agent_event/main.py` | The event agent (Strands), with the trace the console shows |
| `mcp_partner/server.py` | The partner MCP server |
| `lambdas/` | `tools.py` (mock GitHub + context), `interceptor.py` (stamps `caller` from the verified token), `event_trigger.py` (SNS → T1 → the agent) |
| `okta_event.py` | KMS-signed `private_key_jwt` assertions and token calls for the console and test scripts (your backend's XAA in Pattern B, Scenario A1, the Pattern C test); the agents don't use it |
| `server/app.py`, `web/index.html`, `run.sh` | The console (read and run only) |
| `scripts/` | Test scripts: sign-in, token chains against Okta, Runtime calls, Chrome checks, reset |
| `notebooks/` | The three token flows, step by step in Python (`make_notebooks.py` writes them) |
| `build_agent.sh`, `build_event.sh` | Package the agents for AgentCore Runtime (linux/arm64, Python 3.13) |

## Limits to say out loud

- The `X-Agent-Run` header the agent sends to the Gateway only ties tool calls to a run: the bearer token proves who is calling, and Cedar decides on its claims.
- Okta's org authorization server can't do this sign-in setup. Custom authorization servers (API Access Management) are required.
- Okta for AI Agents is in beta. Its console and APIs can change.
- The console is a local demo tool, not a production security boundary:
  - it binds to 127.0.0.1 and keeps sessions in memory;
  - it accepts only `localhost:8010` and `127.0.0.1:8010` as the Host;
  - every POST must come from its own origin, as JSON, with the session's CSRF token.
- The bearer tokens the console and test scripts hold (in memory and in `build/`) are real Okta tokens for the demo users. Use demo users and a demo org only.
- The tool Lambdas trust the `caller` the Gateway's interceptor stamps from the verified token. They refuse a call without one, but who may invoke them at all is decided by IAM: only the Gateway's service role is granted `lambda:InvokeFunction` on them. Keep it that way.
- Only the console operator may publish to the SNS topic `anyco-pr-events`. The event agent acts for the configured event source (`anyco-event-source-app`), not for whoever published the message.
- The Gateway's policy engine is in ENFORCE mode from the moment it's created, so tools are denied by default until their Cedar permits exist.

## License

This sample is licensed under the MIT-0 License; see [LICENSE](LICENSE). The two front-end libraries in `web/vendor/` keep their own licenses (Tailwind CSS, MIT; Lucide, ISC); see [web/vendor/README.md](web/vendor/README.md).
