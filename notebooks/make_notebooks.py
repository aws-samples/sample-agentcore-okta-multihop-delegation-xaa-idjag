"""Writes the three notebooks in this folder (run from the repo root: .venv/bin/python notebooks/make_notebooks.py).
Edit the cells here, not in the .ipynb files, so the three stay consistent."""
import json
from pathlib import Path

HERE = Path(__file__).parent


def nb(cells):
    out = []
    for kind, src in cells:
        src = src.strip("\n")
        cell = {"cell_type": kind, "id": f"cell-{len(out) + 1}", "metadata": {}, "source": src.splitlines(keepends=True)}
        if kind == "code":
            cell.update(execution_count=None, outputs=[])
        out.append(cell)
    return {"cells": out, "metadata": {"kernelspec": {"display_name": "Python (anyco-agentid .venv)", "language": "python", "name": "anyco-agentid"},
                                       "language_info": {"name": "python"}}, "nbformat": 4, "nbformat_minor": 5}


SETUP = r'''
import asyncio, base64, hashlib, json, os, secrets, sys, time, urllib.parse, uuid
sys.path.insert(0, "..")                       # the repo root: config.py reads ../.env and ../state.json
import requests
import config as C

os.environ["AWS_REGION"] = C.REGION            # the decorator builds its own client from AWS_REGION
if C.AWS_PROFILE:
    os.environ["AWS_PROFILE"] = C.AWS_PROFILE
from bedrock_agentcore.identity.auth import requires_access_token
from bedrock_agentcore.runtime.context import BedrockAgentCoreContext
from bedrock_agentcore.services.identity import IdentityClient

E, st = C.os.environ, C.state()
ac = C.session().client("bedrock-agentcore-control")   # to create the notebook's providers
identity = IdentityClient(C.REGION)                     # to bind a JWT to the workload identity

# An older boto3 doesn't know the KMS-signed client assertion (privateKeyJwtConfig) the providers use.
_fields = ac.meta.service_model.shape_for("CustomOauth2ProviderConfigInput").members
if "privateKeyJwtConfig" not in _fields:
    import boto3
    raise RuntimeError(f"This kernel's boto3 {boto3.__version__} is too old ({sys.executable}). "
                       "Run the notebook on the repo's .venv kernel, or: pip install -r notebooks/requirements.txt")

def claims(jwt):
    return json.loads(base64.urlsafe_b64decode(jwt.split(".")[1] + "=="))

def show(name, jwt):
    """A bearer token: the raw value shortened, then the header and every claim. The signature is shown
    only as a length, so nothing printed here is a usable credential."""
    h, p, sig = jwt.split(".")
    dec = lambda x: json.loads(base64.urlsafe_b64decode(x + "=="))
    print(f"{name}  ·  {len(jwt)} chars  ·  {jwt[:16]}…{jwt[-6:]}")
    print(json.dumps({"header": dec(h), "payload": dec(p), "signature": f"<{len(sig)} chars, not shown>"}, indent=1))

def act_chain(jwt):
    """Every actor in the token, newest first."""
    out, a = [], claims(jwt).get("act")
    while isinstance(a, dict):
        out.append(f"{a['sub']} ({a.get('sub_profile', '')})"); a = a.get("act")
    return out

WORKLOAD = "anyco-notebook-workload"           # a standalone workload identity, to bind each subject token
try:
    ac.create_workload_identity(name=WORKLOAD, tags={"project": "anyco-agentid"})
except ac.exceptions.ValidationException as e:
    if "already exists" not in str(e): raise

def bind(jwt):
    """Make this JWT the subject of the next decorated call: AgentCore Identity returns a workload access
    token bound to it, and the decorators read the one in the context."""
    wat = identity.get_workload_access_token(WORKLOAD, user_token=jwt)["workloadAccessToken"]
    BedrockAgentCoreContext.set_workload_access_token(wat)

def provider(name, cfg):
    """Create or update an AgentCore Identity OAuth2 provider."""
    try:
        ac.create_oauth2_credential_provider(name=name, credentialProviderVendor="CustomOauth2",
                                             oauth2ProviderConfigInput=cfg, tags={"project": "anyco-agentid"})
    except (ac.exceptions.ConflictException, ac.exceptions.ValidationException) as e:
        if "already exists" not in str(e) and not isinstance(e, ac.exceptions.ConflictException): raise
        ac.update_oauth2_credential_provider(name=name, credentialProviderVendor="CustomOauth2", oauth2ProviderConfigInput=cfg)

ACCESS_TOKEN = "urn:ietf:params:oauth:token-type:access_token"
ID_JAG = "urn:ietf:params:oauth:token-type:id-jag"
print("ready ·", C.OKTA_DOMAIN, "·", C.REGION)
'''

SIGNIN = r'''
# Ada signs in to anyco-eng-login-app at anyco-users-as: authorization code + PKCE, with plain requests.
# (A browser would show Okta's sign-in page; here Okta's authn API gives a session token instead.)
ok = st["okta"]
s = requests.Session()
authn = s.post(f"{C.OKTA_DOMAIN}/api/v1/authn", timeout=20,
               json={"username": "ada.lovelace@example.com", "password": E["DEMO_USER_PASSWORD"]}).json()
verifier = secrets.token_urlsafe(48)
challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
r = s.get(f"{ok['users_issuer']}/v1/authorize", allow_redirects=False, timeout=20, params={
    "client_id": ok["login_client_id"], "response_type": "code", "scope": "openid profile email pr-agent.invoke",
    "redirect_uri": C.REDIRECT_URI, "state": uuid.uuid4().hex, "nonce": uuid.uuid4().hex,
    "code_challenge": challenge, "code_challenge_method": "S256", "sessionToken": authn["sessionToken"]})
code = urllib.parse.parse_qs(urllib.parse.urlparse(r.headers["Location"]).query)["code"][0]
tokens = s.post(f"{ok['users_issuer']}/v1/token", auth=(ok["login_client_id"], E["ANYCO_LOGIN_CLIENT_SECRET"]), timeout=20,
                data={"grant_type": "authorization_code", "code": code, "redirect_uri": C.REDIRECT_URI,
                      "code_verifier": verifier}).json()
t1 = tokens["access_token"]
show("T1 · Ada's sign-in token", t1)
'''

CLEANUP_COMMON = r'''
for name in NOTEBOOK_PROVIDERS:
    try:
        ac.delete_oauth2_credential_provider(name=name); print("deleted provider", name)
    except Exception as e:
        print("skip", name, str(e)[:80])
try:
    ac.delete_workload_identity(name=WORKLOAD); print("deleted workload identity", WORKLOAD)
except Exception as e:
    print("skip", WORKLOAD, str(e)[:80])
'''

# --------------------------------------------------------------------------------------------- A
A = nb([
 ("markdown", r'''
# Pattern A · On-behalf-of token exchange (RFC 8693)

An agent acts for the signed-in user. Each authorization server **trusts the one before it**, and each hop is one token exchange:

| Step | Who asks | Okta app | Gets | From | Grant |
|---|---|---|---|---|---|
| 1 | Ada (sign-in) | `anyco-eng-login-app` | T1 | `anyco-users-as` | authorization code + PKCE |
| 2 | your backend | `anyco-console-backend-app` | T2 | `anyco-agent-a-as` (trusts `anyco-users-as`) | token exchange, subject T1 |
| 3 | the agent | `anyco-pr-review-agent-app` | T3 | `anyco-gateway-as` (trusts `anyco-agent-a-as`) | token exchange, subject T2 |

No agent and no app run here. Step 1 uses `requests`; steps 2 and 3 use AgentCore Identity's `@requires_access_token` decorator, the same one the agent uses on AgentCore Runtime.

**Before you run it:** Okta is set up (`docs/okta-setup.md`), `okta_values.py` and `deploy.py` have run (they create the agent's provider, `anyco-pr-review-agent-obo`), and `.env` has `DEMO_USER_PASSWORD`. This notebook creates a workload identity (`anyco-notebook-workload`) and one provider for the backend (`anyco-notebook-backend-exchange`); the last cell removes them.
'''),
 ("code", SETUP),
 ("markdown", "## 1 · Ada signs in: T1\nT1's audience is `api://anyco-pr-agent-aud`. No agent accepts it; it stays with your backend."),
 ("code", SIGNIN),
 ("markdown", r'''
## 2 · Your backend: T1 → T2 (token exchange at `anyco-agent-a-as`)
An AgentCore Identity provider holds the backend's Okta app (client ID and secret) and points at `anyco-agent-a-as`. The decorator asks it for a token **on behalf of** the JWT bound to the workload identity: here, T1.
'''),
 ("code", r'''
BACKEND = "anyco-notebook-backend-exchange"
provider(BACKEND, {"customOauth2ProviderConfig": {
    "oauthDiscovery": {"discoveryUrl": f"{ok['agent_a_issuer']}/.well-known/openid-configuration"},
    "clientId": ok["backend_client_id"], "clientSecret": E["ANYCO_BACKEND_CLIENT_SECRET"],   # anyco-console-backend-app
    "clientAuthenticationMethod": "CLIENT_SECRET_BASIC",
    "onBehalfOfTokenExchangeConfig": {"grantType": "TOKEN_EXCHANGE",
                                      "tokenExchangeGrantTypeConfig": {"actorTokenContent": "NONE"}}}})

@requires_access_token(provider_name=BACKEND, scopes=["agent-a.invoke"], auth_flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
                       force_authentication=True,
                       custom_parameters={"audience": ok["agent_a_audience"], "subject_token_type": ACCESS_TOKEN})
async def get_t2(*, access_token):
    return access_token

bind(t1)                  # the subject of this exchange is T1
t2 = await get_t2()
show("T2 · for the agent", t2)
print("act:", act_chain(t2))
'''),
 ("markdown", r'''
## 3 · The agent: T2 → T3 (token exchange at `anyco-gateway-as`)
The same decorator the agent runs on AgentCore Runtime, with the provider `deploy.py` created for the agent's Okta app. `anyco-gateway-as` accepts T2 because it trusts `anyco-agent-a-as`.
'''),
 ("code", r'''
@requires_access_token(provider_name=C.N["obo_provider"], scopes=["pr:read", "pr:review"],
                       auth_flow="ON_BEHALF_OF_TOKEN_EXCHANGE", force_authentication=True,
                       custom_parameters={"audience": ok["gateway_audience"], "subject_token_type": ACCESS_TOKEN})
async def get_t3(*, access_token):
    return access_token

bind(t2)                  # the subject is now T2
t3 = await get_t3()
show("T3 · for the Gateway", t3)
'''),
 ("markdown", "## 4 · The trail\nOkta adds the requesting client as the outermost `act` at each exchange and keeps the earlier ones."),
 ("code", r'''
for name, tok in (("T1", t1), ("T2", t2), ("T3", t3)):
    c = claims(tok)
    print(f"{name}: iss …{c['iss'][-20:]} · aud {c['aud']} · sub {c['sub']} · cid {c['cid']}")
    for i, a in enumerate(act_chain(tok)):
        print(f"      {'act' + '.act' * i}.sub = {a}")
'''),
 ("markdown", "## 5 · Why each hop needs its own token\n`anyco-gateway-as` trusts only `anyco-agent-a-as`, so exchanging T1 there directly is refused."),
 ("code", r'''
r = requests.post(f"{ok['gateway_issuer']}/v1/token", auth=(ok["agent_client_id"], E["OKTA_AGENT_CLIENT_SECRET"]), timeout=20,
                  data={"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token": t1,
                        "subject_token_type": ACCESS_TOKEN, "audience": ok["gateway_audience"], "scope": "pr:read"})
print(r.status_code, r.json().get("error"), "·", r.json().get("error_description"))
'''),
 ("markdown", "## Clean up\nRemoves the workload identity and the provider this notebook created. The deployed demo is untouched."),
 ("code", 'NOTEBOOK_PROVIDERS = ["anyco-notebook-backend-exchange"]\n' + CLEANUP_COMMON),
])

# --------------------------------------------------------------------------------------------- B
XAA_PROVIDER = r'''
def xaa_provider(name, discovery_url, grant, client_id, kms_key_arn, kid):
    """A provider that signs its client assertion (private_key_jwt) with an AWS KMS key: no client secret."""
    obo = {"grantType": grant}
    if grant == "TOKEN_EXCHANGE":
        obo["tokenExchangeGrantTypeConfig"] = {"actorTokenContent": "NONE"}
    provider(name, {"customOauth2ProviderConfig": {
        "oauthDiscovery": {"discoveryUrl": discovery_url}, "clientId": client_id,
        "clientAuthenticationMethod": "PRIVATE_KEY_JWT",
        "privateKeyJwtConfig": {"privateKeySource": {"kmsKeySource": {"kmsKeyArn": kms_key_arn}},
                                "signingAlgorithm": "RS256", "additionalHeaderClaims": {"kid": kid}},
        "onBehalfOfTokenExchangeConfig": obo}})
'''

B = nb([
 ("markdown", r'''
# Pattern B · Cross App Access (ID-JAG) with a user

The same chain as Pattern A, but **no authorization server trusts another**. Your backend and the agent are each a registered **Okta AI agent**, and each hop is two grants: a token exchange at Okta's **org** server for an **ID-JAG**, then a **JWT bearer** grant at the target server.

| Step | Who asks | Okta app / AI agent | Gets | From | Grant |
|---|---|---|---|---|---|
| 1 | Ada (sign-in) | `anyco-eng-login-app` | T1 | `anyco-users-as` | authorization code + PKCE |
| 2a | your backend | `anyco-backend-agent-oai` | ID-JAG | Okta org server | token exchange, subject T1 |
| 2b | your backend | `anyco-backend-agent-oai` | T2 | `anyco-agent-b-as` (trusts nobody) | JWT bearer, assertion = the ID-JAG |
| 3a | the agent | `anyco-pr-review-agent-b-oai` | ID-JAG | Okta org server | token exchange, subject T2 |
| 3b | the agent | `anyco-pr-review-agent-b-oai` | T3 | `anyco-gateway-as` | JWT bearer, assertion = the ID-JAG |

Every client assertion is a `private_key_jwt` signed by an AWS KMS key: AgentCore Identity asks KMS to sign with **your** AWS credentials, which the keys' policies allow for the console operator (`kms_keys.py`).

**Before you run it:** Okta is set up (part 3 of `docs/okta-setup.md`), and `okta_values.py` and `deploy.py` have run (they create the agent's providers, `anyco-xaa-step1` and `anyco-xaa-step2`). This notebook creates a workload identity and two providers for the backend; the last cell removes them.
'''),
 ("code", SETUP),
 ("markdown", "## 1 · Ada signs in: T1"),
 ("code", SIGNIN),
 ("markdown", r'''
## 2 · Your backend: T1 → ID-JAG → T2
`anyco-agent-b-as` trusts no other server, so the backend goes through Okta: the org server issues an ID-JAG addressed to `anyco-agent-b-as` (machine access lets T1 be the subject), and `anyco-agent-b-as` redeems it.
'''),
 ("code", XAA_PROVIDER + r'''
xa = st["xaa"]
STEP1_B, STEP2_B = "anyco-notebook-backend-xaa-step1", "anyco-notebook-backend-xaa-step2"
xaa_provider(STEP1_B, f"{C.OKTA_DOMAIN}/.well-known/openid-configuration", "TOKEN_EXCHANGE",
             xa["backend_agent_client_id"], xa["backend_agent_kms_key_arn"], xa["backend_agent_kid"])
xaa_provider(STEP2_B, f"{xa['agent_b_issuer']}/.well-known/openid-configuration", "JWT_AUTHORIZATION_GRANT",
             xa["backend_agent_client_id"], xa["backend_agent_kms_key_arn"], xa["backend_agent_kid"])

@requires_access_token(provider_name=STEP1_B, scopes=["agent-b.invoke"], auth_flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
                       force_authentication=True,
                       custom_parameters={"subject_token_type": ACCESS_TOKEN, "requested_token_type": ID_JAG,
                                          "audience": xa["agent_b_issuer"]})
async def backend_id_jag(*, access_token):
    return access_token

@requires_access_token(provider_name=STEP2_B, scopes=["agent-b.invoke"], auth_flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
                       force_authentication=True)
async def backend_t2(*, access_token):
    return access_token

bind(t1);           id_jag_1 = await backend_id_jag()      # step 2a: subject T1
show("ID-JAG · for anyco-agent-b-as", id_jag_1)
bind(id_jag_1);     t2 = await backend_t2()                # step 2b: the ID-JAG is the assertion
show("T2 · for the agent", t2)
'''),
 ("markdown", r'''
## 3 · The agent: T2 → ID-JAG → T3
The agent's two providers, created by `deploy.py`, are the ones it uses on AgentCore Runtime. `anyco-gateway-as` doesn't trust `anyco-agent-b-as` either.
'''),
 ("code", r'''
SCOPES = ["pr:read", "pr:review"]

@requires_access_token(provider_name="anyco-xaa-step1", scopes=SCOPES, auth_flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
                       force_authentication=True,
                       custom_parameters={"subject_token_type": ACCESS_TOKEN, "requested_token_type": ID_JAG,
                                          "audience": st["okta"]["gateway_issuer"]})
async def agent_id_jag(*, access_token):
    return access_token

@requires_access_token(provider_name="anyco-xaa-step2", scopes=SCOPES, auth_flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
                       force_authentication=True)
async def agent_t3(*, access_token):
    return access_token

bind(t2);           id_jag_2 = await agent_id_jag()        # step 3a: subject T2
show("ID-JAG · for anyco-gateway-as", id_jag_2)
bind(id_jag_2);     t3 = await agent_t3()                  # step 3b
show("T3 · for the Gateway", t3)
'''),
 ("markdown", "## 4 · The trail\nT3 names Ada as `sub`, and every actor: the agent, your backend's AI agent, the sign-in app."),
 ("code", r'''
for name, tok in (("T1", t1), ("T2", t2), ("T3", t3)):
    c = claims(tok)
    print(f"{name}: aud {c['aud']} · sub {c['sub']} · cid {c['cid']}")
    for i, a in enumerate(act_chain(tok)):
        print(f"      {'act' + '.act' * i}.sub = {a}")
'''),
 ("markdown", "## 5 · No trust between servers\nA plain token exchange of T1 at `anyco-agent-b-as` is refused: it trusts no other authorization server."),
 ("code", r'''
r = requests.post(f"{xa['agent_b_issuer']}/v1/token", auth=(st["okta"]["backend_client_id"], E["ANYCO_BACKEND_CLIENT_SECRET"]), timeout=20,
                  data={"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token": t1,
                        "subject_token_type": ACCESS_TOKEN, "audience": xa["agent_b_audience"], "scope": "agent-b.invoke"})
print(r.status_code, r.json().get("error"), "·", r.json().get("error_description"))
'''),
 ("markdown", "## Clean up\nRemoves the workload identity and the two providers this notebook created. The deployed demo is untouched."),
 ("code", 'NOTEBOOK_PROVIDERS = ["anyco-notebook-backend-xaa-step1", "anyco-notebook-backend-xaa-step2"]\n' + CLEANUP_COMMON),
])

# --------------------------------------------------------------------------------------------- C
C_NB = nb([
 ("markdown", r'''
# Pattern C · Cross App Access, machine to machine

There's no person. An app (the event source) gets its own token, and the event agent acts **for that app**: the partner's token names the app as `sub` and the agent as `act`.

| Step | Who asks | Okta app / AI agent | Gets | From | Grant |
|---|---|---|---|---|---|
| 1 | the event source | `anyco-event-source-app` | T1 | `anyco-event-agent-as` | client credentials, `private_key_jwt` (KMS) |
| 2a | the event agent | `anyco-event-agent-oai` | ID-JAG | Okta org server | token exchange, subject T1 (machine access) |
| 2b | the event agent | `anyco-event-agent-oai` | partner token | `anyco-partner-mcp-as` | JWT bearer, assertion = the ID-JAG |

Step 1 is plain `requests` (in the demo, the trigger Lambda does it). Step 2 uses the event agent's `@requires_access_token` decorators and its providers from `deploy.py` (`anyco-event-step1`, `anyco-event-step2`).

**Signing keys:** both clients sign with AWS KMS keys whose policies allow only their own roles (the trigger Lambda, the event agent). To run this notebook as yourself, the next cell lets the console operator sign with those two keys too; the last cell puts the policies back.
'''),
 ("code", SETUP),
 ("markdown", "## 0 · Let your AWS identity sign with the two Pattern C keys (for this notebook only)"),
 ("code", r'''
import kms_keys
for line in kms_keys.apply_policies(operator_test=True):
    print(line)
time.sleep(10)            # key policy changes take a few seconds to apply
'''),
 ("markdown", r'''
## 1 · The event source: T1 by client credentials
The client assertion is a short JWT (`iss` = `sub` = the event source, `aud` = the token URL) that the event source signs with its KMS key. It proves who is asking; **T1 itself comes from Okta**.
'''),
 ("code", r'''
ev = st["event"]
b64 = lambda raw: base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
token_url = f"{ev['agent_issuer']}/v1/token"
now = int(time.time())
head = b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": ev["source_kid"]}).encode())
body = b64(json.dumps({"iss": ev["source_client_id"], "sub": ev["source_client_id"], "aud": token_url,
                       "iat": now, "exp": now + 300, "jti": str(uuid.uuid4())}).encode())
sig = C.session().client("kms").sign(KeyId=ev["source_kms_key_arn"], Message=hashlib.sha256(f"{head}.{body}".encode()).digest(),
                                     MessageType="DIGEST", SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256")["Signature"]
client_assertion = f"{head}.{body}.{b64(sig)}"

r = requests.post(token_url, timeout=20, data={
    "grant_type": "client_credentials", "scope": "agent.invoke", "resource": ev["agent_audience"],
    "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer", "client_assertion": client_assertion})
t1 = r.json()["access_token"]
show("T1 · the event source's own token", t1)
'''),
 ("markdown", r'''
## 2 · The event agent: T1 → ID-JAG → partner token
Machine access lets T1 be the subject: the event source is an allowed caller of `anyco-event-agent-oai`, and T1's audience is the agent's resource URL. The resource connection grants `partner:read` only.
'''),
 ("code", r'''
@requires_access_token(provider_name="anyco-event-step1", scopes=["partner:read"], auth_flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
                       force_authentication=True,
                       custom_parameters={"subject_token_type": ACCESS_TOKEN, "requested_token_type": ID_JAG,
                                          "audience": ev["mcp_issuer"]})
async def event_id_jag(*, access_token):
    return access_token

@requires_access_token(provider_name="anyco-event-step2", scopes=["partner:read"], auth_flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
                       force_authentication=True)
async def partner_token(*, access_token):
    return access_token

bind(t1);       id_jag = await event_id_jag()           # step 2a: subject T1
show("ID-JAG · for anyco-partner-mcp-as", id_jag)
bind(id_jag);   t3 = await partner_token()              # step 2b
show("Partner token · for the partner MCP server", t3)
'''),
 ("markdown", "## 3 · The trail\nNo user anywhere: `sub` is the event source, and `act` is the event agent acting for it."),
 ("code", r'''
for name, tok in (("T1", t1), ("partner token", t3)):
    c = claims(tok)
    print(f"{name}: aud {c['aud']} · sub {c['sub']} · cid {c['cid']} · scp {c.get('scp')}")
    for i, a in enumerate(act_chain(tok)):
        print(f"      {'act' + '.act' * i}.sub = {a}")
'''),
 ("markdown", "## 4 · Okta limits what's granted\nThe resource connection allows `partner:read` only, so asking for `partner:write` is refused at step 2a. Okta answers `invalid_scope`; AgentCore Identity reports it as a failed token exchange (HTTP 400)."),
 ("code", r'''
@requires_access_token(provider_name="anyco-event-step1", scopes=["partner:write"], auth_flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
                       force_authentication=True,
                       custom_parameters={"subject_token_type": ACCESS_TOKEN, "requested_token_type": ID_JAG,
                                          "audience": ev["mcp_issuer"]})
async def event_id_jag_write(*, access_token):
    return access_token

bind(t1)
try:
    await event_id_jag_write()
except Exception as e:
    print("refused:", str(e)[:300])
'''),
 ("markdown", "## Clean up\nPuts the two keys back to one signer each, and removes the workload identity. The deployed demo is untouched."),
 ("code", r'''
for line in kms_keys.apply_policies():
    print(line)
NOTEBOOK_PROVIDERS = []
''' + CLEANUP_COMMON),
])

for name, book in (("pattern-a-token-exchange.ipynb", A), ("pattern-b-cross-app-access.ipynb", B),
                   ("pattern-c-machine-to-machine.ipynb", C_NB)):
    (HERE / name).write_text(json.dumps(book, indent=1) + "\n")
    print("wrote", name)
