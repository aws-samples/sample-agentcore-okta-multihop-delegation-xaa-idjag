"""Test helper: Pattern B's two Cross App Access hops straight against Okta (no AWS but KMS).
Run scripts/headless_login.py first (it saves T1). Prints decoded claims only, never a token.
  hop 1  your backend, AI agent anyco-backend-agent-oai:  T1 -> ID-JAG (org server) -> T2 (anyco-agent-b-as)
  hop 2  the agent, AI agent anyco-pr-review-agent-b-oai: T2 -> ID-JAG (org server) -> T3 (anyco-gateway-as)
It also shows that anyco-agent-b-as refuses a plain token exchange of T1 (it trusts no other server).
Usage: python scripts/xaa_test.py"""
import base64, json, os, sys
import requests
sys.path.insert(0, os.path.abspath("."))
import config as C
if C.AWS_PROFILE:
    os.environ["AWS_PROFILE"] = C.AWS_PROFILE
import okta_event as E

st = C.state(); ok, xa = st["okta"], st["xaa"]
EX, AT = "urn:ietf:params:oauth:grant-type:token-exchange", "urn:ietf:params:oauth:token-type:access_token"
CA = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
ORG = f"{C.OKTA_DOMAIN}/oauth2/v1/token"
claims = lambda t: json.loads(base64.urlsafe_b64decode(t.split(".")[1] + "=="))
show = lambda label, t: print(f"\n{label}\n" + json.dumps({k: v for k, v in claims(t).items() if k not in ("jti", "iat", "exp", "ver")}, indent=1))


def post(url, data, label):
    r = requests.post(url, data=data, timeout=20)
    if r.status_code >= 400:
        sys.exit(f"{label} refused: {r.status_code} {r.json().get('error_description')}")
    return r.json()["access_token"]


def xaa(subject, client, key, kid, target_issuer, scope, who):
    jag = post(ORG, {"grant_type": EX, "subject_token": subject, "subject_token_type": AT,
                     "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag", "audience": target_issuer,
                     "scope": scope, "client_id": client, "client_assertion_type": CA,
                     "client_assertion": E.assertion(client, key, kid, ORG)}, f"{who} step 1")
    url = f"{target_issuer}/v1/token"
    tok = post(url, {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": jag, "client_id": client,
                     "client_assertion_type": CA, "client_assertion": E.assertion(client, key, kid, url)}, f"{who} step 2")
    return jag, tok


t1 = (C.ROOT / "build" / ".user_token").read_text().strip()
show("T1 · the sign-in token", t1)
r = requests.post(f"{xa['agent_b_issuer']}/v1/token", timeout=20,
                  auth=(ok["backend_client_id"], os.environ["ANYCO_BACKEND_CLIENT_SECRET"]),
                  data={"grant_type": EX, "subject_token": t1, "subject_token_type": AT,
                        "audience": xa["agent_b_audience"], "scope": "agent-b.invoke"})
print(f"\nplain token exchange of T1 at anyco-agent-b-as: {r.status_code} {r.json().get('error_description')}")
j1, t2 = xaa(t1, xa["backend_agent_client_id"], xa["backend_agent_kms_key_arn"], xa["backend_agent_kid"],
             xa["agent_b_issuer"], "agent-b.invoke", "hop 1 (backend)")
show("hop 1 · ID-JAG for anyco-agent-b-as", j1); show("hop 1 · T2", t2)
j2, t3 = xaa(t2, xa["client_id"], xa["kms_key_arn"], xa["kms_kid"], ok["gateway_issuer"], "pr:read pr:review", "hop 2 (agent)")
show("hop 2 · ID-JAG for anyco-gateway-as", j2); show("hop 2 · T3", t3)
