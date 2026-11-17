"""Record the Okta values you created by hand (docs/okta-setup.md) for the AWS stacks.

Reads the IDs from .env, checks that each authorization server answers its public discovery
URL (no Okta admin token is needed or used), and writes state.json["okta"], ["xaa"] and
["event"]. Run kms_keys.py first: the key ARNs come from there.

Pattern A needs the OKTA_* values; Pattern B adds OKTA_AGENT_B_*; Pattern C adds OKTA_EVENT_*.
A group whose values are all empty is skipped, so you can set up one pattern at a time.
"""
import sys

import requests

import config as C

B = {"OKTA_USERS_AS_ID": "anyco-users-as authorization server ID",
     "OKTA_GATEWAY_AS_ID": "anyco-gateway-as authorization server ID",
     "OKTA_LOGIN_CLIENT_ID": "anyco-eng-login-app client ID",
     "ANYCO_LOGIN_CLIENT_SECRET": "anyco-eng-login-app client secret",
     "OKTA_AGENT_CLIENT_ID": "anyco-pr-review-agent-app client ID",
     "OKTA_AGENT_CLIENT_SECRET": "anyco-pr-review-agent-app client secret",
     "OKTA_BACKEND_CLIENT_ID": "anyco-console-backend-app client ID (the backend's token exchange)",
     "ANYCO_BACKEND_CLIENT_SECRET": "anyco-console-backend-app client secret",
     "OKTA_AGENT_A_AS_ID": "anyco-agent-a-as authorization server ID"}
XAA = {"OKTA_AGENT_B_CLIENT_ID": "AI agent anyco-pr-review-agent-b-oai client ID (Client registration tab)",
       "OKTA_AGENT_B_KID": "its public key's Key ID, as Okta shows it",
       "OKTA_AGENT_B_AS_ID": "anyco-agent-b-as authorization server ID",
       "OKTA_BACKEND_AGENT_CLIENT_ID": "AI agent anyco-backend-agent-oai client ID (your backend, Client registration tab)",
       "OKTA_BACKEND_AGENT_KID": "its public key's Key ID, as Okta shows it"}
EVENT = {"OKTA_EVENT_SOURCE_CLIENT_ID": "anyco-event-source-app client ID",
         "OKTA_EVENT_SOURCE_KID": "its public key's Key ID, as Okta shows it",
         "OKTA_EVENT_AGENT_CLIENT_ID": "AI agent anyco-event-agent-oai client ID (Client registration tab)",
         "OKTA_EVENT_AGENT_KID": "its public key's Key ID, as Okta shows it",
         "OKTA_EVENT_AGENT_AS_ID": "anyco-event-agent-as authorization server ID",
         "OKTA_PARTNER_AS_ID": "anyco-partner-mcp-as authorization server ID"}
USERS_AUD, GATEWAY_AUD, AGENT_A_AUD = "api://anyco-pr-agent-aud", "api://anyco-gateway-aud", "api://anyco-agent-a-aud"
EVENT_AUD, PARTNER_AUD = "api://anyco-event-agent-aud", "api://anyco-partner-mcp-aud"


def values(group, name):
    got = {k: C.os.environ.get(k, "").strip() for k in group}
    if not any(got.values()):
        return None
    missing = [f"  {k}  ({group[k]})" for k, v in got.items() if not v]
    if missing:
        sys.exit(f"{name}: set these in .env:\n" + "\n".join(missing))
    return got


def issuer(as_id):
    iss = f"{C.OKTA_DOMAIN}/oauth2/{as_id}"
    r = requests.get(f"{iss}/.well-known/openid-configuration", timeout=15)
    if r.status_code != 200 or r.json().get("issuer") != iss:
        sys.exit(f"Okta authorization server {as_id} not found at {iss} (check the ID and that it is active)")
    return iss


def main():
    keys = C.state().get("kms") or {}
    b = values(B, "Pattern A")
    if not b:
        sys.exit("Fill in the Pattern A values in .env first (see docs/okta-setup.md, part 2).")
    okta = {"users_as_id": b["OKTA_USERS_AS_ID"], "users_issuer": issuer(b["OKTA_USERS_AS_ID"]), "users_audience": USERS_AUD,
            "gateway_as_id": b["OKTA_GATEWAY_AS_ID"], "gateway_issuer": issuer(b["OKTA_GATEWAY_AS_ID"]),
            "gateway_audience": GATEWAY_AUD, "login_client_id": b["OKTA_LOGIN_CLIENT_ID"],
            "agent_client_id": b["OKTA_AGENT_CLIENT_ID"], "backend_client_id": b["OKTA_BACKEND_CLIENT_ID"],
            "agent_a_as_id": b["OKTA_AGENT_A_AS_ID"], "agent_a_issuer": issuer(b["OKTA_AGENT_A_AS_ID"]),
            "agent_a_audience": AGENT_A_AUD}
    C.save_state(okta=okta)
    print("Pattern A: anyco-users-as, anyco-agent-a-as and anyco-gateway-as found")

    x = values(XAA, "Pattern B")
    if x:
        if not keys.get("anyco-pr-review-agent-b") or not keys.get("anyco-backend-agent"):
            sys.exit("Run kms_keys.py first")
        C.save_state(xaa={"agent_id": x["OKTA_AGENT_B_CLIENT_ID"], "client_id": x["OKTA_AGENT_B_CLIENT_ID"],
                          "kms_key_arn": keys["anyco-pr-review-agent-b"], "kms_kid": x["OKTA_AGENT_B_KID"],
                          "agent_b_as_id": x["OKTA_AGENT_B_AS_ID"], "agent_b_issuer": issuer(x["OKTA_AGENT_B_AS_ID"]),
                          "agent_b_audience": "api://anyco-agent-b-aud",
                          "backend_agent_client_id": x["OKTA_BACKEND_AGENT_CLIENT_ID"],
                          "backend_agent_kid": x["OKTA_BACKEND_AGENT_KID"],
                          "backend_agent_kms_key_arn": keys["anyco-backend-agent"],
                          "scopes": ["pr:read", "pr:review"], "custom_as_audience": okta["gateway_issuer"]})
        print("Pattern B: anyco-agent-b-as found; both AI agents recorded")

    e = values(EVENT, "Pattern C")
    if e:
        if not keys.get("anyco-event-source"):
            sys.exit("Run kms_keys.py first")
        C.save_state(event={"source_client_id": e["OKTA_EVENT_SOURCE_CLIENT_ID"], "source_kid": e["OKTA_EVENT_SOURCE_KID"],
                            "source_kms_key_arn": keys["anyco-event-source"],
                            "agent_id": e["OKTA_EVENT_AGENT_CLIENT_ID"], "agent_client_id": e["OKTA_EVENT_AGENT_CLIENT_ID"],
                            "agent_kid": e["OKTA_EVENT_AGENT_KID"], "agent_kms_key_arn": keys["anyco-event-agent"],
                            "agent_as_id": e["OKTA_EVENT_AGENT_AS_ID"], "agent_issuer": issuer(e["OKTA_EVENT_AGENT_AS_ID"]),
                            "agent_audience": EVENT_AUD, "agent_resource_url": EVENT_AUD,
                            "mcp_as_id": e["OKTA_PARTNER_AS_ID"], "mcp_issuer": issuer(e["OKTA_PARTNER_AS_ID"]),
                            "mcp_audience": PARTNER_AUD, "granted_scopes": ["partner:read"]})
        print("Pattern C: anyco-event-agent-as and anyco-partner-mcp-as found")
    print("state.json updated. Next: .venv/bin/python deploy.py")


if __name__ == "__main__":
    main()
