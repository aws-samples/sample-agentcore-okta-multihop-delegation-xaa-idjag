"""Test helper: run the machine-access chain directly against Okta (no AWS besides KMS signing).
T1 event source token -> T2 ID-JAG -> T3 partner MCP token. Prints decoded claims only.
Usage: python scripts/event_test.py [--resource]"""
import json, os, sys
sys.path.insert(0, os.path.abspath("."))
import config as C
import okta_event as E

ev = C.state()["event"]
use_resource = "--resource" in sys.argv
show = lambda name, t: print(f"{name:7}", json.dumps({k: v for k, v in E.claims(t).items() if k not in ("iat", "jti", "ver")}))

try:
    t1 = E.t1(ev["agent_issuer"], ev["source_client_id"], ev["source_kms_key_arn"], ev["source_kid"], "agent.invoke",
              resource=ev["agent_audience"] if use_resource else None, profile=C.AWS_PROFILE)
except Exception as e:
    sys.exit(f"T1: {e}")
show("T1", t1)
try:
    jag = E.t2(C.OKTA_DOMAIN, t1, ev["agent_client_id"], ev["agent_kms_key_arn"], ev["agent_kid"], ev["mcp_issuer"],
               "partner:read", profile=C.AWS_PROFILE)
except Exception as e:
    sys.exit(f"T2: {e}")
show("ID-JAG", jag)
try:
    t3 = E.t3(ev["mcp_issuer"], jag, ev["agent_client_id"], ev["agent_kms_key_arn"], ev["agent_kid"], "partner:read",
              profile=C.AWS_PROFILE)
except Exception as e:
    sys.exit(f"T3: {e}")
show("T3", t3)
