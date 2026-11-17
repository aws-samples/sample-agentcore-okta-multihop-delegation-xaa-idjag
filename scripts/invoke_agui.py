"""RUNTIME=b python scripts/invoke_agui.py DEFAULT "prompt"   (T1 from scripts/headless_login.py)
  RUNTIME=b, Pattern A: the backend's token exchange (T1 -> T2 at anyco-agent-a-as, as anyco-console-backend-app),
  then Runtime A with T2.
  RUNTIME=c, Pattern B: the backend's Cross App Access (T1 -> ID-JAG at the org server -> T2 at anyco-agent-b-as,
  as the AI agent anyco-backend-agent-oai), then Runtime B with T2.
  Add --raw to send T1 itself (each Runtime refuses it: wrong issuer)."""
import json, os, sys, time, urllib.parse, uuid
import requests
sys.path.insert(0, os.path.abspath("."))
import config as C
import okta_event as E
RT = os.environ.get("RUNTIME", "b")
fwd = {}
tok = (C.ROOT / "build" / ".user_token").read_text().strip()
EX, AT = "urn:ietf:params:oauth:grant-type:token-exchange", "urn:ietf:params:oauth:token-type:access_token"
CA = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
if "--raw" not in sys.argv and RT == "b":          # Pattern A: the backend's exchange, as the console does it
    ok = C.state()["okta"]
    r = requests.post(f"{ok['agent_a_issuer']}/v1/token", timeout=20,
                      auth=(ok["backend_client_id"], os.environ["ANYCO_BACKEND_CLIENT_SECRET"]),
                      data={"grant_type": EX, "subject_token": tok, "subject_token_type": AT,
                            "audience": ok["agent_a_audience"], "scope": "agent-a.invoke"})
    r.raise_for_status()
    tok = r.json()["access_token"]
elif "--raw" not in sys.argv:                       # Pattern B: the backend's XAA, as the console does it
    xs = C.state()["xaa"]
    cid, key, kid = xs["backend_agent_client_id"], xs["backend_agent_kms_key_arn"], xs["backend_agent_kid"]
    org = f"{C.OKTA_DOMAIN}/oauth2/v1/token"
    r = requests.post(org, timeout=20, data={"grant_type": EX, "subject_token": tok, "subject_token_type": AT,
        "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag", "audience": xs["agent_b_issuer"],
        "scope": "agent-b.invoke", "client_id": cid, "client_assertion_type": CA,
        "client_assertion": E.assertion(cid, key, kid, org)})
    r.raise_for_status()
    url = f"{xs['agent_b_issuer']}/v1/token"
    r = requests.post(url, timeout=20, data={"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        "assertion": r.json()["access_token"], "client_id": cid, "client_assertion_type": CA,
        "client_assertion": E.assertion(cid, key, kid, url)})
    r.raise_for_status()
    tok = r.json()["access_token"]
args = [a for a in sys.argv[1:] if not a.startswith("--")]
rel = args[0] if args else "DEFAULT"
prompt = args[1] if len(args) > 1 else "Review anyco/receipts-service #128 and post your review."
arn = C.state()[{"b": "runtime_b_arn", "c": "runtime_c_arn"}[RT]]
url = f"https://bedrock-agentcore.{C.REGION}.amazonaws.com/runtimes/{urllib.parse.quote(arn, safe='')}/invocations?qualifier={rel}"
body = {"threadId": str(uuid.uuid4()), "runId": str(uuid.uuid4()), "messages": [{"id": str(uuid.uuid4()), "role": "user", "content": prompt}],
        "tools": [], "context": [], "state": {}, "forwardedProps": fwd}
t = time.time()
r = requests.post(url, json=body, stream=True, timeout=300, headers={"Authorization": f"Bearer {tok}", "Content-Type": "application/json",
    "Accept": "text/event-stream", "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": f"run-{rel}-attempt-1-{uuid.uuid4().hex}"})
print("HTTP", r.status_code, r.headers.get("content-type"))
if r.status_code >= 400: print(r.text[:800]); sys.exit()
text = ""
for line in r.iter_lines():
    line = line.decode() if isinstance(line, bytes) else line
    if not line.startswith("data:"): continue
    ev = json.loads(line[5:])
    ty = ev.get("type")
    if ty == "TEXT_MESSAGE_CONTENT": text += ev.get("delta", ""); continue
    if ty in ("TOOL_CALL_ARGS", "RAW", "STATE_SNAPSHOT", "MESSAGES_SNAPSHOT", "STATE_DELTA"): continue
    extra = {k: ev[k] for k in ("toolCallName", "name", "value", "content", "message") if k in ev}
    print(f"{time.time()-t:5.1f}s {ty} {json.dumps(extra)[:int(os.environ.get('W', 240))]}")
print("TEXT:", text[:500])
