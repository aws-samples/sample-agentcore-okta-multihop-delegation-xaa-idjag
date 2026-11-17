"""Console for the agent-identity demo: Patterns A, B and C, live. Deploy and teardown are scripts
(deploy.py, teardown.py); the console never changes AWS resources.

Run from the project root:  ./run.sh   (or .venv/bin/uvicorn server.app:app --port 8010)

  /                 the UI (Patterns A, B and C · live runs)
  /login, /callback engineer sign-in with Okta (authorization code + PKCE)
  /api/a1           Scenario A1: the same token exchange with the Okta AI agent as the client (refused)
  /api/run-b        SSE: invoke Runtime A with the engineer's token, relay the agent's AG-UI
                    events, and the Gateway's own records of each tool call (interceptor
                    stamp + Cedar decision) as they land.
  /api/run-c        SSE: your backend's Cross App Access (T1 -> T2), then Runtime B with T2
  /api/event-publish  publish one pull-request event to SNS (JSON body only)
  /api/last-event   the trigger Lambda's newest trace record (claims and results, no tokens)
The console never shows a raw token, only decoded claims.
"""
import asyncio
import base64
import hashlib
import json
import secrets
import sys
import threading
import time
import urllib.parse
import uuid
from pathlib import Path

import requests
from boto3.dynamodb.conditions import Key
from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import config as C  # noqa: E402

if C.AWS_PROFILE:          # one account for every AWS call: the .env profile, not the shell's
    C.os.environ["AWS_PROFILE"] = C.AWS_PROFILE
C.os.environ.setdefault("AWS_DEFAULT_REGION", C.REGION)
import okta_event  # noqa: E402  (KMS-signed private_key_jwt for the Okta AI agents)

app = FastAPI()

# The console is a local demo tool: only these Host values and Origins are accepted. That stops DNS
# rebinding (a public name that resolves to 127.0.0.1) and requests from other local origins, such
# as a page on another localhost port, which browsers treat as the same site for cookies.
ALLOWED_HOSTS = {f"localhost:{C.CONSOLE_PORT}", f"127.0.0.1:{C.CONSOLE_PORT}"}
ALLOWED_ORIGINS = {f"http://{h}" for h in ALLOWED_HOSTS}


@app.middleware("http")
async def local_only(request, call_next):
    """Every request: an allowed Host. Every POST: an allowed Origin, a JSON body and the session's
    CSRF token in X-CSRF-Token. Anything else is refused before a route runs."""
    if request.headers.get("host", "") not in ALLOWED_HOSTS:
        return JSONResponse({"error": "unexpected Host"}, status_code=403)
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        if request.headers.get("origin", "") not in ALLOWED_ORIGINS:
            return JSONResponse({"error": "cross-origin request refused"}, status_code=403)
        if not request.headers.get("content-type", "").startswith("application/json"):
            return JSONResponse({"error": "JSON only"}, status_code=415)
        s = SESSIONS.get(request.cookies.get("fsid", ""))
        sent = request.headers.get("x-csrf-token", "")
        if not s or not sent or not secrets.compare_digest(sent, s.get("csrf", "")):
            return JSONResponse({"error": "missing or wrong CSRF token"}, status_code=403)
    return await call_next(request)

WEB = C.ROOT / "web"
app.mount("/vendor", StaticFiles(directory=WEB / "vendor"), name="vendor")
S = C.session()
TABLE = S.resource("dynamodb").Table(C.N["table"])
SESSIONS = {}
RUN = {"n": 41}


def _num(o):
    from decimal import Decimal
    if isinstance(o, Decimal):
        return int(o) if o == o.to_integral_value() else float(o)
    return str(o)


def _sse(obj):
    return f"data: {json.dumps(obj, default=_num)}\n\n"


def claims_of(tok):
    try:
        p = tok.split(".")[1]
        p += "=" * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except Exception:
        return {}


def jwt_view(tok):
    """A JWT as header + claims; the signature only as a length (never a usable token)."""
    try:
        h, p, sig = tok.split(".")
        dec = lambda x: json.loads(base64.urlsafe_b64decode(x + "=" * (-len(x) % 4)))
        return {"header": dec(h), "payload": dec(p), "signature": f"<{len(sig)} chars, not shown>"}
    except Exception:
        return f"<{len(tok or '')} chars>"


def backend_exchange(s, which="a"):
    """Your backend turns the signed-in user's token (T1) into a token for one agent (T2).
    Pattern A ("a"): one RFC 8693 exchange at anyco-agent-a-as, as the service app anyco-console-backend-app.
    Pattern B ("b"): Cross App Access, as the AI agent anyco-backend-agent-oai (private_key_jwt, KMS):
    step 1 at the org server (T1 -> ID-JAG for anyco-agent-b-as), step 2 at anyco-agent-b-as (ID-JAG -> T2).
    anyco-agent-b-as trusts no other server, so the one-step exchange is refused there.
    Returns (T2, the calls as made: JWTs as claims only). Cached per agent in the session until near
    expiry; cleared on every sign-in and sign-out."""
    cache = s.get("t2") or {}
    hit = cache.get(which) or {}
    if hit.get("token") and claims_of(hit["token"]).get("exp", 0) > time.time() + 30:
        return hit["token"], hit["record"]
    token, record = _exchange_a(s) if which == "a" else _xaa_b(s)
    s["t2"] = {**cache, which: {"token": token, "record": record}}
    return token, record


def _call(url, form, shown, client, **kw):
    r = requests.post(url, data=form, timeout=20, **kw)
    body = r.json() if r.headers.get("content-type", "").startswith("application/json") else {"text": r.text[:300]}
    rec = {"in": {"method": "POST", "url": url, "client": client, "form": shown},
           "out": {"status": r.status_code, "body": {**body, **({"access_token": jwt_view(body["access_token"])}
                                                              if body.get("access_token") else {})}}}
    return r, body, rec


def _exchange_a(s):
    ok = C.state()["okta"]
    url = f"{ok['agent_a_issuer']}/v1/token"
    form = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token": s["token"],
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": ok["agent_a_audience"], "scope": "agent-a.invoke"}
    r, body, rec = _call(url, form, {**form, "subject_token": jwt_view(s["token"])},
                         "anyco-console-backend-app (client secret, Basic auth)",
                         auth=(ok["backend_client_id"], C.os.environ["ANYCO_BACKEND_CLIENT_SECRET"]))
    if r.status_code >= 400:
        raise RuntimeError(f"Okta refused the backend's token exchange: {body.get('error')}: {body.get('error_description')}")
    return body["access_token"], rec


def _xaa_b(s):
    xs = C.state()["xaa"]
    cid, key, kid = xs["backend_agent_client_id"], xs["backend_agent_kms_key_arn"], xs["backend_agent_kid"]
    who = "anyco-backend-agent-oai (AI agent · private_key_jwt, signed in KMS)"
    hide = {"client_assertion": "(private_key_jwt · signed in KMS · not shown)"}
    org = f"{C.OKTA_DOMAIN}/oauth2/v1/token"
    f1 = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token": s["token"],
          "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
          "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
          "audience": xs["agent_b_issuer"], "scope": "agent-b.invoke", "client_id": cid,
          "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion": okta_event.assertion(cid, key, kid, org)}
    r, body, step1 = _call(org, f1, {**f1, **hide, "subject_token": jwt_view(s["token"])}, who)
    if r.status_code >= 400:
        raise RuntimeError(f"Okta refused the backend's XAA step 1: {body.get('error')}: {body.get('error_description')}")
    jag = body["access_token"]
    url = f"{xs['agent_b_issuer']}/v1/token"
    f2 = {"grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer", "assertion": jag, "client_id": cid,
          "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
          "client_assertion": okta_event.assertion(cid, key, kid, url)}
    r, body, step2 = _call(url, f2, {**f2, **hide, "assertion": jwt_view(jag)}, who)
    if r.status_code >= 400:
        raise RuntimeError(f"anyco-agent-b-as refused the backend's XAA step 2: {body.get('error')}: {body.get('error_description')}")
    return body["access_token"], {**step2, "steps": [step1, step2], "id_jag": jwt_view(jag)}


def sess(request):
    """The request's session; a new one if it has none. One request always gets the same session
    (cached on request.state), so the cookie set on the response matches the CSRF token returned."""
    sid = getattr(request.state, "sid", None) or request.cookies.get("fsid")
    if not sid or sid not in SESSIONS:
        sid = secrets.token_urlsafe(16)
        SESSIONS[sid] = {"token": None, "claims": None, "xaa": {}, "csrf": secrets.token_urlsafe(24)}
    request.state.sid = sid
    return sid, SESSIONS[sid]


def with_cookie(request, resp):
    sid, _ = sess(request)
    resp.set_cookie("fsid", sid, httponly=True, samesite="lax")
    return resp


@app.get("/")
def index():
    return FileResponse(WEB / "index.html")


# Code shown on the Pattern C screen: an explicit allowlist (names, not paths).
CODE_FILES = {"event-agent-core": C.ROOT / "agent_event" / "main.py"}


@app.get("/api/code/{name}")
def code_file(name: str):
    f = CODE_FILES.get(name)
    if not f or not f.exists():
        return JSONResponse({"error": "not found"}, status_code=404)
    return JSONResponse({"path": str(f.relative_to(C.ROOT)), "text": f.read_text()})


@app.get("/api/status")
def status(request: Request):
    _, s = sess(request)
    st = C.state()
    ok = st.get("okta", {})
    c = s.get("claims") or {}
    user = None
    if c and c.get("exp", 0) > time.time():
        user = {k: c.get(k) for k in ("sub", "uid", "scp", "aud", "exp", "iss") if k in c}
    xs = st.get("xaa") or {}
    ev = st.get("event") or {}
    acct = C.ACCOUNT
    # who each ID in a token is: lets the drawers decode sub, cid and every act level
    clients = {k: v for k, v in {
        ok.get("login_client_id"): ["anyco-eng-login-app", "the web app Ada signs in to"],
        ok.get("backend_client_id"): ["anyco-console-backend-app", "your backend's service app (Pattern A)"],
        ok.get("agent_client_id"): ["anyco-pr-review-agent-app", "the agent's service app (Pattern A)"],
        xs.get("backend_agent_client_id"): ["anyco-backend-agent-oai", "your backend, as an Okta AI agent (Pattern B)"],
        xs.get("client_id"): ["anyco-pr-review-agent-b-oai", "the agent on Runtime B, an Okta AI agent (Pattern B)"],
        ev.get("source_client_id"): ["anyco-event-source-app", "the app that fires the event (Pattern C)"],
        ev.get("agent_client_id"): ["anyco-event-agent-oai", "the event agent, an Okta AI agent (Pattern C)"]}.items() if k}
    issuers = {k: v for k, v in {
        C.OKTA_DOMAIN: "the Okta org authorization server (issues ID-JAGs)",
        ok.get("users_issuer"): "anyco-users-as (sign-in)", ok.get("agent_a_issuer"): "anyco-agent-a-as",
        xs.get("agent_b_issuer"): "anyco-agent-b-as", ok.get("gateway_issuer"): "anyco-gateway-as",
        ev.get("agent_issuer"): "anyco-event-agent-as", ev.get("mcp_issuer"): "anyco-partner-mcp-as"}.items() if k}
    audiences = {"api://anyco-pr-agent-aud": "anyco-users-as' audience: the sign-in token",
                 "api://anyco-agent-a-aud": "the Pattern A agent (Runtime A)", "api://anyco-agent-b-aud": "the Pattern B agent (Runtime B)",
                 "api://anyco-gateway-aud": "AgentCore Gateway", "api://anyco-event-agent-aud": "the event agent",
                 "api://anyco-partner-mcp-aud": "the partner MCP server"}
    return with_cookie(request, JSONResponse({
        "csrf": s.get("csrf", ""),
        "who": {"clients": clients, "issuers": issuers, "audiences": audiences},
        "account": f"{acct[:3]}••••••{acct[-3:]}", "region": C.REGION,
        "okta": {"issuer": ok.get("users_issuer"), "audience": ok.get("users_audience"), "ready": bool(ok),
                 "gateway_issuer": ok.get("gateway_issuer"), "gateway_audience": ok.get("gateway_audience"),
                 "login_client_id": ok.get("login_client_id"), "agent_client_id": ok.get("agent_client_id")},
        "user": user, "login_error": s.get("login_error"),
        "deployed": {"policy_engine": st.get("policy_engine_id"),           # the shared base
                     "interceptor": C.N["interceptor_fn"], "tools": C.N["tools_fn"]},
        "deployed_b": {"gateway": st.get("gateway_b_id"), "gateway_url": st.get("gateway_b_url"),
                       "runtime": st.get("runtime_b_id"), "runtime_arn": st.get("runtime_b_arn"),
                       "runtime_version": st.get("runtime_b_version"), "provider": st.get("obo_provider_arn"),
                       "role": f"arn:aws:iam::{acct}:role/anyco-agentid-runtime-obo-role" if st.get("runtime_b_id") else None},
        "deployed_c": {"runtime": st.get("runtime_c_id"), "runtime_arn": st.get("runtime_c_arn"),
                       "runtime_version": st.get("runtime_c_version"), "gateway": st.get("gateway_b_id"),
                       "gateway_url": st.get("gateway_b_url"),
                       "role": f"arn:aws:iam::{acct}:role/anyco-agentid-runtime-xaa-role" if st.get("runtime_c_id") else None,
                       "agent_id": xs.get("agent_id"), "app_id": xs.get("app_id"), "client_id": xs.get("client_id"),
                       "connection_id": xs.get("connection_id"), "scopes": xs.get("scopes"),
                       "kid": xs.get("kms_kid")},
        "deployed_e": {"runtime": st.get("event_runtime_id"), "runtime_arn": st.get("event_runtime_arn"),
                       "gateway": st.get("event_gateway_id"), "gateway_url": st.get("event_gateway_url"),
                       "mcp_runtime": st.get("event_mcp_runtime_id"), "topic": st.get("event_topic_arn"),
                       "source_client_id": ev.get("source_client_id"), "agent_id": ev.get("agent_id"),
                       "agent_issuer": ev.get("agent_issuer"), "agent_audience": ev.get("agent_audience"),
                       "mcp_issuer": ev.get("mcp_issuer"), "mcp_audience": ev.get("mcp_audience"),
                       "delegation_link_id": ev.get("delegation_link_id"), "scopes": ev.get("granted_scopes"),
                       "source_kid": ev.get("source_kid"), "agent_kid": ev.get("agent_kid")},
    }))


# ---- sign-in ------------------------------------------------------------------------------

@app.get("/login")
def login(request: Request):
    sid, s = sess(request)
    ok = C.state()["okta"]
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    state = secrets.token_urlsafe(16)
    s["pending"] = {"state": state, "verifier": verifier, "back": request.query_params.get("back", "liveb")}
    q = {"client_id": ok["login_client_id"], "response_type": "code", "scope": "openid profile email pr-agent.invoke",
         "redirect_uri": C.REDIRECT_URI, "state": state, "code_challenge": challenge,
         "code_challenge_method": "S256", "prompt": "login"}
    r = RedirectResponse(f"{ok['users_issuer']}/v1/authorize?{urllib.parse.urlencode(q)}")
    r.set_cookie("fsid", sid, httponly=True, samesite="lax")
    return r


@app.get("/callback")
def callback(request: Request, code: str = "", state: str = "", error: str = "", error_description: str = ""):
    _, s = sess(request)
    p = s.get("pending") or {}
    back = p.get("back", "liveb")
    if error:
        s["login_error"] = f"{error}: {error_description}"
        return RedirectResponse(f"/#{back}")
    if state != p.get("state"):
        s["login_error"] = "state mismatch"
        return RedirectResponse(f"/#{back}")
    ok = C.state()["okta"]
    r = requests.post(f"{ok['users_issuer']}/v1/token", timeout=30,
                      auth=(ok["login_client_id"], C.os.environ["ANYCO_LOGIN_CLIENT_SECRET"]),
                      data={"grant_type": "authorization_code", "code": code, "redirect_uri": C.REDIRECT_URI,
                            "code_verifier": p.get("verifier", "")})
    if r.status_code >= 400:
        s["login_error"] = r.text[:200]
        return RedirectResponse(f"/#{back}")
    s["t2"] = None                                  # never reuse another sign-in's exchanged token
    s["token"] = r.json()["access_token"]
    s["id_token"] = r.json().get("id_token")         # only used for Okta logout
    s["claims"] = claims_of(s["token"])
    s["login_error"] = None
    return RedirectResponse(f"/#{back}")


@app.get("/api/my-token")
def my_token(request: Request, app: str = "", kind: str = "access"):
    """The signed-in engineer's Okta access token (or, app=xaa, the agent-app tokens; kind=id for
    the id_token), decoded: header + every claim. The raw token and its signature never leave."""
    _, s = sess(request)
    tok = s.get("token")
    if not tok:
        return with_cookie(request, JSONResponse({}))
    h, p, sig = (tok.split(".") + ["", "", ""])[:3]

    def dec(part):
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    return with_cookie(request, JSONResponse({"header": dec(h), "payload": dec(p),
                                              "signature": f"<{len(sig)} chars, hidden>"}))


@app.get("/logout")
def okta_logout(request: Request):
    """Sign out of the console AND end the Okta session, so the next sign-in can be another user."""
    _, s = sess(request)
    idt = s.get("id_token")
    s.update(token=None, claims=None, id_token=None, login_error=None, xaa={}, t2=None)
    ok = C.state()["okta"]
    if not idt:
        return RedirectResponse("/")
    q = {"id_token_hint": idt, "post_logout_redirect_uri": f"http://localhost:{C.CONSOLE_PORT}/"}
    return RedirectResponse(f"{ok['users_issuer']}/v1/logout?{urllib.parse.urlencode(q)}")


@app.post("/api/logout")
def logout(request: Request):
    _, s = sess(request)
    s.update(token=None, claims=None, login_error=None, xaa={}, t2=None)
    return with_cookie(request, JSONResponse({"ok": True}))


@app.get("/api/tool-specs")
def tool_specs():
    """The tool specs the agent gets from the Gateway's tools/list (read from the deployed targets)."""
    ac = S.client("bedrock-agentcore-control")
    gid = C.state().get("gateway_b_id")
    out = []
    if gid:
        for t in ac.list_gateway_targets(gatewayIdentifier=gid, maxResults=100)["items"]:
            d = ac.get_gateway_target(gatewayIdentifier=gid, targetId=t["targetId"])
            lam = d.get("targetConfiguration", {}).get("mcp", {}).get("lambda", {})
            for tool in lam.get("toolSchema", {}).get("inlinePayload", []):
                out.append({"name": f"{t['name']}___{tool['name']}", "target": t["name"],
                            "description": tool.get("description", ""), "inputSchema": tool.get("inputSchema", {})})
    return JSONResponse(json.loads(json.dumps({"tools": out}, default=_num)))


@app.get("/api/last-call")
def last_call(act: int = 0):
    """The most recent tools/call as the Gateway's interceptor received it (credentials masked).
    act=1: delegation calls (cid = the Okta AI agent); act=0: Pattern A token-exchange calls
    (cid = the agent's Okta app). Both tokens carry act, so cid tells them apart."""
    since = int((time.time() - 6 * 3600) * 1000)
    r = TABLE.query(KeyConditionExpression=Key("pk").eq("trace") & Key("sk").gt(f"{since:013d}"),
                    ScanIndexForward=False, Limit=80)
    keep = C.ROOT / "build" / ("last_call_xaa.json" if act else "last_call_jwt.json")   # survive reset_demo
    st = C.state()
    want_cid = (st.get("xaa") or {}).get("client_id") if act else (st.get("okta") or {}).get("agent_client_id")
    for it in r.get("Items", []):
        if it.get("phase") == "request" and it.get("method") == "tools/call" and it.get("http") \
                and it.get("auth") == "JWT" and (it.get("claims") or {}).get("cid") == want_cid:
            out = json.loads(json.dumps({"http": it["http"], "tool": it.get("tool"),
                                         "modified_arguments": it.get("arguments"),
                                         "agent_headers": it.get("agent_headers"),
                                         "literal_event": it.get("literal_event"),
                                         "literal_return": it.get("literal_return")}, default=_num))
            keep.write_text(json.dumps(out, indent=1))
            return JSONResponse(out)
    return JSONResponse(json.loads(keep.read_text()) if keep.exists() else {})


@app.get("/api/last-obo")
def last_obo():
    """Claims of the last exchanged (OBO) token the Pattern A agent reported."""
    f = C.ROOT / "build" / "last_obo.json"
    return JSONResponse(json.loads(f.read_text()) if f.exists() else {})


@app.get("/api/last-xaa")
def last_xaa():
    """The Cross App Access agent's last report of the two Okta steps (claims and masked forms only)."""
    f = C.ROOT / "build" / "last_xaa.json"
    return JSONResponse(json.loads(f.read_text()) if f.exists() else {})


@app.get("/api/policies")
def policies():
    import release as R
    ac = S.client("bedrock-agentcore-control")
    pe = C.state().get("policy_engine_id")
    out = {}
    if pe:
        for p in R._policies(ac, pe):
            if p["name"].startswith(("AnycoA_", "AnycoB_")):
                d = ac.get_policy(policyEngineId=pe, policyId=p["policyId"])
                out[p["name"]] = d.get("definition", {}).get("cedar", {}).get("statement", "")
    return JSONResponse({"policies": out})


# ---- run: AG-UI relay + Gateway records ------------------------------------------------------

def _gateway_records(since_ms, run_id):
    r = TABLE.query(KeyConditionExpression=Key("pk").eq("trace") & Key("sk").gt(f"{since_ms:013d}"), Limit=200)
    out = []
    for it in r.get("Items", []):
        if it.get("run") == run_id and it.get("method") == "tools/call":
            out.append({"sk": it["sk"], "phase": it["phase"], "tool": it.get("tool", ""),
                        "outcome": it.get("outcome"),
                        "agent_id": it.get("agent_id"), "auth": it.get("auth"), "run": it.get("run"),
                        "arguments": it.get("arguments"), "original_arguments": it.get("original_arguments"),
                        "agent_headers": it.get("agent_headers"),
                        "http": it.get("http"), "literal_event": it.get("literal_event"),
                        "literal_return": it.get("literal_return"),
                        "detail": (it.get("detail") or "")[:1200]})
    return out


# ---- Pattern C: an event, no user -----------------------------------------------------------

@app.post("/api/a1")
async def scenario_a1(request: Request):
    """Scenario A1: the agent's token exchange (step 4, subject = T2), but with the Okta AI agent as the client
    (private_key_jwt signed by its KMS key) instead of the agent's service app. Okta refuses it:
    an AI agent can't be the requesting client of an on-behalf-of exchange; it uses Cross App Access.
    Returns the request as sent and Okta's answer (JWTs as claims only)."""
    _, s = sess(request)
    if not s.get("token") or (s.get("claims") or {}).get("exp", 0) < time.time():
        return JSONResponse({"error": "Sign in on this screen first"}, status_code=401)
    st = C.state()
    ok, xs = st.get("okta") or {}, st.get("xaa") or {}
    if not xs.get("client_id"):
        return JSONResponse({"error": "Set up Pattern B's Okta AI agent first"}, status_code=409)
    try:
        tok, _ = backend_exchange(s)      # the subject is what the agent receives: T2
    except Exception as e:
        return JSONResponse({"error": str(e)[:300]}, status_code=502)
    url = f"{ok['gateway_issuer']}/v1/token"
    form = {"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange", "subject_token": tok,
            "subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
            "audience": ok["gateway_audience"], "scope": "pr:read pr:review", "client_id": xs["client_id"],
            "client_assertion_type": okta_event.ASSERTION_TYPE,
            "client_assertion": okta_event.assertion(xs["client_id"], xs["kms_key_arn"], xs["kms_kid"], url)}
    r = requests.post(url, data=form, timeout=20)
    try:
        body = r.json()
    except ValueError:
        body = {"text": r.text[:300]}
    if body.get("access_token"):
        body["access_token"] = jwt_view(body["access_token"])
    return JSONResponse({
        "request": {"method": "POST", "url": url, "form": {**form, "subject_token": jwt_view(tok),
                                                          "client_assertion": jwt_view(form["client_assertion"])}},
        "response": {"status": r.status_code, "body": body}})


EVENT_TYPES = ("pr.opened", "pr.approved")


@app.post("/api/event-publish")
async def event_publish(request: Request):
    """Publish one pull-request event to the SNS topic (as this console's AWS identity)."""
    st = C.state()
    if not st.get("event_topic_arn"):
        return JSONResponse({"error": "Deploy Pattern C first"}, status_code=409)
    body = await request.json()
    ev = {"type": body.get("type") if body.get("type") in EVENT_TYPES else "pr.opened",
          "repo": str(body.get("repo") or "anyco/receipts-service")[:80],
          "pr": int(body.get("pr") or 128), "title": str(body.get("title") or "Add receipt OCR retry")[:120]}
    t0 = int(time.time() * 1000)
    mid = C.session().client("sns").publish(TopicArn=st["event_topic_arn"], Message=json.dumps(ev))["MessageId"]
    return JSONResponse({"message_id": mid, "published_ms": t0, "event": ev})


def _plain(o):
    from decimal import Decimal
    if isinstance(o, Decimal):
        return int(o) if o == o.to_integral_value() else float(o)
    if isinstance(o, dict):
        return {k: _plain(v) for k, v in o.items()}
    if isinstance(o, list):
        return [_plain(v) for v in o]
    return o


@app.get("/api/last-event")
def last_event(after: int = 0):
    """The newest event run the trigger Lambda recorded (claims and results only, no tokens)."""
    tbl = C.session().resource("dynamodb").Table(C.N["table"])
    r = tbl.query(KeyConditionExpression=Key("pk").eq("event") & Key("sk").gt(str(after)), ScanIndexForward=False, Limit=1)
    items = r.get("Items") or []
    return JSONResponse(_plain(items[0]) if items else {})


@app.post("/api/run-b")
async def run_b(request: Request):
    """Pattern A · OBO/Delegation (token exchange): same engineer token, Runtime A, exchange inside the agent."""
    body = await request.json()
    return _run(request, C.state().get("runtime_b_arn"), "DEFAULT",
                body.get("prompt") or "Post a COMMENT review on anyco/receipts-service #128 as me.")


@app.post("/api/run-c")
async def run_c(request: Request):
    """Pattern B · Cross App Access: your backend's two XAA steps (T1 -> ID-JAG -> T2), then Runtime B with T2."""
    body = await request.json()
    return _run(request, C.state().get("runtime_c_arn"), "DEFAULT",
                body.get("prompt") or "Post a COMMENT review on anyco/receipts-service #128 for me.", exchange_for="b")


def _run(request, runtime_arn, qualifier, prompt, exchange_for="a"):
    _, s = sess(request)
    src = s
    token = src.get("token")
    fwd = {}
    st = {"runtime_arn": runtime_arn}

    async def gen():
        if not token or (src.get("claims") or {}).get("exp", 0) < time.time():
            yield _sse({"type": "failed", "reason": "Sign in with Okta first"})
            return
        if not st.get("runtime_arn"):
            yield _sse({"type": "failed", "reason": "Deploy the stack first"})
            return
        RUN["n"] += 1
        run_id = f"run-{RUN['n']}-attempt-1-{uuid.uuid4().hex}"
        t0 = int(time.time() * 1000) - 2000
        yield _sse({"type": "run", "run_id": run_id, "release": qualifier})
        bearer = token
        if exchange_for:   # the backend exchanges the user's token for this agent's audience first
            try:
                bearer, rec = backend_exchange(s, exchange_for)
            except Exception as e:
                yield _sse({"type": "failed", "reason": str(e)[:300]})
                return
            yield _sse({"type": "backend", "value": rec})
        url = (f"https://bedrock-agentcore.{C.REGION}.amazonaws.com/runtimes/"
               f"{urllib.parse.quote(st['runtime_arn'], safe='')}/invocations?qualifier={qualifier}")
        payload = {"threadId": str(uuid.uuid4()), "runId": str(uuid.uuid4()),
                   "messages": [{"id": str(uuid.uuid4()), "role": "user", "content": prompt}],
                   "tools": [], "context": [], "state": {}, "forwardedProps": fwd}
        q = asyncio.Queue()
        loop = asyncio.get_event_loop()
        done = threading.Event()

        def reader():
            try:
                r = requests.post(url, json=payload, stream=True, timeout=300, headers={
                    "Authorization": f"Bearer {bearer}", "Content-Type": "application/json",
                    "Accept": "text/event-stream", "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": run_id})
                if r.status_code >= 400:
                    loop.call_soon_threadsafe(q.put_nowait, {"type": "failed", "reason": f"Runtime HTTP {r.status_code}: {r.text[:300]}"})
                    return
                for line in r.iter_lines():
                    line = line.decode() if isinstance(line, bytes) else line
                    if line.startswith("data:"):
                        try:
                            ev = json.loads(line[5:])
                        except Exception:
                            continue
                        if ev.get("type") in ("RAW", "STATE_SNAPSHOT", "MESSAGES_SNAPSHOT", "STATE_DELTA"):
                            continue
                        if ev.get("type") == "CUSTOM" and ev.get("name") == "obo_token_jwt":
                            (C.ROOT / "build" / "last_obo.json").write_text(json.dumps(ev.get("value") or {}, indent=1))
                        if ev.get("type") == "CUSTOM" and ev.get("name") == "xaa":
                            (C.ROOT / "build" / "last_xaa.json").write_text(json.dumps(ev.get("value") or {}, indent=1))
                        loop.call_soon_threadsafe(q.put_nowait, {"type": "agui", "event": ev})
            except Exception as e:  # noqa: BLE001
                loop.call_soon_threadsafe(q.put_nowait, {"type": "failed", "reason": str(e)[:300]})
            finally:
                done.set()
                loop.call_soon_threadsafe(q.put_nowait, None)

        def poller():
            seen = set()
            last_pass = False
            while True:
                finished = last_pass
                if done.is_set() and not last_pass:
                    time.sleep(1.5)          # the RESPONSE record can land just after the stream ends
                    last_pass = True
                    finished = True
                try:
                    for rec in _gateway_records(t0, run_id):
                        if rec["sk"] not in seen:
                            seen.add(rec["sk"])
                            loop.call_soon_threadsafe(q.put_nowait, {"type": "gateway", **rec})
                except Exception:
                    pass
                if finished:
                    loop.call_soon_threadsafe(q.put_nowait, {"type": "poller_done"})
                    return
                time.sleep(0.6)

        threading.Thread(target=reader, daemon=True).start()
        threading.Thread(target=poller, daemon=True).start()
        open_streams = 2
        while open_streams:
            item = await q.get()
            if item is None or (isinstance(item, dict) and item.get("type") == "poller_done"):
                open_streams -= 1
                continue
            yield _sse(item)
        yield _sse({"type": "done", "run_id": run_id})

    return StreamingResponse(gen(), media_type="text/event-stream")
