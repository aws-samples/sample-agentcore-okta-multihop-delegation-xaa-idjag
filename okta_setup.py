"""Optional: create the demo's Okta objects with the Okta Admin API, instead of by hand.

It does the same steps as docs/okta-setup.md (parts 1 to 4), in the same order, with the same
names. It needs an Okta API token from an admin (Admin Console > Security > API > Tokens) in .env:
    OKTA_API_TOKEN=...
It writes the IDs (and the client secrets of the apps it creates) into .env, so the next step is
okta_values.py. Run kms_keys.py first: the AI agents' public keys come from build/jwks/.

    .venv/bin/python okta_setup.py            create what's missing (safe to re-run)
    .venv/bin/python okta_setup.py --check    only report what exists and what's missing

Not automated: the optional password-only sign-in policy (docs part 1.3). It depends on your org's
session policies; without it the demo users sign in with MFA.
Remove everything it creates with okta_teardown.py. The AWS side has its own scripts (deploy.py,
teardown.py); none of them touch Okta.
"""
import json
import sys
import time

import requests

import config as C

TOKEN = C.os.environ.get("OKTA_API_TOKEN", "").strip()
if not TOKEN:
    sys.exit("Put OKTA_API_TOKEN=... in .env first (an Okta admin's API token), or follow docs/okta-setup.md by hand.")
BASE = C.OKTA_DOMAIN
H = {"Authorization": f"SSWS {TOKEN}", "Accept": "application/json", "Content-Type": "application/json"}
WP = "/workload-principals/api/v1"
EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
USERS = {"ada.lovelace@example.com": ("Ada", "Lovelace", True), "alan.turing@example.com": ("Alan", "Turing", True),
         "grace.hopper@example.com": ("Grace", "Hopper", False)}       # True = engineer
CHECK = "--check" in sys.argv
ENV = {}                                                 # what we write to .env at the end


def call(method, path, **kw):
    r = requests.request(method, BASE + path, headers=H, timeout=30, **kw)
    if r.status_code >= 400:
        raise RuntimeError(f"{method} {path} -> {r.status_code}: {r.text[:400]}")
    return r.json() if r.text else {}


def items(r):
    return r.get("data", []) if isinstance(r, dict) else r


def say(what, name, created):
    print(f"  {'created' if created else 'exists '}  {what} {name}")


# ---------------- lookups (also used by okta_teardown.py) ----------------
def find_user(login):
    return next(iter(call("GET", "/api/v1/users", params={"search": f'profile.login eq "{login}"'})), None)


def find_group(name):
    return next((g for g in call("GET", "/api/v1/groups", params={"q": name}) if g["profile"]["name"] == name), None)


def find_app(label):
    return next((a for a in call("GET", "/api/v1/apps", params={"q": label}) if a["label"] == label), None)


def find_as(name):
    return next((a for a in call("GET", "/api/v1/authorizationServers") if a["name"] == name), None)


def find_agent(name):
    return next((a for a in items(call("GET", f"{WP}/ai-agents")) if a["profile"]["name"] == name), None)


# ---------------- create-if-missing ----------------
def user(login, first, last):
    u = find_user(login)
    say("user", login, not u)
    if not u:
        pw = C.os.environ.get("DEMO_USER_PASSWORD")
        if not pw:
            sys.exit("Set DEMO_USER_PASSWORD in .env: okta_setup.py gives the demo users this password.")
        u = call("POST", "/api/v1/users", params={"activate": "true"}, json={
            "profile": {"firstName": first, "lastName": last, "email": login, "login": login},
            "credentials": {"password": {"value": pw}}})
    return u["id"]


def group(name, members):
    g = find_group(name)
    say("group", name, not g)
    if not g:
        g = call("POST", "/api/v1/groups", json={"profile": {"name": name, "description": "AnyCompany demo engineers"}})
    for uid in members:
        call("PUT", f"/api/v1/groups/{g['id']}/users/{uid}")
    return g["id"]


def app(label, settings, auth_method, env_id=None, env_secret=None, jwks=None):
    a = find_app(label)
    say("app", label, not a)
    if not a:
        oauth = {"token_endpoint_auth_method": auth_method}
        body = {"name": "oidc_client", "label": label, "signOnMode": "OPENID_CONNECT",
                "credentials": {"oauthClient": oauth},
                "settings": {"oauthClient": {**settings, "dpop_bound_access_tokens": False,
                                             **({"jwks": {"keys": [jwks]}} if jwks else {})}}}
        a = call("POST", "/api/v1/apps", json=body)
        if env_secret:
            ENV[env_secret] = a["credentials"]["oauthClient"]["client_secret"]
    elif env_secret and not C.os.environ.get(env_secret):
        print(f"    note: {label} already existed; copy its client secret into .env as {env_secret}")
    if env_id:
        ENV[env_id] = a["credentials"]["oauthClient"]["client_id"]
    return a


def auth_server(name, audience, description, env_id):
    a = find_as(name)
    say("authorization server", name, not a)
    if not a:
        a = call("POST", "/api/v1/authorizationServers", json={"name": name, "description": description, "audiences": [audience]})
    ENV[env_id] = a["id"]
    return a


def scopes(asid, names):
    have = {s["name"] for s in call("GET", f"/api/v1/authorizationServers/{asid}/scopes")}
    for n in names:
        if n not in have:
            call("POST", f"/api/v1/authorizationServers/{asid}/scopes",
                 json={"name": n, "description": n, "consent": "IMPLICIT", "metadataPublish": "NO_CLIENTS"})


def trust(asid, trusted_id):
    have = [t["id"] for t in call("GET", f"/api/v1/authorizationServers/{asid}/associatedServers", params={"trusted": "true"})]
    if trusted_id not in have:
        call("POST", f"/api/v1/authorizationServers/{asid}/associatedServers", json={"trusted": [trusted_id]})


def policy(asid, name, client_id, rules, lifetime=5):
    """An access policy for one client, with rules (name, group ids, grant types, scopes)."""
    p = next((x for x in call("GET", f"/api/v1/authorizationServers/{asid}/policies") if x["name"] == name), None)
    if not p:
        p = call("POST", f"/api/v1/authorizationServers/{asid}/policies", json={
            "type": "OAUTH_AUTHORIZATION_POLICY", "status": "ACTIVE", "name": name, "description": name,
            "priority": 1, "conditions": {"clients": {"include": [client_id]}}})
    have = {r["name"] for r in call("GET", f"/api/v1/authorizationServers/{asid}/policies/{p['id']}/rules")}
    for i, (rname, groups, grants, scps) in enumerate(rules, start=1):
        if rname in have:
            continue
        call("POST", f"/api/v1/authorizationServers/{asid}/policies/{p['id']}/rules", json={
            "type": "RESOURCE_ACCESS", "name": rname, "priority": i, "status": "ACTIVE",
            "conditions": {"people": {"groups": {"include": groups}}, "grantTypes": {"include": grants},
                           "scopes": {"include": scps}},
            "actions": {"token": {"accessTokenLifetimeMinutes": lifetime, "refreshTokenLifetimeMinutes": 0,
                                  "refreshTokenWindowMinutes": 10080}}})


def ai_agent(name, description, jwk_file, env_id, env_kid):
    """An Okta AI agent (no linked sign-in app) with the public half of its KMS key."""
    a = find_agent(name)
    say("AI agent", name, not a)
    if not a:
        call("POST", f"{WP}/ai-agents", json={"profile": {"name": name, "description": description}})
        for _ in range(10):                               # the API answers 202; the agent appears shortly
            time.sleep(3)
            a = find_agent(name)
            if a:
                break
    jwk = json.loads((C.ROOT / "build" / "jwks" / jwk_file).read_text())
    if not any(j.get("kid") == jwk["kid"] for j in items(call("GET", f"{WP}/ai-agents/{a['id']}/credentials/jwks"))):
        call("POST", f"{WP}/ai-agents/{a['id']}/credentials/jwks", json=jwk)
    ENV[env_id], ENV[env_kid] = a["id"], jwk["kid"]
    return a


def machine_access(org, agent, resource_url, as_id, caller_orn):
    """Register the agent as a resource (resource URL, set once, protected by an authorization
    server) and allow one caller: that caller's access tokens may be the subject of its exchange."""
    r = requests.patch(f"{BASE}{WP}/ai-agents/{agent['id']}", timeout=30, data=json.dumps({"resourceUrl": resource_url}),
                       headers={**H, "Content-Type": "application/merge-patch+json"})
    if r.status_code >= 400 and "already has existing A2A Server" not in r.text:
        raise RuntimeError(f"resourceUrl -> {r.status_code}: {r.text[:300]}")
    time.sleep(5)
    as_orn = f"orn:okta:idp:{org}:authorization_servers:{as_id}"
    a2a = f"/resource-servers/api/v1/a2a-servers/{agent['id']}/authorization-servers"
    if not any(x.get("orn") == as_orn for x in items(call("GET", a2a))):
        call("POST", a2a, json={"orn": as_orn, "type": "OKTA"})
        time.sleep(5)
    agent_orn = f"orn:okta:directory:{org}:workload-principals:ai-agents:{agent['id']}"
    found = call("GET", f"{WP}/delegation-links",
                 params={"filter": f'to.resourceOrn eq "{agent_orn}" AND from.clientOrn eq "{caller_orn}"'})
    flat = [x for x in items(found) if isinstance(x, dict) and "from" in x] + \
           [l for x in items(found) if isinstance(x, dict) for v in x.values() if isinstance(v, list) for l in v
            if isinstance(l, dict) and "from" in l]
    if not flat:
        call("POST", f"{WP}/delegation-links", json={
            "from": {"type": "OKTA_AUTHORIZATION_SERVER", "tokenType": "ACCESS_TOKEN", "clientOrn": caller_orn},
            "to": {"resourceOrn": agent_orn}})


def connection(org, agent, as_id, scps):
    as_orn = f"orn:okta:idp:{org}:authorization_servers:{as_id}"
    c = next((x for x in items(call("GET", f"{WP}/ai-agents/{agent['id']}/connections"))
              if (x.get("authorizationServer") or {}).get("orn") == as_orn), None)
    if not c:
        c = call("POST", f"{WP}/ai-agents/{agent['id']}/connections", json={
            "connectionType": "IDENTITY_ASSERTION_CUSTOM_AS", "authorizationServer": {"orn": as_orn},
            "scopeCondition": "INCLUDE_ONLY", "scopes": scps})
    if c.get("status") != "ACTIVE":
        call("POST", f"{WP}/ai-agents/{agent['id']}/connections/{c['id']}/lifecycle/activate")


def activate(agent):
    if (find_agent(agent["profile"]["name"]) or {}).get("status") != "ACTIVE":
        call("POST", f"{WP}/ai-agents/{agent['id']}/lifecycle/activate")


# ---------------- the four parts of docs/okta-setup.md ----------------
NAMES = {"users": list(USERS), "group": "anyco-engineers",
         "apps": ["anyco-eng-login-app", "anyco-pr-review-agent-app", "anyco-console-backend-app", "anyco-event-source-app"],
         "authorization servers": ["anyco-users-as", "anyco-agent-a-as", "anyco-gateway-as", "anyco-agent-b-as",
                                   "anyco-event-agent-as", "anyco-partner-mcp-as"],
         "AI agents": ["anyco-backend-agent-oai", "anyco-pr-review-agent-b-oai", "anyco-event-agent-oai"]}


def check():
    print("Okta objects (docs/okta-setup.md):")
    for login in NAMES["users"]:
        print(f"  {'exists ' if find_user(login) else 'MISSING'}  user {login}")
    print(f"  {'exists ' if find_group(NAMES['group']) else 'MISSING'}  group {NAMES['group']}")
    for n in NAMES["apps"]:
        print(f"  {'exists ' if find_app(n) else 'MISSING'}  app {n}")
    for n in NAMES["authorization servers"]:
        print(f"  {'exists ' if find_as(n) else 'MISSING'}  authorization server {n}")
    for n in NAMES["AI agents"]:
        a = find_agent(n)
        print(f"  {('exists ' if a else 'MISSING')}  AI agent {n}{' (' + a['status'] + ')' if a else ''}")


def main():
    if CHECK:
        return check()
    org = call("GET", "/api/v1/org")["id"]
    app_orn = lambda a: f"orn:okta:idp:{org}:apps:oidc_client:{a['id']}"
    agent_orn = lambda a: f"orn:okta:directory:{org}:workload-principals:ai-agents:{a['id']}"

    print("Part 1 · users and group")
    uids = {login: user(login, f, l) for login, (f, l, _) in USERS.items()}
    eng = group("anyco-engineers", [uids[u] for u, (_, _, e) in USERS.items() if e])
    everyone = "EVERYONE"                                   # what Okta's rule API takes for "any user"

    print("Part 2 · Pattern A")
    login = app("anyco-eng-login-app", {"application_type": "web", "grant_types": ["authorization_code"],
                                    "response_types": ["code"], "redirect_uris": [C.REDIRECT_URI],
                                    "post_logout_redirect_uris": [f"http://localhost:{C.CONSOLE_PORT}/"],
                                    "consent_method": "TRUSTED"},
                "client_secret_basic", "OKTA_LOGIN_CLIENT_ID", "ANYCO_LOGIN_CLIENT_SECRET")
    for uid in uids.values():
        call("POST", f"/api/v1/apps/{login['id']}/users", json={"id": uid})
    service = {"application_type": "service", "grant_types": ["client_credentials", EXCHANGE], "response_types": ["token"]}
    agent_app = app("anyco-pr-review-agent-app", service, "client_secret_basic", "OKTA_AGENT_CLIENT_ID", "OKTA_AGENT_CLIENT_SECRET")
    backend = app("anyco-console-backend-app", service, "client_secret_basic", "OKTA_BACKEND_CLIENT_ID", "ANYCO_BACKEND_CLIENT_SECRET")
    cid = lambda a: a["credentials"]["oauthClient"]["client_id"]

    users_as = auth_server("anyco-users-as", "api://anyco-pr-agent-aud", "Engineer sign-in for the PR Review Agent", "OKTA_USERS_AS_ID")
    scopes(users_as["id"], ["pr-agent.invoke"])
    policy(users_as["id"], "anyco-sign-in", cid(login), [
        ("engineers-may-invoke", [eng], ["authorization_code"], ["openid", "profile", "email", "pr-agent.invoke"]),
        ("everyone-sign-in-only", [everyone], ["authorization_code"], ["openid", "profile", "email"])], lifetime=60)
    agent_a = auth_server("anyco-agent-a-as", "api://anyco-agent-a-aud", "Tokens for the Pattern A agent", "OKTA_AGENT_A_AS_ID")
    scopes(agent_a["id"], ["agent-a.invoke"])
    trust(agent_a["id"], users_as["id"])
    policy(agent_a["id"], "anyco-console-backend-app", cid(backend),
           [("backend-for-engineers", [eng], [EXCHANGE], ["agent-a.invoke"])])
    gateway = auth_server("anyco-gateway-as", "api://anyco-gateway-aud", "Tokens that AgentCore Gateway accepts", "OKTA_GATEWAY_AS_ID")
    scopes(gateway["id"], ["pr:read", "pr:review", "pr:merge", "context:search"])
    trust(gateway["id"], agent_a["id"])
    policy(gateway["id"], "anyco-pr-review-agent-app", cid(agent_app),
           [("on-behalf-of-engineers", [eng], [EXCHANGE], ["pr:read", "pr:review"])])

    print("Part 3 · Pattern B")
    agent_b_as = auth_server("anyco-agent-b-as", "api://anyco-agent-b-aud", "Tokens for the Pattern B agent (trusts no other server)",
                             "OKTA_AGENT_B_AS_ID")
    scopes(agent_b_as["id"], ["agent-b.invoke"])
    backend_agent = ai_agent("anyco-backend-agent-oai", "Your backend, registered as an Okta AI agent (Cross App Access)",
                             "anyco-backend-agent.json", "OKTA_BACKEND_AGENT_CLIENT_ID", "OKTA_BACKEND_AGENT_KID")
    machine_access(org, backend_agent, "api://anyco-pr-agent-aud", users_as["id"], app_orn(login))
    connection(org, backend_agent, agent_b_as["id"], ["agent-b.invoke"])
    policy(agent_b_as["id"], "anyco-backend-agent-oai", backend_agent["id"],
           [("backend-agent-for-engineers", [eng], [JWT_BEARER], ["agent-b.invoke"])])
    activate(backend_agent)
    agent_b = ai_agent("anyco-pr-review-agent-b-oai", "The Pattern B agent on AgentCore Runtime (Cross App Access)",
                       "anyco-pr-review-agent-b.json", "OKTA_AGENT_B_CLIENT_ID", "OKTA_AGENT_B_KID")
    machine_access(org, agent_b, "api://anyco-agent-b-aud", agent_b_as["id"], agent_orn(backend_agent))
    connection(org, agent_b, gateway["id"], ["pr:read", "pr:review"])
    policy(gateway["id"], "anyco-pr-review-agent-b-oai", agent_b["id"],
           [("delegated-for-engineers", [eng], [JWT_BEARER], ["pr:read", "pr:review"])])
    activate(agent_b)

    print("Part 4 · Pattern C")
    src_jwk = json.loads((C.ROOT / "build" / "jwks" / "anyco-event-source.json").read_text())
    source = app("anyco-event-source-app", {"application_type": "service", "grant_types": ["client_credentials"],
                                        "response_types": ["token"]}, "private_key_jwt",
                 "OKTA_EVENT_SOURCE_CLIENT_ID", jwks=src_jwk)
    ENV["OKTA_EVENT_SOURCE_KID"] = src_jwk["kid"]
    event_as = auth_server("anyco-event-agent-as", "api://anyco-event-agent-aud", "Tokens for calling the event agent",
                           "OKTA_EVENT_AGENT_AS_ID")
    scopes(event_as["id"], ["agent.invoke"])
    policy(event_as["id"], "anyco-event-source-app", cid(source),
           [("event-source", [everyone], ["client_credentials"], ["agent.invoke"])])
    event_agent = ai_agent("anyco-event-agent-oai", "Event-triggered agent: acts for the app that fired the event",
                           "anyco-event-agent.json", "OKTA_EVENT_AGENT_CLIENT_ID", "OKTA_EVENT_AGENT_KID")
    machine_access(org, event_agent, "api://anyco-event-agent-aud", event_as["id"], app_orn(source))
    partner = auth_server("anyco-partner-mcp-as", "api://anyco-partner-mcp-aud", "The partner MCP server's issuer", "OKTA_PARTNER_AS_ID")
    scopes(partner["id"], ["partner:read", "partner:write"])
    policy(partner["id"], "anyco-event-agent-oai", event_agent["id"],
           [("event-agent-delegated", [everyone], [JWT_BEARER], ["partner:read", "partner:write"])])
    connection(org, event_agent, partner["id"], ["partner:read"])          # never partner:write
    activate(event_agent)

    C.write_env(ENV)
    print(f"\nDone. Wrote {len(ENV)} values to .env (never printed). Next: .venv/bin/python okta_values.py")


if __name__ == "__main__":
    main()
