"""Test helper: sign a demo user in without a browser (Okta authn -> sessionToken -> code).
Usage: python scripts/headless_login.py ada.lovelace@example.com  (password from DEMO_USER_PASSWORD)
Prints claims only; writes the token to build/.user_token (git-ignored) for other test scripts."""
import base64, hashlib, json, os, secrets, sys, urllib.parse
import requests
sys.path.insert(0, os.path.abspath("."))
import config as C
ok = C.state()["okta"]
user = sys.argv[1]; invoke = "--no-invoke" not in sys.argv
pw = C.required("DEMO_USER_PASSWORD")
r = requests.post(f"{C.OKTA_DOMAIN}/api/v1/authn", json={"username": user, "password": pw}, timeout=30)
if r.status_code >= 400 or r.json().get("status") != "SUCCESS":
    sys.exit(f"authn: {r.status_code} {r.text[:300]}")
st = r.json()["sessionToken"]
ver = secrets.token_urlsafe(48); ch = base64.urlsafe_b64encode(hashlib.sha256(ver.encode()).digest()).rstrip(b"=").decode()
q = {"client_id": ok["login_client_id"], "response_type": "code", "scope": "openid profile email" + (" pr-agent.invoke" if invoke else ""),
     "redirect_uri": C.REDIRECT_URI, "state": "x", "code_challenge": ch, "code_challenge_method": "S256", "sessionToken": st}
a = requests.get(f"{ok['users_issuer']}/v1/authorize", params=q, allow_redirects=False, timeout=30)
loc = a.headers.get("Location", "")
qs = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(loc).query))
if "code" not in qs:
    sys.exit(f"authorize: {a.status_code} {qs or a.text[:300]}")
t = requests.post(f"{ok['users_issuer']}/v1/token", auth=(ok["login_client_id"], os.environ["ANYCO_LOGIN_CLIENT_SECRET"]),
                  data={"grant_type": "authorization_code", "code": qs["code"], "redirect_uri": C.REDIRECT_URI, "code_verifier": ver}, timeout=30)
tok = t.json()["access_token"]
p = tok.split(".")[1]; p += "=" * (-len(p) % 4)
print(json.dumps({k: v for k, v in json.loads(base64.urlsafe_b64decode(p)).items() if k in ("sub", "uid", "email", "scp", "aud", "cid")}))
tf = C.ROOT / "build" / ".user_token"           # a real bearer token: owner-only
tf.touch(mode=0o600); tf.chmod(0o600); tf.write_text(tok)
