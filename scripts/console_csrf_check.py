"""Evidence for the console's cross-origin protections. Signs Ada in (Chrome), then:
  1. a page on ANOTHER localhost port posts to /api/run-b with her cookie: text/plain fetch and an
     HTML form post (both "simple" requests that skip CORS preflight) -> both must be refused (403/415)
  2. the same POST from the console's own origin but without the CSRF token -> refused (403)
  3. a request with a foreign Host header (DNS rebinding) -> refused (403)
  4. the console's own page still works (status 200, CSRF token present)
Writes build/console-csrf-check.json. The attacker page is served on 127.0.0.1 only.
"""
import http.server, json, os, sys, threading
import requests
from playwright.sync_api import sync_playwright
sys.path.insert(0, os.path.abspath("."))
import config as C

ATTACKER_PORT = 8125
PAGE = b"""<!doctype html><html><body>
<form id="f" method="POST" action="http://localhost:8010/api/run-b" enctype="text/plain">
<input name='{"prompt":"attacker","x":"' value='"}'></form>
<script>
fetch("http://localhost:8010/api/run-b",{method:"POST",mode:"no-cors",credentials:"include",
  headers:{"Content-Type":"text/plain"},body:JSON.stringify({prompt:"attacker"})});
setTimeout(()=>document.getElementById("f").submit(),800);
</script></body></html>"""


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200); self.send_header("Content-Type", "text/html"); self.end_headers(); self.wfile.write(PAGE)

    def log_message(self, *a):
        pass


srv = http.server.HTTPServer(("127.0.0.1", ATTACKER_PORT), H)
threading.Thread(target=srv.serve_forever, daemon=True).start()
out, ok = {}, True
with sync_playwright() as p:
    b = p.chromium.launch(channel="chrome", headless=True); ctx = b.new_context(); pg = ctx.new_page()
    pg.goto("http://localhost:8010/login?back=liveb")
    pg.wait_for_selector("input[name='identifier'], input[name='credentials.passcode']", timeout=30000)
    if pg.locator("input[name='identifier']").count():
        pg.fill("input[name='identifier']", "ada.lovelace@example.com"); pg.locator("input[type='submit']").first.click()
    pg.wait_for_selector("input[name='credentials.passcode']", timeout=30000)
    pg.fill("input[name='credentials.passcode']", C.required("DEMO_USER_PASSWORD")); pg.locator("input[type='submit']").first.click()
    pg.wait_for_url("http://localhost:8010/**", timeout=30000); pg.wait_for_timeout(1500)
    st = pg.evaluate("fetch('/api/status').then(r=>r.json())")
    out["own page: signed in, CSRF token present"] = bool(st.get("user")) and bool(st.get("csrf"))
    seen = []
    ev = ctx.new_page()
    ev.on("response", lambda r: seen.append((r.request.method, r.url, r.status)) if "/api/run-b" in r.url else None)
    ev.goto(f"http://localhost:{ATTACKER_PORT}/"); ev.wait_for_timeout(4000)
    out["other localhost port -> /api/run-b"] = [f"{m} {s}" for m, _, s in seen]
    # same origin, cookie, JSON, but no CSRF token
    r = pg.evaluate("fetch('/api/run-b',{method:'POST',headers:{'Content-Type':'application/json'},body:'{\"prompt\":\"x\"}'}).then(r=>r.status)")
    out["own origin, no CSRF token"] = r
    b.close()
srv.shutdown()
out["foreign Host header (DNS rebinding)"] = requests.get("http://127.0.0.1:8010/api/status", headers={"Host": "rebind.example:8010"}, timeout=10).status_code
out["normal Host"] = requests.get("http://127.0.0.1:8010/api/status", timeout=10).status_code
checks = [out["own page: signed in, CSRF token present"] is True,
          len(out["other localhost port -> /api/run-b"]) >= 1 and all(x.split()[1] in ("403", "415") for x in out["other localhost port -> /api/run-b"]),
          out["own origin, no CSRF token"] == 403, out["foreign Host header (DNS rebinding)"] == 403, out["normal Host"] == 200]
for k, v in out.items():
    print(f"{k:42s} {v}")
ok = all(checks)
print("PASS" if ok else "FAIL")
(C.ROOT / "build" / "console-csrf-check.json").write_text(json.dumps({**out, "pass": ok}, indent=1))
sys.exit(0 if ok else 1)
