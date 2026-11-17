"""Cross App Access in Chrome: explain drawers, Ada signs in to the agent's app, posts + lists
(delegated), merge refused; live drawers; UML C; Pattern A regression."""
import os
from playwright.sync_api import sync_playwright
import sys; sys.path.insert(0, ".")
import config as C   # loads .env
PW=C.required("DEMO_USER_PASSWORD"); OUT="build/shots"; os.makedirs(OUT,exist_ok=True)
def sign_in(pg,user,url):
    pg.goto(url)
    pg.wait_for_selector("input[name='identifier'], input[name='credentials.passcode']", timeout=30000)
    if pg.locator("input[name='identifier']").count():
        pg.fill("input[name='identifier']", f"{user}@example.com"); pg.locator("input[type='submit']").first.click()
    pg.wait_for_selector("input[name='credentials.passcode']", timeout=30000)
    pg.fill("input[name='credentials.passcode']", PW); pg.locator("input[type='submit']").first.click()
    pg.wait_for_url("http://localhost:8010/**",timeout=30000); pg.wait_for_timeout(1500)
def run(pg,chips,label,status):
    pg.locator(f"{chips} button",has_text=label).click(); pg.wait_for_timeout(2000)
    pg.wait_for_function(f"() => ['done','failed','error'].includes(document.querySelector('{status}').textContent)",timeout=240000); pg.wait_for_timeout(2000)
rows="[...document.querySelectorAll('#chat-c [id^=t-]')].map(r=>r.innerText.replace(/\\n/g,' '))"
last="[...document.querySelectorAll('#chat-c [id^=m-]')].map(e=>e.innerText).slice(-1)"
with sync_playwright() as p:
    b=p.chromium.launch(channel="chrome",headless=True); pg=b.new_page(viewport={"width":1900,"height":1250})
    errs=[]; pg.on("pageerror",lambda e: errs.append(str(e)))
    pg.goto("http://localhost:8010/#delegation"); pg.wait_for_timeout(1500); pg.screenshot(path=f"{OUT}/c-explain.png")
    for n in ("c:okta","c:t1","c:bstep1","c:bstep2","c:t2","c:agent","c:step1","c:step2","c:token","c:interceptor","c:cedar","c:tools"):
        pg.locator(f"#xflowc [data-xnode='{n}'], #xlegendc [data-xnode='{n}']").first.click(); pg.wait_for_timeout(900)
        t=pg.locator("#node-panel-body").inner_text(); print(f"explain {n}: {t.splitlines()[0][:70]} … {len(t)} chars")
        pg.keyboard.press("Escape"); pg.wait_for_timeout(250)
    sign_in(pg,"ada.lovelace","http://localhost:8010/login?back=livec")
    print("signin row:", pg.locator("#signin-row-c").inner_text().replace("\n"," "))
    run(pg,"#prompt-chips-c","Post a review on #128 for me","#agui-status-c"); pg.screenshot(path=f"{OUT}/c-live-ada-post.png")
    print("ada post rows:", pg.evaluate(rows)); print("ticker:", pg.locator("#agui-ticker-c").inner_text())
    for n in ("c:t1","c:backend","c:t2","c:step1","c:idjag","c:step2","c:token","c:interceptor","c:cedar","c:agent","okta"):
        pg.locator(f"#agui-svg-c .agui-node[data-node='{n}']").first.click(); pg.wait_for_timeout(1800)
        t=pg.locator("#node-panel-body").inner_text(); print(f"live {n}: {t.splitlines()[0][:60]} … {len(t)} chars · act={'act' in t}")
        pg.screenshot(path=f"{OUT}/c-live-{n.replace(':','_')}.png"); pg.keyboard.press("Escape"); pg.wait_for_timeout(300)
    run(pg,"#prompt-chips-c","List my reviews","#agui-status-c"); print("ada list:", pg.evaluate(last))
    run(pg,"#prompt-chips-c","Merge PR #128","#agui-status-c"); print("merge rows:", pg.evaluate(rows)[-1:], pg.evaluate(last))
    pg.goto("http://localhost:8010/#gapsb"); pg.wait_for_timeout(1200)
    pg.screenshot(path=f"{OUT}/c-gapsb.png"); print("where B stops:", pg.locator("#gapsb-cards").inner_text()[:160].replace("\n"," | "))
    print("JS errors:", errs or "none"); b.close()
