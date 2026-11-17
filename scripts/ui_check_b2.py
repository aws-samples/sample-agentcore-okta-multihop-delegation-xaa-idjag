"""Pattern A in Chrome: Ada posts + lists, Alan lists; drawers."""
import os, json
from playwright.sync_api import sync_playwright
import sys; sys.path.insert(0, ".")
import config as C   # loads .env
PW=C.required("DEMO_USER_PASSWORD"); OUT="build/shots"
def sign_in(pg,user,back):
    pg.goto(f"http://localhost:8010/login?back={back}")
    pg.wait_for_selector("input[name='identifier'], input[name='credentials.passcode']", timeout=30000)
    if pg.locator("input[name='identifier']").count():
        pg.fill("input[name='identifier']", f"{user}@example.com"); pg.locator("input[type='submit']").first.click()
    pg.wait_for_selector("input[name='credentials.passcode']", timeout=30000)
    pg.fill("input[name='credentials.passcode']", PW); pg.locator("input[type='submit']").first.click()
    pg.wait_for_url("http://localhost:8010/**",timeout=30000); pg.wait_for_timeout(1500)
def run(pg,chips,label,status):
    pg.locator(f"{chips} button",has_text=label).click(); pg.wait_for_timeout(2000)
    pg.wait_for_function(f"() => ['done','failed','error'].includes(document.querySelector('{status}').textContent)",timeout=240000); pg.wait_for_timeout(1500)
with sync_playwright() as p:
    b=p.chromium.launch(channel="chrome",headless=True); pg=b.new_page(viewport={"width":1900,"height":1250})
    errs=[]; pg.on("pageerror",lambda e: errs.append(str(e)))
    pg.goto("http://localhost:8010/#explainb"); pg.wait_for_timeout(1500); pg.screenshot(path=f"{OUT}/b-explain.png")
    pg.locator("[data-xnode='exchange']").click(); pg.wait_for_timeout(1200); pg.screenshot(path=f"{OUT}/b-explain-exchange.png"); pg.keyboard.press("Escape")
    pg.goto("http://localhost:8010/#delegation"); pg.wait_for_timeout(800); pg.screenshot(path=f"{OUT}/b-delegation.png")
    sign_in(pg,"ada.lovelace","liveb")
    run(pg,"#prompt-chips-b","Post a review on #128 as me","#agui-status-b"); pg.screenshot(path=f"{OUT}/b-live-ada-post.png")
    print("ada post rows:", pg.evaluate("[...document.querySelectorAll('#chat-b [id^=t-]')].map(r=>r.innerText.replace(/\\n/g,' '))"))
    for n in ("exchange","b:interceptor","b:cedar"):
        pg.locator(f"#agui-svg-b .agui-node[data-node='{n}']").click(); pg.wait_for_timeout(1500)
        pg.screenshot(path=f"{OUT}/b-live-{n.replace(':','_')}.png"); pg.keyboard.press("Escape"); pg.wait_for_timeout(300)
    run(pg,"#prompt-chips-b","List my reviews","#agui-status-b")
    print("ada list:", pg.evaluate("[...document.querySelectorAll('#chat-b [id^=m-]')].map(e=>e.innerText).slice(-1)"))
    pg.goto("http://localhost:8010/logout"); pg.wait_for_url("http://localhost:8010/**", timeout=30000); pg.wait_for_timeout(1000)
    sign_in(pg,"alan.turing","liveb"); pg.evaluate("document.querySelector('#chat-b').innerHTML=''")
    run(pg,"#prompt-chips-b","List my reviews","#agui-status-b"); pg.screenshot(path=f"{OUT}/b-live-alan-list.png")
    print("alan list:", pg.evaluate("[...document.querySelectorAll('#chat-b [id^=m-]')].map(e=>e.innerText).slice(-1)"))
    print("JS errors:", errs or "none"); b.close()
