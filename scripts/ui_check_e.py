"""Pattern C in Chrome: explain drawers, publish an event, the live token drawers, Where B stops."""
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(channel="chrome", headless=True); pg = b.new_page(viewport={"width": 1900, "height": 1250})
    errs = []; pg.on("pageerror", lambda e: errs.append(str(e)))
    pg.goto("http://localhost:8010/#gapsb"); pg.wait_for_timeout(1200)
    print("where B stops:", pg.locator("#gapsb-cards").inner_text()[:120].replace("\n", " | "))
    pg.goto("http://localhost:8010/#event"); pg.wait_for_timeout(1200)
    for n in ("e:agent",):
        pg.locator(f"[data-xnode='{n}']").first.click(); pg.wait_for_timeout(2000)
        print(f"explain {n}:", pg.locator("#node-panel-body").inner_text()[:200].replace("\n", " | "))
        pg.keyboard.press("Escape")
    pg.goto("http://localhost:8010/#livee"); pg.wait_for_timeout(1500)
    pg.locator("#btn-publish").click()
    pg.wait_for_function("() => /done|✗/.test(document.querySelector('#ev-status').textContent)", timeout=240000)
    pg.wait_for_timeout(1500)
    print("status:", pg.locator("#ev-status").inner_text()); print("answer:", pg.locator("#ev-answer").inner_text()[:200])
    print("ticker:", pg.locator("#agui-ticker-e").inner_text())
    for n in ("e:t1", "e:jag", "e:token", "e:mcp"):
        pg.locator(f"#agui-svg-e .agui-node[data-node='{n}']").first.click(); pg.wait_for_timeout(1200)
        t = pg.locator("#node-panel-body").inner_text(); i = t.upper().find("WHO IS WHO")
        print(f"== live {n}\n" + (t[i:i + 700] if i >= 0 else t[:300]))
    pg.screenshot(path="build/shots/e-live.png")
    print("JS errors:", errs or "none"); b.close()
