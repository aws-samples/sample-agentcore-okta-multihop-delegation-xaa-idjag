"""Draws the diagrams for docs/token-flows.md as SVG and PNG (needs rsvg-convert).

    python3 docs/images/make_token_flows.py
"""
import subprocess
from html import escape
from pathlib import Path

OUT = Path(__file__).parent / "token-flows"
W = 1200
FS = 20                       # smallest text on a 1200 px canvas
LH = 34                       # line height
SANS = "Helvetica, Arial, sans-serif"
MONO = "Menlo, Consolas, monospace"
INK, GREY, BLUE, GREEN, ORANGE, NAVY = "#16191f", "#5f6b7a", "#0972d3", "#037f0c", "#ec7211", "#232f3e"


def width(text, mono=False, fs=FS):
    return len(text) * fs * (0.61 if mono else 0.56)


def t(x, y, s, fs=FS, fill=INK, mono=False, weight="normal", anchor="start"):
    s = s.replace("  ", "\u00a0\u00a0")                 # keep indents (SVG collapses spaces)
    return (f'<text x="{x:.0f}" y="{y:.0f}" font-family="{MONO if mono else SANS}" font-size="{fs}" '
            f'font-weight="{weight}" fill="{fill}" text-anchor="{anchor}">{escape(s)}</text>')


def card(x, y, w, title, color, rows, dots=True):
    """rows: (name, value, kind) with kind 'req' | 'opt' | 'claim' | 'note'. Returns (svg, height)."""
    out, cy, pad = [], y + 74, 22
    for name, value, kind in rows:
        tx = x + pad + (26 if dots and kind in ("req", "opt") else 0)
        if kind == "req" and dots:
            out.append(f'<circle cx="{x + pad + 8}" cy="{cy - 7}" r="7" fill="{ORANGE}"/>')
        elif kind == "opt" and dots:
            out.append(f'<circle cx="{x + pad + 8}" cy="{cy - 7}" r="6" fill="white" stroke="{GREY}" stroke-width="2"/>')
        if kind == "note":
            out.append(t(tx, cy, name, fill=GREY))
            cy += LH
            continue
        mono_fill = INK if kind in ("req", "claim") else GREY
        out.append(t(tx, cy, name, mono=True, fill=mono_fill, weight="bold" if kind == "req" else "normal"))
        if value:
            vx = tx + width(name, mono=True) + 14
            if vx + width(value) > x + w - pad:          # no room: the value goes on its own line
                cy += LH - 4
                vx = tx + 20
            out.append(t(vx, cy, value, fill=GREY))
        cy += LH
    h = cy - y - LH + 26
    box = (f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="white" stroke="{color}" stroke-width="2.5"/>'
           f'<rect x="{x}" y="{y}" width="{w}" height="40" rx="14" fill="{color}"/>'
           f'<rect x="{x}" y="{y + 26}" width="{w}" height="14" fill="{color}"/>'
           + t(x + pad, y + 28, title, fill="white", weight="bold"))
    return box + "".join(out), h


def server(x, y, w, h, lines):
    out = [f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="14" fill="{NAVY}"/>']
    cy = y + h / 2 - (len(lines) - 1) * LH / 2 + 7
    for i, s in enumerate(lines):
        out.append(t(x + w / 2, cy + i * LH, s, fill="white", weight="bold" if i < len(lines) - 1 else "normal",
                     anchor="middle", mono=(i == len(lines) - 1 and s.startswith(("POST", "GET")))))
    return "".join(out)


def arrow(x1, y1, x2, y2, color=GREY):
    return (f'<line x1="{x1}" y1="{y1}" x2="{x2 - 10}" y2="{y2}" stroke="{color}" stroke-width="3"/>'
            f'<polygon points="{x2},{y2} {x2 - 14},{y2 - 8} {x2 - 14},{y2 + 8}" fill="{color}"/>')


def legend(y):
    return (f'<circle cx="38" cy="{y - 7}" r="7" fill="{ORANGE}"/>' + t(54, y, "required", fill=GREY)
            + f'<circle cx="160" cy="{y - 7}" r="6" fill="white" stroke="{GREY}" stroke-width="2"/>' + t(176, y, "optional", fill=GREY))


def checks(y, items):
    out = [t(30, y, "The server checks", weight="bold", fill=NAVY)]
    for i, s in enumerate(items):
        out.append(t(30, y + (i + 1) * LH, "✓  " + s, fill=INK))
    return "".join(out), LH * (len(items) + 1)


def flow(sends, srv, back, token=None, chk=(), top=20):
    """Client card → server → response card (+ the token's claims under it)."""
    L, SX, SW, R = (20, 530), 590, 180, (810, 370)
    left, lh = card(L[0], top, L[1], "The client sends", BLUE, sends)
    right, rh = card(R[0], top, R[1], "It gets back", GREEN, back, dots=False)
    parts = [left, right]
    if token:
        tok, th = card(R[0], top + rh + 18, R[1], token[0], NAVY, token[1], dots=False)
        parts.append(tok)
        rh += 18 + th
    h = max(lh, rh)
    sh = min(h, 220)
    sy = top + (lh - sh) / 2
    parts += [server(SX, sy, SW, sh, srv), arrow(L[0] + L[1] + 4, sy + sh / 2, SX - 4, sy + sh / 2),
              arrow(SX + SW + 4, sy + sh / 2, R[0] - 4, sy + sh / 2)]
    y = top + h + 40
    if chk:
        c, ch = checks(y, chk)
        parts.append(c)
        y += ch + 10
    parts.append(legend(y + 6))
    return "".join(parts), y + 30


def save(name, body, h):
    OUT.mkdir(parents=True, exist_ok=True)
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{h:.0f}" viewBox="0 0 {W} {h:.0f}">'
           f'<rect width="100%" height="100%" fill="white"/>{body}</svg>')
    (OUT / f"{name}.svg").write_text(svg)
    subprocess.run(["rsvg-convert", "-z", "2", "-o", str(OUT / f"{name}.png"), str(OUT / f"{name}.svg")], check=True)


CLIENT_AUTH = ("+ client authentication", "", "note")

# ---- overview: two ways to get a token for another server ----
def overview():
    p = []
    y1, y2, bh = 70, 290, 120
    p.append(t(20, 36, "Direct: the target server trusts the issuer of the token you hold", weight="bold", fill=NAVY))
    p.append(t(20, 256, "Cross App Access: the target trusts only the identity provider (IdP)", weight="bold", fill=NAVY))

    def pill(x, y, label, sub, color):
        return (f'<rect x="{x}" y="{y}" width="190" height="{bh}" rx="60" fill="white" stroke="{color}" stroke-width="3"/>'
                + t(x + 95, y + 54, label, weight="bold", anchor="middle") + t(x + 95, y + 86, sub, fill=GREY, anchor="middle"))

    def box(x, y, lines):
        return server(x, y, 210, bh, lines)

    p += [pill(20, y1, "Token A", "you hold it", BLUE), arrow(214, y1 + 60, 251, y1 + 60),
          box(255, y1, ["Target server", "token exchange"]), arrow(469, y1 + 60, 996, y1 + 60),
          pill(1000, y1, "Token B", "for the target", GREEN)]
    p += [pill(20, y2, "Token A", "you hold it", BLUE), arrow(214, y2 + 60, 251, y2 + 60),
          box(255, y2, ["IdP", "token exchange"]), arrow(469, y2 + 60, 506, y2 + 60),
          pill(510, y2, "ID-JAG", "names the target", ORANGE), arrow(704, y2 + 60, 741, y2 + 60),
          box(745, y2, ["Target server", "JWT bearer"]), arrow(959, y2 + 60, 996, y2 + 60),
          pill(1000, y2, "Token B", "for the target", GREEN)]
    save("overview", "".join(p), y2 + bh + 30)


def authcode():
    p = [t(20, 34, "Step 1 · the browser goes to the authorization server, and the user signs in", weight="bold", fill=NAVY)]
    a, ah = flow([("response_type", "code", "req"), ("client_id", "", "req"), ("redirect_uri", "", "req"),
                  ("scope", "e.g. openid profile", "req"), ("state", "random, checked on return", "opt"),
                  ("code_challenge", "SHA-256 of the verifier", "req"), ("code_challenge_method", "S256", "req")],
                 ["Authorization", "server", "GET /authorize"],
                 [("a redirect to redirect_uri with:", "", "note"), ("code", "one use, short-lived", "claim"), ("state", "the same value", "claim")],
                 top=56)
    p.append(a.split('<circle cx="38"')[0])                      # one legend, at the bottom
    y = ah + 10
    p.append(t(20, y + 14, "Step 2 · your backend trades the code for tokens", weight="bold", fill=NAVY))
    b, bh = flow([("grant_type", "authorization_code", "req"), ("code", "from step 1", "req"),
                  ("redirect_uri", "the same as step 1", "req"), ("code_verifier", "the secret behind the challenge", "req"),
                  CLIENT_AUTH],
                 ["Authorization", "server", "POST /token"],
                 [("access_token", "for the user", "claim"), ("id_token", "if scope has openid", "claim"),
                  ("refresh_token", "if allowed", "claim"), ("token_type", "Bearer", "claim"),
                  ("expires_in", "seconds", "claim"), ("scope", "what was granted", "claim")],
                 chk=["the user signed in, and may use this app",
                      "SHA-256(code_verifier) matches the code_challenge from step 1",
                      "the code is unused and fresh, and redirect_uri matches"],
                 top=y + 40)
    p.append(b)
    save("authorization-code", "".join(p), bh)


def client_credentials():
    body, h = flow([("grant_type", "client_credentials", "req"), ("scope", "what the app wants", "opt"),
                    ("resource", "which API (RFC 8707)", "opt"), CLIENT_AUTH],
                   ["Authorization", "server", "POST /token"],
                   [("access_token", "for the app itself", "claim"), ("token_type", "Bearer", "claim"),
                    ("expires_in", "seconds", "claim"), ("scope", "what was granted", "claim")],
                   token=("Inside the token", [("sub", "the app (no user)", "claim"), ("aud", "the API", "claim")]),
                   chk=["the client authenticated, and may use this grant", "a policy allows these scopes for this client"])
    save("client-credentials", body, h)


def exchange_access():
    body, h = flow([("grant_type", "…:token-exchange", "req"), ("subject_token", "the token you hold", "req"),
                    ("subject_token_type", "what it is", "req"), ("audience", "who the new token is for", "opt"),
                    ("resource", "or name the API by URL", "opt"), ("scope", "what to ask for", "opt"),
                    ("requested_token_type", "default: access token", "opt"),
                    ("actor_token (+_type)", "a separate actor", "opt"), CLIENT_AUTH],
                   ["Authorization", "server", "POST /token"],
                   [("access_token", "the new token", "claim"), ("issued_token_type", "…:access_token", "claim"),
                    ("token_type", "Bearer", "claim"), ("expires_in", "seconds", "claim"), ("scope", "what was granted", "claim")],
                   token=("Inside the new token", [("sub", "same as the subject", "claim"), ("aud", "the audience asked for", "claim"),
                                                   ("act", "the client that asked", "claim")]),
                   chk=["the subject token is valid, and its issuer is one this server trusts",
                        "the client may exchange tokens, for this audience and these scopes"])
    save("token-exchange", body, h)


def exchange_idjag():
    body, h = flow([("grant_type", "…:token-exchange", "req"), ("requested_token_type", "…:id-jag", "req"),
                    ("subject_token", "the user's token", "req"), ("subject_token_type", "what it is", "req"),
                    ("audience", "the target server's issuer URL", "req"), ("scope", "for the target", "opt"),
                    ("resource", "the target API", "opt"), CLIENT_AUTH],
                   ["Identity", "provider", "POST /token"],
                   [("access_token", "holds the ID-JAG", "claim"), ("issued_token_type", "…:id-jag", "claim"),
                    ("token_type", "N_A (not a bearer)", "claim"), ("expires_in", "seconds", "claim")],
                   token=("Inside the ID-JAG", [("typ", "oauth-id-jag+jwt", "claim"), ("iss", "the IdP", "claim"),
                                                ("aud", "the target server", "claim"), ("sub", "the user", "claim"),
                                                ("client_id", "who may redeem it", "claim"), ("scope", "granted", "claim")]),
                   chk=["the subject token is valid, and this client may act for its user",
                        "the client is allowed to reach the target server with these scopes"])
    save("token-exchange-id-jag", body, h)


def jwt_bearer():
    body, h = flow([("grant_type", "…:jwt-bearer", "req"), ("assertion", "the ID-JAG", "req"),
                    ("scope", "must fit the ID-JAG", "opt"), CLIENT_AUTH],
                   ["Target", "server", "POST /token"],
                   [("access_token", "for the target's API", "claim"), ("token_type", "Bearer", "claim"),
                    ("expires_in", "seconds", "claim"), ("scope", "what was granted", "claim")],
                   token=("Inside the token", [("iss", "the target server", "claim"), ("sub", "the user", "claim"),
                                               ("aud", "the target's API", "claim")]),
                   chk=["the assertion is signed by the IdP, names this server in aud, and is fresh",
                        "the client is the one the ID-JAG names in client_id"])
    save("jwt-bearer", body, h)


def client_auth():
    p, cw = [], 370
    cols = [("client_secret_basic", [("an HTTP header:", "", "note"), ("Authorization: Basic", "", "claim"),
                                     ("base64(id:secret)", "", "claim")]),
            ("client_secret_post", [("client_id", "", "claim"), ("client_secret", "", "claim"), ("form fields", "", "note")]),
            ("private_key_jwt", [("client_assertion_type", "", "claim"), ("  …:jwt-bearer", "", "note"),
                                 ("client_assertion", "", "claim"), ("  a JWT you sign:", "", "note"),
                                 ("  iss, sub", "client_id", "claim"), ("  aud", "the token URL", "claim"),
                                 ("  exp, jti", "short, one use", "claim")])]
    hs = []
    for i, (title, rows) in enumerate(cols):
        c, ch = card(20 + i * (cw + 25), 20, cw, title, [BLUE, BLUE, NAVY][i], rows, dots=False)
        p.append(c)
        hs.append(ch)
    y = 20 + max(hs) + 40
    c, ch = checks(y, ["a secret: it matches the one registered for the client",
                       "private_key_jwt: the signature verifies with the client's registered public key"])
    p.append(c)
    save("client-authentication", "".join(p), y + ch)


if __name__ == "__main__":
    for f in (overview, authcode, client_credentials, exchange_access, exchange_idjag, jwt_bearer, client_auth):
        f()
    print("wrote", sorted(x.name for x in OUT.iterdir()))
