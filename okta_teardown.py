"""Optional: delete the demo's Okta objects with the Okta Admin API (the "Clean up" list in
docs/okta-setup.md), instead of by hand. Needs OKTA_API_TOKEN in .env, like okta_setup.py.

    .venv/bin/python okta_teardown.py            list what it would delete, then ask
    .venv/bin/python okta_teardown.py --users    also delete the three demo users
    .venv/bin/python okta_teardown.py --yes      don't ask

It finds objects by their demo names only (anyco-*, and the demo users with --users); nothing else in
your org is touched. It doesn't touch AWS: use teardown.py for that.
"""
import sys
import time

import okta_setup as O
from okta_setup import NAMES, WP, call, find_agent, find_app, find_as, find_group, find_user


def delete_agent(a):
    org = call("GET", "/api/v1/org")["id"]
    orn = f"orn:okta:directory:{org}:workload-principals:ai-agents:{a['id']}"
    for f in (f'to.resourceOrn eq "{orn}"', f'from.clientOrn eq "{orn}"'):     # delegation links to and from it
        try:
            found = call("GET", f"{WP}/delegation-links", params={"filter": f})
            links = [x for x in O.items(found) if isinstance(x, dict) and "from" in x] + \
                    [l for x in O.items(found) if isinstance(x, dict) for v in x.values() if isinstance(v, list)
                     for l in v if isinstance(l, dict) and "from" in l]
            for link in links:
                call("DELETE", f"{WP}/delegation-links/{link['id']}")
        except RuntimeError as e:
            print("    (delegation links:", str(e)[:120], ")")
    if a.get("status") == "ACTIVE":
        call("POST", f"{WP}/ai-agents/{a['id']}/lifecycle/deactivate")
    for i in range(10):                                   # deactivation takes a moment
        try:
            return call("DELETE", f"{WP}/ai-agents/{a['id']}")
        except RuntimeError:
            if i == 9:
                raise
            time.sleep(3)


def main():
    plan = []
    for n in NAMES["AI agents"]:
        if (a := find_agent(n)):
            plan.append(("AI agent", n, lambda a=a: delete_agent(a)))
    for n in NAMES["apps"]:
        if (a := find_app(n)):
            plan.append(("app", n, lambda a=a: (a["status"] == "ACTIVE" and call("POST", f"/api/v1/apps/{a['id']}/lifecycle/deactivate"),
                                                 call("DELETE", f"/api/v1/apps/{a['id']}"))))
    for n in NAMES["authorization servers"]:
        if (a := find_as(n)):
            plan.append(("authorization server", n, lambda a=a: (call("POST", f"/api/v1/authorizationServers/{a['id']}/lifecycle/deactivate"),
                                                                  call("DELETE", f"/api/v1/authorizationServers/{a['id']}"))))
    if (g := find_group(NAMES["group"])):
        plan.append(("group", NAMES["group"], lambda g=g: call("DELETE", f"/api/v1/groups/{g['id']}")))
    if "--users" in sys.argv:
        for login in NAMES["users"]:
            if (u := find_user(login)):
                plan.append(("user", login, lambda u=u: (call("POST", f"/api/v1/users/{u['id']}/lifecycle/deactivate"),
                                                          call("DELETE", f"/api/v1/users/{u['id']}"))))
    if not plan:
        return print("Nothing to delete: none of the demo's Okta objects exist.")
    print(f"This deletes from {O.BASE}:")
    for kind, name, _ in plan:
        print(f"  {kind} {name}")
    if "--yes" not in sys.argv and input("Type 'delete' to go on: ").strip() != "delete":
        return print("Nothing deleted.")
    for kind, name, run in plan:
        try:
            run()
            print(f"  deleted  {kind} {name}")
        except RuntimeError as e:
            print(f"  FAILED   {kind} {name}: {str(e)[:200]}")


if __name__ == "__main__":
    main()
