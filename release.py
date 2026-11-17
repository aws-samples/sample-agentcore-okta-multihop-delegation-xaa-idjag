"""Helpers the stacks share: Cedar policy sync and the Runtime waiter."""
import time

import config as C

# ---- Cedar ------------------------------------------------------------------------

def _policies(ac, pe_id):
    out, tok = [], None
    while True:
        kw = {"policyEngineId": pe_id, "maxResults": 100}
        if tok:
            kw["nextToken"] = tok
        r = ac.list_policies(**kw)
        out += r.get("policies", [])
        tok = r.get("nextToken")
        if not tok:
            return out


def apply_policies(ac, pe_id, wanted, prefix):
    """Make the engine's policies with this prefix exactly `wanted` (name -> cedar)."""
    have = {p["name"]: p for p in _policies(ac, pe_id) if p["name"].startswith(prefix)}
    for name, p in have.items():
        if name not in wanted:
            ac.delete_policy(policyEngineId=pe_id, policyId=p["policyId"])
    for name, stmt in wanted.items():
        if name in have:
            ac.update_policy(policyEngineId=pe_id, policyId=have[name]["policyId"],
                             definition={"cedar": {"statement": stmt}}, validationMode="FAIL_ON_ANY_FINDINGS")
        else:
            ac.create_policy(policyEngineId=pe_id, name=name, definition={"cedar": {"statement": stmt}},
                             validationMode="FAIL_ON_ANY_FINDINGS")
    for _ in range(60):
        cur = [p for p in _policies(ac, pe_id) if p["name"].startswith(prefix)]
        bad = [p for p in cur if p.get("status") in ("CREATE_FAILED", "UPDATE_FAILED")]
        if bad:
            raise RuntimeError(f"policy failed: {bad[0]['name']}: {bad[0].get('statusReasons')}")
        if {p["name"] for p in cur} == set(wanted) and all(p.get("status") == "ACTIVE" for p in cur):
            return
        time.sleep(2)
    raise RuntimeError("policies did not become ACTIVE")


# ---- Runtime ------------------------------------------------------------------------

def wait_runtime(ac, rid):
    for _ in range(120):
        r = ac.get_agent_runtime(agentRuntimeId=rid)
        if r["status"] == "READY":
            return r
        if "FAIL" in r["status"]:
            raise RuntimeError(f"runtime {rid} {r['status']}: {r.get('failureReason')}")
        time.sleep(5)
    raise RuntimeError("runtime not READY")
