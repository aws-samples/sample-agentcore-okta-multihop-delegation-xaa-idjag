"""Deploy the whole demo to AWS in one go (safe to re-run; each step updates what exists).

  1. package   build_agent.sh, build_event.sh       (skip with --skip-build)
  2. stack     shared base: table, tool + interceptor Lambdas, policy engine, code bucket
  3. stack_a   Pattern A · OBO/Delegation (token exchange): the Gateway, token-exchange provider, Runtime A
  4. stack_b   Pattern B · Cross App Access (user): AgentCore Identity providers, Runtime B
  5. stack_c   Pattern C · Cross App Access (machine): partner MCP Runtime, event agent Runtime, SNS + trigger Lambda
  6. kms_keys   each signing key's policy: only its role (or the console operator) may sign. During the
                deploy the deployer may sign with every key (AgentCore Identity checks it when a
                PRIVATE_KEY_JWT provider is created or updated); the last step takes that away.

Patterns whose Okta values aren't in state.json (okta_values.py) are skipped.
Usage: .venv/bin/python deploy.py [--skip-build]
"""
import subprocess
import sys
import time

import config as C


def run(name, gen):
    t0 = time.time()
    print(f"\n== {name}", flush=True)
    for line in gen():
        print(f"   {line}", flush=True)
    print(f"   ({int(time.time() - t0)} s)", flush=True)


def main():
    st = C.state()
    if not st.get("okta"):
        sys.exit("No Okta values yet: follow docs/okta-setup.md, then run okta_values.py")
    if "--skip-build" not in sys.argv:
        print("== ./build_agent.sh", flush=True)
        subprocess.run(["./build_agent.sh"], cwd=C.ROOT, check=True)     # the repo's own build scripts, no input
        print("== ./build_event.sh", flush=True)
        subprocess.run(["./build_event.sh"], cwd=C.ROOT, check=True)

    import stack, stack_a, stack_b, stack_c
    import kms_keys
    # AgentCore Identity checks that whoever creates or updates a PRIVATE_KEY_JWT provider may sign
    # with its KMS key. So the deployer may sign with all four keys while the stacks deploy; the last
    # step puts back the per-key policies. If a deploy fails before that, run it again.
    run("KMS key policies: the deployer may sign during this deploy", lambda: kms_keys.apply_policies(operator_test=True))
    run("shared base (stack.py)", stack.deploy)
    run("Pattern A · OBO/Delegation, token exchange (stack_a.py)", stack_a.deploy)
    if st.get("xaa"):
        run("Pattern B · Cross App Access, user (stack_b.py)", stack_b.deploy)
    else:
        print("\n== Pattern B skipped: no OKTA_AGENT_B_* values in state.json")
    if st.get("event"):
        run("Pattern C · Cross App Access, machine (stack_c.py)", stack_c.deploy)
    else:
        print("\n== Pattern C skipped: no OKTA_EVENT_* values in state.json")
    # the roles exist now: only they (and the console operator, for its two keys) may sign
    run("KMS key policies: back to one signer per key", kms_keys.apply_policies)
    print("\nDone. Start the console: ./run.sh  (http://localhost:8010)")


if __name__ == "__main__":
    main()
