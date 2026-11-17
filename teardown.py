"""Delete everything the demo created in AWS.

Usage: python teardown.py [--patterns | --keys]
--patterns removes only the pattern resources (the Runtimes, the Gateway, the AgentCore Identity
providers, SNS and the trigger Lambda, the Cedar permits) and keeps the shared base, so a redeploy
is quick.
--keys also schedules the KMS signing keys for deletion (7-day recovery window). Without it
they are kept, so the public keys you registered in Okta stay valid for a redeploy.
Okta objects are yours to remove by hand: docs/okta-setup.md lists them ("Clean up").
"""
import sys
import time

import config as C
import release as R

S = C.session()
ac, lam, iam, ddb, s3, logs, sm = (S.client(x) for x in ("bedrock-agentcore-control", "lambda", "iam", "dynamodb", "s3", "logs",
                                                         "secretsmanager"))
st = C.state()


def quiet(fn, *a, **k):
    try:
        return fn(*a, **k)
    except Exception as e:
        print("  skip:", str(e)[:120])


import stack_c                 # Pattern C (event-triggered): SNS, trigger Lambda, two Runtimes

if "--patterns" in sys.argv:
    import stack_a, stack_b
    for gen in (stack_c.destroy, stack_b.destroy, stack_a.destroy):
        for line in gen():
            print(line)
    print("Pattern resources removed; the shared base is kept. Redeploy: .venv/bin/python deploy.py")
    sys.exit(0)

for line in stack_c.destroy():
    print(line)
st = C.state()

for key in ("runtime_b_id", "runtime_c_id"):
    rid = st.get(key)
    if rid:
        quiet(ac.delete_agent_runtime, agentRuntimeId=rid)
        print("runtime", rid)

for gid in filter(None, (st.get("gateway_b_id"),)):
    for t in (quiet(ac.list_gateway_targets, gatewayIdentifier=gid, maxResults=100) or {}).get("items", []):
        quiet(ac.delete_gateway_target, gatewayIdentifier=gid, targetId=t["targetId"])
    time.sleep(10)
    quiet(ac.delete_gateway, gatewayIdentifier=gid)
    print("gateway", gid)

if st.get("policy_engine_id"):
    pe = st["policy_engine_id"]
    for p in R._policies(ac, pe):
        quiet(ac.delete_policy, policyEngineId=pe, policyId=p["policyId"])
    time.sleep(10)
    quiet(ac.delete_policy_engine, policyEngineId=pe)
    print("policy engine", pe)

for name in (C.N["obo_provider"], "anyco-xaa-step1", "anyco-xaa-step2"):
    quiet(ac.delete_oauth2_credential_provider, name=name)
quiet(ac.delete_workload_identity, name="anyco-xaa-identity-test")
quiet(ac.delete_workload_identity, name=C.N["console_workload"])
for fn in (C.N["tools_fn"], C.N["interceptor_fn"]):
    quiet(lam.delete_function, FunctionName=fn)
for role in (C.N["lambda_role"], C.N["gateway_role"], "anyco-agentid-runtime-obo-role",
             "anyco-agentid-runtime-xaa-role", stack_c.AGENT_ROLE, stack_c.MCP_ROLE, stack_c.GW_ROLE, stack_c.TRIGGER_ROLE):
    quiet(iam.delete_role_policy, RoleName=role, PolicyName="main")
    quiet(iam.delete_role, RoleName=role)
quiet(ddb.delete_table, TableName=C.N["table"])
b = C.N["code_bucket"]
for o in (quiet(s3.list_objects_v2, Bucket=b) or {}).get("Contents", []):
    quiet(s3.delete_object, Bucket=b, Key=o["Key"])
quiet(s3.delete_bucket, Bucket=b)
print("AWS side removed")

if "--keys" in sys.argv:
    kms = S.client("kms")
    import kms_keys
    # every key kms_keys.py creates, plus alias/anyco-xaa-agent from an earlier version of Pattern B
    for alias in [a for a, _, _ in kms_keys.KEYS.values()] + ["alias/anyco-xaa-agent"]:
        try:
            key = kms.describe_key(KeyId=alias)["KeyMetadata"]["KeyId"]
        except kms.exceptions.NotFoundException:
            continue
        quiet(kms.delete_alias, AliasName=alias)
        quiet(kms.schedule_key_deletion, KeyId=key, PendingWindowInDays=7)
        print("KMS key", alias, "scheduled for deletion (7-day recovery window)")
    st = C.state(); st.pop("kms", None); C.STATE_FILE.write_text(__import__("json").dumps(st, indent=2))
print("Okta objects are not touched: remove them by hand (docs/okta-setup.md, Clean up).")
