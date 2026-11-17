"""Evidence for the KMS key policies: who may sign with each key, and a real kms:Sign attempt as the
console operator (ANYCO_AWS_PROFILE).

Expected: the operator signs with the backend and agent-b keys, and is refused (AccessDenied) for
the two Pattern C keys, though it is an account admin with kms:* in IAM. The roles' own signing is
shown by running Patterns B and C end to end (scripts/ui_check_c.py, scripts/ui_check_e.py).
Writes build/kms-sign-check.json.
"""
import hashlib
import json
import os
import sys

sys.path.insert(0, os.path.abspath("."))
import config as C
import kms_keys

kms = C.session().client("kms")
op = kms_keys.operator_arn()
expect_op = {name: kms_keys.OPERATOR in roles for name, (_, _, _, roles) in kms_keys.KEYS.items()}
results, ok = [], True
print(f"operator: {op.split(':')[-1]}")
for name, (alias, _, _, _) in kms_keys.KEYS.items():
    key_id = kms.describe_key(KeyId=alias)["KeyMetadata"]["KeyId"]
    pol = json.loads(kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"])
    signers = [p for s in pol["Statement"] if "kms:Sign" in ([s["Action"]] if isinstance(s["Action"], str) else s["Action"])
               for p in ([s["Principal"]["AWS"]] if isinstance(s["Principal"]["AWS"], str) else s["Principal"]["AWS"])]
    admin_has_sign = any(s["Sid"] == "KeyAdministrationNotSigning" and "kms:Sign" in s["Action"] for s in pol["Statement"])
    try:
        kms.sign(KeyId=key_id, Message=hashlib.sha256(b"kms policy check").digest(), MessageType="DIGEST",
                 SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256")
        got = "allowed"
    except kms.exceptions.ClientError as e:
        got = e.response["Error"]["Code"]
    grants = kms.list_grants(KeyId=key_id).get("Grants", [])           # grants are another way to allow kms:Sign
    sign_grants = [g.get("GranteePrincipal", "?").split(":")[-1] for g in grants if "Sign" in g.get("Operations", [])]
    want = "allowed" if expect_op[name] else "AccessDeniedException"
    passed = got == want and not admin_has_sign and not sign_grants
    ok &= passed
    results.append({"key": alias, "kms_sign_principals": [s.split(":")[-1] for s in signers],
                    "account_admin_statement_includes_sign": admin_has_sign, "grants_allowing_sign": sign_grants,
                    "operator_sign": got, "expected": want, "pass": passed})
    print(f"{'PASS' if passed else 'FAIL'}  {alias:27s} sign: {', '.join(s.split(':')[-1] for s in signers):55s} operator: {got}{'  GRANTS: ' + ', '.join(sign_grants) if sign_grants else ''}")
(C.ROOT / "build" / "kms-sign-check.json").write_text(json.dumps({"operator": op.split(":")[-1], "results": results}, indent=1))
sys.exit(0 if ok else 1)
