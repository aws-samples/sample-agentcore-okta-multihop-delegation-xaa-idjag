"""Create the signing keys in AWS KMS, restrict who may sign with each, and print their public
JWKs for Okta.

Okta never holds a private key in this demo. Each Okta client that signs a client assertion
(private_key_jwt) gets an asymmetric KMS key; you paste the key's PUBLIC half into Okta.

Whoever can call kms:Sign with a key can act as that Okta client, so each key has its own key
policy instead of the default (which lets any IAM principal with broad KMS rights sign):

  key                        Okta client                     may sign
  alias/anyco-agent-b        anyco-pr-review-agent-b-oai     Runtime B's role, the console operator
  alias/anyco-backend-agent  anyco-backend-agent-oai         the console operator (your backend runs in the console)
  alias/anyco-event-source   anyco-event-source-app          the trigger Lambda's role
  alias/anyco-event-agent    anyco-event-agent-oai           the event agent's role

The console operator is the AWS identity the console and test scripts run as (ANYCO_AWS_PROFILE).
It signs for the backend and for Scenario A1 / scripts/xaa_test.py. --operator-test also lets it
sign with the two Pattern C keys, for scripts/event_test.py; leave it off otherwise.

Every key also keeps an administration statement for the account root: manage, read the public
key, rotate, schedule deletion, change the key policy. It doesn't include kms:Sign. Changing the
key policy is the recovery path, and it shows in CloudTrail.

A role that doesn't exist yet is added when deploy.py runs this again after the stacks.
Safe to re-run: an existing key (found by alias) is reused, and its policy is replaced.
The JWKs are also written to build/jwks/<name>.json.

    .venv/bin/python kms_keys.py [--operator-test]
"""
import base64
import json
import sys

from cryptography.hazmat.primitives.serialization import load_der_public_key

import config as C

OPERATOR = "operator"
KEYS = {   # name -> (alias, suggested kid, what uses it, roles that may sign)
    "anyco-pr-review-agent-b": ("alias/anyco-agent-b", "anyco-pr-review-agent-b-kms", "AI agent · Pattern B (the agent)",
                                ["anyco-agentid-runtime-xaa-role", OPERATOR]),
    "anyco-backend-agent": ("alias/anyco-backend-agent", "anyco-backend-agent-kms", "your backend as an AI agent · Pattern B",
                            [OPERATOR]),
    "anyco-event-source": ("alias/anyco-event-source", "anyco-event-source-kms", "service app · Pattern C",
                           ["anyco-event-trigger-role"]),
    "anyco-event-agent": ("alias/anyco-event-agent", "anyco-event-agent-kms", "AI agent · Pattern C",
                          ["anyco-event-agent-role"]),
}
TEST_ONLY = ("anyco-event-source", "anyco-event-agent")   # the operator signs with these only with --operator-test
ADMIN_ACTIONS = ["kms:Create*", "kms:Describe*", "kms:Enable*", "kms:List*", "kms:Put*", "kms:Update*", "kms:Revoke*",
                 "kms:Disable*", "kms:Get*", "kms:Delete*", "kms:TagResource", "kms:UntagResource",
                 "kms:ScheduleKeyDeletion", "kms:CancelKeyDeletion", "kms:RotateKeyOnDemand"]


def b64(n):
    return base64.urlsafe_b64encode(n.to_bytes((n.bit_length() + 7) // 8, "big")).rstrip(b"=").decode()


def operator_arn():
    """The IAM role (or user) the console runs as. ANYCO_KMS_OPERATOR_ARN overrides it."""
    if C.os.environ.get("ANYCO_KMS_OPERATOR_ARN"):
        return C.os.environ["ANYCO_KMS_OPERATOR_ARN"]
    arn = C.session().client("sts").get_caller_identity()["Arn"]
    if ":assumed-role/" in arn:                     # arn:aws:sts::<acct>:assumed-role/<role>/<session>
        return C.session().client("iam").get_role(RoleName=arn.split("/")[1])["Role"]["Arn"]
    return arn


def role_arn(name):
    iam = C.session().client("iam")
    try:
        return iam.get_role(RoleName=name)["Role"]["Arn"]
    except iam.exceptions.NoSuchEntityException:
        return None


def key_policy(signers):
    stmts = [{"Sid": "KeyAdministrationNotSigning", "Effect": "Allow",
              "Principal": {"AWS": f"arn:aws:iam::{C.ACCOUNT}:root"}, "Action": ADMIN_ACTIONS, "Resource": "*"}]
    if signers:
        stmts.append({"Sid": "SignAsTheOktaClient", "Effect": "Allow", "Principal": {"AWS": sorted(signers)},
                      "Action": "kms:Sign", "Resource": "*"})
    return {"Version": "2012-10-17", "Statement": stmts}


def ensure(alias, description):
    kms = C.session().client("kms")
    try:
        key_id = kms.describe_key(KeyId=alias)["KeyMetadata"]["KeyId"]
    except kms.exceptions.NotFoundException:
        key_id = kms.create_key(KeySpec="RSA_2048", KeyUsage="SIGN_VERIFY", Description=description,
                                Tags=[{"TagKey": "project", "TagValue": "anyco-agentid"}])["KeyMetadata"]["KeyId"]
        kms.create_alias(AliasName=alias, TargetKeyId=key_id)
    arn = kms.describe_key(KeyId=key_id)["KeyMetadata"]["Arn"]
    pub = load_der_public_key(kms.get_public_key(KeyId=key_id)["PublicKey"]).public_numbers()
    return key_id, arn, {"kty": "RSA", "alg": "RS256", "use": "sig", "e": b64(pub.e), "n": b64(pub.n)}


def apply_policies(operator_test=False):
    """Replace each key's policy with its signers. Yields a line per key."""
    kms = C.session().client("kms")
    op = operator_arn()
    for name, (alias, _, _, roles) in KEYS.items():
        signers, pending = [], []
        for r in roles:
            if r == OPERATOR:
                signers.append(op)
            elif (a := role_arn(r)):
                signers.append(a)
            else:
                pending.append(r)
        if operator_test and name in TEST_ONLY:
            signers.append(op)
        key_id = kms.describe_key(KeyId=alias)["KeyMetadata"]["KeyId"]
        kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=json.dumps(key_policy(signers)))
        who = ", ".join(s.split(":")[-1] for s in sorted(signers)) or "nobody"
        yield f"{alias}: kms:Sign only for {who}" + (f" (added on deploy: {', '.join(pending)})" if pending else "")


def main():
    out = C.ROOT / "build" / "jwks"
    out.mkdir(parents=True, exist_ok=True)
    arns = {}
    for name, (alias, kid, used_by, _) in KEYS.items():
        _, arn, jwk = ensure(alias, f"Okta client-assertion signing key for {name} (private_key_jwt)")
        jwk = {**jwk, "kid": kid}
        (out / f"{name}.json").write_text(json.dumps(jwk, indent=2))
        arns[name] = arn
        print(f"\n== {name}  ({used_by})  KMS {alias}")
        print(json.dumps(jwk))
    C.save_state(kms=arns)
    print("\nKey policies:")
    for line in apply_policies("--operator-test" in sys.argv):
        print("  " + line)
    print(f"\nPublic JWKs also in {out}/. Paste each into Okta as described in docs/okta-setup.md.")


if __name__ == "__main__":
    main()
