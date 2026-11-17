"""Shared AWS helpers for the stacks: IAM roles, Lambda packaging, waiters, lookups, and the
tool schemas (two Gateway targets: mock GitHub and the context service). stack.py deploys the
shared base with them; stack_a.py, stack_b.py and stack_c.py add each pattern.
"""
import io
import json
import time
import zipfile

import config as C

S = C.session()
iam, lam, ddb, ac, logs = (S.client(x) for x in ("iam", "lambda", "dynamodb", "bedrock-agentcore-control", "logs"))
TAGS = {"project": "anyco-agentid"}
ACCT, REG = C.ACCOUNT, C.REGION


def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}", flush=True)


# ---- IAM ----------------------------------------------------------------------------

def role(name, service, statements):
    trust = {"Version": "2012-10-17", "Statement": [{
        "Effect": "Allow", "Principal": {"Service": service}, "Action": "sts:AssumeRole",
        **({"Condition": {"StringEquals": {"aws:SourceAccount": ACCT}}} if "agentcore" in service else {})}]}
    try:
        arn = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust),
                              Tags=[{"Key": k, "Value": v} for k, v in TAGS.items()])["Role"]["Arn"]
        time.sleep(10)  # IAM propagation before a service assumes it
    except iam.exceptions.EntityAlreadyExistsException:
        arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        iam.update_assume_role_policy(RoleName=name, PolicyDocument=json.dumps(trust))
    iam.put_role_policy(RoleName=name, PolicyName="main",
                        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}))
    return arn


# ---- Lambda -------------------------------------------------------------------------

def zipped(path, arcname):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(C.ROOT / path, arcname)
    return buf.getvalue()


def function(name, path, handler, role_arn, table):
    code = zipped(path, path.split("/")[-1])
    for attempt in range(6):
        try:
            arn = lam.create_function(FunctionName=name, Runtime="python3.12", Role=role_arn, Handler=handler,
                                      Code={"ZipFile": code}, Timeout=20, MemorySize=256, Architectures=["arm64"],
                                      Environment={"Variables": {"TABLE": table}}, Tags=TAGS)["FunctionArn"]
            break
        except lam.exceptions.ResourceConflictException:
            arn = lam.update_function_code(FunctionName=name, ZipFile=code)["FunctionArn"]
            break
        except lam.exceptions.InvalidParameterValueException as e:
            if "assume" in str(e) and attempt < 5:
                time.sleep(5)
                continue
            raise
    lam.get_waiter("function_updated_v2").wait(FunctionName=name)
    return arn


# ---- AgentCore helpers ----------------------------------------------------------------

def wait(getter, ok=("READY", "ACTIVE"), label=""):
    for _ in range(120):
        r = getter()
        st = r.get("status")
        if st in ok:
            return r
        if st and "FAIL" in st:
            raise RuntimeError(f"{label} {st}: {r.get('statusReasons') or r.get('failureReason')}")
        time.sleep(5)
    raise RuntimeError(f"{label} timed out")


def find_named(lister, key, name, field="name"):
    tok = None
    while True:
        kw = {"maxResults": 100}
        if tok:
            kw["nextToken"] = tok
        r = lister(**kw)
        for it in r.get(key, []):
            if it.get(field) == name:
                return it
        tok = r.get("nextToken")
        if not tok:
            return None


CALLER_SCHEMA = {"type": "object", "description": "Reserved. The Gateway's interceptor fills this from the "
                 "verified token (and the run id header); anything you send here is replaced.",
                 "properties": {"user": {"type": "string"}, "sub": {"type": "string"}, "client_id": {"type": "string"},
                                "scopes": {"type": "array", "items": {"type": "string"}},
                                "acting_agent": {"type": "string"},
                                "act_chain": {"type": "array", "items": {"type": "object", "properties": {
                                    "sub": {"type": "string"}, "sub_profile": {"type": "string"}}}},
                                "agent_id": {"type": "string"}, "run_id": {"type": "string"}}}


def tool(name, desc, props, required):
    return {"name": name, "description": desc,
            "inputSchema": {"type": "object", "properties": {**props, "caller": CALLER_SCHEMA}, "required": required}}


REPO = {"repo": {"type": "string", "description": "owner/name, e.g. anyco/receipts-service"},
        "number": {"type": "integer", "description": "pull request number"}}
GITHUB_TOOLS = [
    tool("get_pull_request", "Read a pull request: title, author, diff.", REPO, ["repo", "number"]),
    tool("post_review", "Post a review on a pull request.",
         {**REPO, "verdict": {"type": "string", "description": "APPROVE, COMMENT or REQUEST_CHANGES"},
          "body": {"type": "string"}}, ["repo", "number", "verdict", "body"]),
    tool("merge_pull_request", "Merge a pull request.", REPO, ["repo", "number"]),
    tool("list_my_reviews", "List reviews posted on behalf of the signed-in user.", {}, []),
]
CONTEXT_TOOLS = [
    tool("search_context", "Search a context corpus. Corpora: engineering, payments, people.",
         {"corpus": {"type": "string"}, "query": {"type": "string"}}, ["corpus", "query"]),
]
