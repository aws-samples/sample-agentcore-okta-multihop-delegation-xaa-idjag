"""Mock GitHub and context-service tools behind AgentCore Gateway.

The data is fake. The identity is not: every call carries a `caller` object that the
gateway's request interceptor filled in from the Okta token the gateway had already
validated. Anything the model put in `caller` was overwritten before this code runs.
"""
import json
import os
import time
import uuid

import boto3
from boto3.dynamodb.conditions import Key

TABLE = boto3.resource("dynamodb").Table(os.environ["TABLE"])

PULL_REQUESTS = {
    ("anyco/receipts-service", 128): {
        "title": "Retry receipt image upload on 5xx",
        "author": "jlee",
        "files": ["upload/client.py"],
        "diff": (
            "+ for attempt in range(5):\n"
            "+     resp = s3_proxy.post('/receipts', data=image)\n"
            "+     if resp.status < 500:\n"
            "+         break\n"
            "+     time.sleep(1)\n"
        ),
    },
}

CORPORA = {
    "engineering": [
        "Retries: every retried write must send an Idempotency-Key header, and back off "
        "exponentially with jitter (base 200 ms, cap 10 s).",
        "Code review: approve only when tests cover the new branch.",
    ],
    "payments": [
        "Card processor failover runbook (restricted): rotate the processor API key in the vault...",
    ],
    "people": [
        "Compensation bands by level (restricted).",
    ],
}


def _who(caller):
    """The signed-in user; with no user behind the token, the calling client."""
    return caller.get("user") or f"client:{caller.get('client_id')}"


def lambda_handler(event, context):
    full = context.client_context.custom["bedrockAgentCoreToolName"]
    tool = full.split("___", 1)[-1]
    caller = event.pop("caller", None) or {}
    # The Gateway's interceptor always stamps caller from the verified token. Without it, this wasn't
    # a Gateway call (for example a direct Lambda invoke): refuse. This catches mistakes, not a
    # forger: who may invoke this function is decided by IAM (only the Gateway's role is granted it).
    if not caller.get("client_id") or not caller.get("sub"):
        return {"error": "refused: no caller from the Gateway interceptor"}

    if tool == "get_pull_request":
        pr = PULL_REQUESTS.get((event.get("repo"), int(event.get("number", 0))))
        if not pr:
            return {"error": "pull request not found"}
        return {"served_to": _who(caller), "repo": event["repo"], "number": event["number"], **pr}

    if tool == "search_context":
        corpus = event.get("corpus", "")
        docs = CORPORA.get(corpus, [])
        return {"served_to": _who(caller), "corpus": corpus, "results": docs}

    if tool == "post_review":
        author = _who(caller)
        item = {"pk": f"reviews#{author}", "sk": f"{int(time.time() * 1000)}#{uuid.uuid4().hex[:6]}",
                "repo": event.get("repo"), "number": int(event.get("number", 0)),
                "verdict": event.get("verdict", "COMMENT"), "body": event.get("body", ""), "author": author,
                "acting_agent": caller.get("acting_agent", ""), "act_chain": caller.get("act_chain", []),
                "run_id": caller.get("run_id", ""), "ttl": int(time.time()) + 86400}
        TABLE.put_item(Item=item)
        return {"posted": True, **{k: item[k] for k in ("author", "repo", "number", "verdict", "acting_agent", "act_chain")}}

    if tool == "list_my_reviews":
        user = caller.get("user")
        if not user:
            return {"error": "list_my_reviews needs a signed-in user; this token has none"}
        out = TABLE.query(KeyConditionExpression=Key("pk").eq(f"reviews#{user}"),
                          ScanIndexForward=False, Limit=10)
        return {"user": user, "reviews": [
            {k: (int(v) if k == "number" else v) for k, v in r.items()
             if k in ("repo", "number", "verdict", "body", "author", "acting_agent", "act_chain")} for r in out.get("Items", [])]}

    if tool == "merge_pull_request":
        return {"merged": True, "by": _who(caller)}

    return {"error": f"unknown tool {tool}"}
