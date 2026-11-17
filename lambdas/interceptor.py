"""AgentCore Gateway interceptor (REQUEST and RESPONSE).

Order on every call: the Gateway validates the Okta JWT, runs this REQUEST interceptor, evaluates
Cedar, calls the tool, then runs this RESPONSE interceptor.

REQUEST, tools/call: stamp a `caller` object into the tool arguments from the verified token (who
is calling, and every actor in `act`), replacing anything the model sent. The tools trust only this.
Both phases write a trace record for the console (claims and outcome, never the token).
"""
import base64
import copy
import json
import os
import time
import uuid
from decimal import Decimal

import boto3

TABLE = boto3.resource("dynamodb").Table(os.environ["TABLE"])


def header(headers, name):
    return next((str(v) for k, v in (headers or {}).items() if k.lower() == name.lower()), "")


def claims_of(headers):
    try:
        return json.loads(base64.urlsafe_b64decode(header(headers, "Authorization").split(".")[1] + "=="))
    except Exception:
        return {}


def act_chain(act):
    """Every actor in the token, newest first: act, act.act, ..."""
    chain = []
    while isinstance(act, dict):
        chain.append({k: act[k] for k in ("sub", "sub_profile") if k in act})
        act = act.get("act")
    return chain


def caller(c, headers):
    chain = act_chain(c.get("act"))
    return {"user": c.get("sub", "") if "uid" in c else "", "sub": c.get("sub", ""), "client_id": c.get("cid", ""),
            "scopes": c.get("scp", []), "acting_agent": chain[0]["sub"] if chain else "", "act_chain": chain,
            "run_id": header(headers, "X-Agent-Run")}


def masked(headers):
    """Headers for the trace: credentials replaced, everything else kept."""
    hide = ("authorization", "cookie", "x-amz-security-token")
    return {k: ("Bearer <token>" if k.lower() == "authorization" else "<hidden>") if k.lower() in hide
            or "workloadaccesstoken" in k.lower() else str(v)[:300] for k, v in (headers or {}).items()}


def record(**item):
    now = time.time()
    item.update(pk="trace", sk=f"{int(now * 1000):013d}#{uuid.uuid4().hex[:6]}", ttl=int(now) + 86400, auth="JWT")
    TABLE.put_item(Item=json.loads(json.dumps(item, default=str), parse_float=Decimal))


def lambda_handler(event, context):
    mcp = event.get("mcp", {})
    req = mcp.get("gatewayRequest") or {}
    body, headers = req.get("body") or {}, req.get("headers") or {}
    method, params = body.get("method"), body.get("params") or {}
    c = claims_of(headers)
    who = {k: c[k] for k in ("sub", "cid", "uid", "scp", "aud", "act", "exp") if k in c}
    run = header(headers, "X-Agent-Run")

    resp = mcp.get("gatewayResponse")
    if resp is not None:                                    # RESPONSE phase: record the outcome
        rbody = resp.get("body") or {}
        if method == "tools/call":
            err, result = rbody.get("error"), rbody.get("result") or {}
            text = json.dumps(err) if err else " ".join(x.get("text", "") for x in result.get("content", []))
            outcome = ("denied" if err and any(w in text.lower() for w in ("denied", "policy", "authoriz")) else
                       "error" if err or result.get("isError") else "allowed")
            record(phase="response", method=method, tool=params.get("name", ""), run=run, claims=who,
                   outcome=outcome, detail=text[:1200])
        out = {"statusCode": resp.get("statusCode", 200), "body": rbody, **({"headers": resp["headers"]} if resp.get("headers") else {})}
        return {"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayResponse": out}}

    if method == "tools/call":                              # REQUEST phase: stamp the caller
        original = copy.deepcopy(params.get("arguments") or {})
        params["arguments"] = {**original, "caller": caller(c, headers)}
        body["params"] = params
        out = {"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayRequest": {"body": body}}}
        shown = {**event, "mcp": {**mcp, "gatewayRequest": {**req, "headers": masked(headers),
                                                            "body": {**body, "params": {**params, "arguments": original}}}}}
        record(phase="request", method=method, tool=params.get("name", ""), run=run, claims=who,
               original_arguments=original, arguments=params["arguments"],
               agent_headers={"X-Agent-Run": run}, literal_event=shown, literal_return=out,
               http={"method": req.get("httpMethod", "POST"), "path": req.get("path", "/mcp"),
                     "headers": masked(headers), "body": shown["mcp"]["gatewayRequest"]["body"]})
        return out
    return {"interceptorOutputVersion": "1.0", "mcp": {"transformedGatewayRequest": {"body": body}}}
