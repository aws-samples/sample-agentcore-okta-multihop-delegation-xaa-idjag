"""Event trigger: SNS -> this Lambda -> the event agent on AgentCore Runtime.

This function plays the event source. For each SNS message it:
  1. gets T1, the event source's own Okta token: client credentials, with a private_key_jwt signed
     by the event source's KMS key, for the agent's resource URL (aud = the agent)
  2. invokes the event agent with T1 as the bearer; the body carries only the event
  3. writes a trace record for the console (the token as header + claims, never its signature)
"""
import base64
import hashlib
import http.client
import json
import os
import ssl
import time
import urllib.parse
import uuid

import boto3

E = os.environ
TABLE = boto3.resource("dynamodb").Table(E["TABLE"])
KMS = boto3.client("kms")


def b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def jwt_view(tok):
    h, p, sig = tok.split(".")
    dec = lambda x: json.loads(base64.urlsafe_b64decode(x + "=="))
    return {"header": dec(h), "payload": dec(p), "signature": f"<{len(sig)} chars, not shown>"}


def post(url, data, headers):
    """POST over HTTPS only (Okta's token URL, the Runtime's invoke URL); raises on HTTP 4xx/5xx."""
    u = urllib.parse.urlsplit(url)
    if u.scheme != "https" or not u.hostname:
        raise ValueError(f"refusing a non-HTTPS URL: {u.scheme}://{u.hostname}")
    conn = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=110, context=ssl.create_default_context())
    try:
        conn.request("POST", u.path + (f"?{u.query}" if u.query else ""), body=data, headers=headers)
        r = conn.getresponse()
        body = r.read()
    finally:
        conn.close()
    if r.status >= 400:
        raise RuntimeError(f"HTTP Error {r.status}: {r.reason}: {body[:200].decode(errors='replace')}")
    return json.loads(body)


def get_t1():
    """Client credentials as the event source, authenticated with a KMS-signed private_key_jwt."""
    url = f"{E['EVENT_AGENT_ISSUER']}/v1/token"
    client, now = E["EVENT_SOURCE_CLIENT_ID"], int(time.time())
    head = b64(json.dumps({"alg": "RS256", "typ": "JWT", "kid": E["EVENT_SOURCE_KID"]}).encode())
    body = b64(json.dumps({"iss": client, "sub": client, "aud": url, "iat": now, "exp": now + 300,
                           "jti": str(uuid.uuid4())}).encode())
    sig = KMS.sign(KeyId=E["EVENT_SOURCE_KMS_KEY"], Message=hashlib.sha256(f"{head}.{body}".encode()).digest(),
                   MessageType="DIGEST", SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256")["Signature"]
    form = {"grant_type": "client_credentials", "scope": "agent.invoke", "resource": E["EVENT_AGENT_AUDIENCE"],
            "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
            "client_assertion": f"{head}.{body}.{b64(sig)}"}
    out = post(url, urllib.parse.urlencode(form).encode(), {"Content-Type": "application/x-www-form-urlencoded"})
    return out["access_token"]


def invoke_agent(event, t1, session_id):
    url = (f"https://bedrock-agentcore.{E['AWS_REGION']}.amazonaws.com/runtimes/"
           f"{urllib.parse.quote(E['EVENT_RUNTIME_ARN'], safe='')}/invocations?qualifier=DEFAULT")
    return post(url, json.dumps({"event": event}).encode(),
                {"Content-Type": "application/json", "Authorization": f"Bearer {t1}",
                 "X-Amzn-Bedrock-AgentCore-Runtime-Session-Id": session_id})


def lambda_handler(event, _ctx):
    for rec in event.get("Records", []):
        msg = rec.get("Sns", {})
        run_id = str(uuid.uuid4())
        item = {"pk": "event", "sk": f"{int(time.time() * 1000)}#{run_id}", "ttl": int(time.time()) + 86400,
                "run_id": run_id, "sns": {"topic": msg.get("TopicArn", ""), "message_id": msg.get("MessageId", "")}}
        t0 = time.time()
        try:
            item["event"] = json.loads(msg.get("Message") or "{}")
            t1 = get_t1()
            item["t1"] = jwt_view(t1)
            item["agent"] = invoke_agent(item["event"], t1, f"event-{run_id}")
        except Exception as e:      # Okta or the Runtime refused: record it, don't retry
            item["error"] = str(e)[:400]
        item["total_ms"] = int((time.time() - t0) * 1000)
        TABLE.put_item(Item=json.loads(json.dumps(item), parse_float=str))
    return {"ok": True}
