"""Okta calls for the event-triggered pattern (machine access), each client signed by its own KMS key.

  T1  the event source (a service app) gets a token for itself: client credentials at the
      agent's authorization server, aud = the agent's resource URL
  T2  the AI agent exchanges T1 at the Okta org authorization server for an ID-JAG
      (sub = the event source, act = the agent), aud = the MCP server's authorization server
  T3  the ID-JAG is redeemed at the MCP server's authorization server (jwt-bearer)

The deployed agent doesn't call t2/t3 itself: AgentCore Identity and the Gateway do. These are
for the trigger Lambda (t1) and the test script (all three).
"""
import base64
import hashlib
import json
import time
import uuid

import boto3
import httpx

ASSERTION_TYPE = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
EXCHANGE = "urn:ietf:params:oauth:grant-type:token-exchange"
JWT_BEARER = "urn:ietf:params:oauth:grant-type:jwt-bearer"
ACCESS_TYPE_URN = "urn:ietf:params:oauth:token-type:access_token"   # an RFC 8693 token-type name, not a credential
ID_JAG = "urn:ietf:params:oauth:token-type:id-jag"

_kms = {}


def _b64(raw):
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def claims(jwt):
    p = jwt.split(".")[1]
    return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))


def assertion(client_id, key_arn, kid, audience, profile=None):
    """A 5-minute private_key_jwt client assertion for one token endpoint, signed in KMS."""
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": kid}
    body = {"iss": client_id, "sub": client_id, "aud": audience, "iat": now, "exp": now + 300, "jti": str(uuid.uuid4())}
    signing_input = f"{_b64(json.dumps(header).encode())}.{_b64(json.dumps(body).encode())}"
    kms = _kms.setdefault(profile, boto3.Session(profile_name=profile).client("kms"))
    sig = kms.sign(KeyId=key_arn, Message=hashlib.sha256(signing_input.encode()).digest(), MessageType="DIGEST",
                   SigningAlgorithm="RSASSA_PKCS1_V1_5_SHA_256")["Signature"]
    return f"{signing_input}.{_b64(sig)}"


def _post(url, data):
    r = httpx.post(url, data=data, timeout=15)
    if r.status_code >= 400:
        raise RuntimeError(f"{url.rsplit('/oauth2/', 1)[-1]} -> {r.status_code}: {r.text[:300]}")
    return r.json()["access_token"]


def t1(issuer, client_id, key_arn, kid, scope, resource=None, profile=None):
    """Event source -> its own access token for the agent (client credentials)."""
    url = f"{issuer}/v1/token"
    data = {"grant_type": "client_credentials", "scope": scope, "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": assertion(client_id, key_arn, kid, url, profile)}
    if resource:
        data["resource"] = resource
    return _post(url, data)


def t2(okta, subject, agent_client_id, key_arn, kid, audience, scope, resource=None, profile=None):
    """AI agent -> ID-JAG at the org authorization server, subject = the event source's token."""
    url = f"{okta}/oauth2/v1/token"
    data = {"grant_type": EXCHANGE, "requested_token_type": ID_JAG, "subject_token": subject,
            "subject_token_type": ACCESS_TYPE_URN, "audience": audience, "scope": scope,
            "client_assertion_type": ASSERTION_TYPE, "client_assertion": assertion(agent_client_id, key_arn, kid, url, profile)}
    if resource:
        data["resource"] = resource
    return _post(url, data)


def t3(issuer, id_jag, agent_client_id, key_arn, kid, scope=None, profile=None):
    """AI agent -> access token at the MCP server's authorization server (jwt-bearer)."""
    url = f"{issuer}/v1/token"
    data = {"grant_type": JWT_BEARER, "assertion": id_jag, "client_assertion_type": ASSERTION_TYPE,
            "client_assertion": assertion(agent_client_id, key_arn, kid, url, profile)}
    if scope:
        data["scope"] = scope
    return _post(url, data)
