"""Partner compliance MCP server on AgentCore Runtime (MCP protocol), behind its own Okta issuer.

Inbound: the Runtime's CUSTOM_JWT authorizer admits only tokens from the anyco-partner-mcp-as
authorization server, aud api://anyco-partner-mcp-aud, cid = the event agent. The Authorization
header is on the request-header allowlist, so the tools can read the (already verified) claims
and apply their own rule: a delegated call (act names the agent) with the tool's scope.

The container listens on 0.0.0.0:8000/mcp as the Runtime's MCP contract requires; no port is
published, and the Runtime endpoint is the only way in.
"""
import base64
import hashlib
import json
import os

from mcp.server.fastmcp import Context, FastMCP

AGENT = os.environ.get("EVENT_AGENT_PRINCIPAL", "")     # the Okta AI agent (act.sub)

mcp = FastMCP("partner-compliance", host="0.0.0.0", stateless_http=True)


def _claims(ctx):
    req = getattr(ctx.request_context, "request", None)
    auth = (req.headers.get("authorization") if req else "") or ""
    try:
        part = auth.split(" ", 1)[1].split(".")[1]
        return json.loads(base64.urlsafe_b64decode(part + "=" * (-len(part) % 4)))
    except Exception:
        return {}


def _authorize(ctx, scope):
    c = _claims(ctx)
    act = c.get("act") if isinstance(c.get("act"), dict) else {}
    if act.get("sub") != AGENT or scope not in (c.get("scp") or []):
        raise PermissionError(f"partner MCP refused: needs a token delegated to the event agent with {scope}")
    return {"sub": c.get("sub"), "sub_profile": c.get("sub_profile"), "acting_agent": act.get("sub"),
            "client": c.get("cid"), "scopes": c.get("scp"), "issuer": c.get("iss")}


@mcp.tool()
def get_compliance_checks(repo: str, pr: int, ctx: Context) -> dict:
    """Run the partner's compliance checks for a pull request (license, dependency pinning, secrets)."""
    caller = _authorize(ctx, "partner:read")
    seed = int(hashlib.sha256(f"{repo}#{pr}".encode()).hexdigest(), 16)
    pinning = "warn" if seed % 3 == 0 else "pass"
    return {"repo": repo, "pr": pr,
            "checks": [{"name": "license-scan", "status": "pass"},
                       {"name": "dependency-pinning", "status": pinning,
                        **({"detail": "2 dependencies use a version range"} if pinning == "warn" else {})},
                       {"name": "secrets-scan", "status": "pass"}],
            "checked_for": caller}


@mcp.tool()
def record_compliance_result(repo: str, pr: int, status: str, ctx: Context) -> dict:
    """Record a compliance decision for a pull request in the partner's system (needs partner:write)."""
    caller = _authorize(ctx, "partner:write")
    return {"repo": repo, "pr": pr, "recorded": status, "recorded_for": caller}


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
