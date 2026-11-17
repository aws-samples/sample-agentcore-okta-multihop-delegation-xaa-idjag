"""Event agent: a Strands agent on AgentCore Runtime. An event wakes it, and it acts for the app
that fired the event. No user is involved.

The trigger Lambda sends T1 (the event source's own Okta token, aud = this agent) as the bearer.
The Runtime accepts only that token, and binds it to this agent's workload identity. Then:
  step 1  AgentCore Identity: T1 -> ID-JAG at the Okta org server (Okta machine access)
  step 2  AgentCore Identity: ID-JAG -> the partner token at anyco-partner-mcp-as
The agent calls the partner MCP server directly with the partner token. There's no Gateway here.
"""
import base64
import json
import os

from bedrock_agentcore.identity.auth import requires_access_token
from bedrock_agentcore.runtime import BedrockAgentCoreApp
from bedrock_agentcore.runtime.context import BedrockAgentCoreContext
from bedrock_agentcore.services.identity import IdentityClient
from mcp.client.streamable_http import streamablehttp_client
from strands import Agent
from strands.models import BedrockModel
from strands.tools.mcp import MCPClient

E = os.environ
REGION = E.get("AWS_REGION", "us-west-2")
SCOPES = E.get("PARTNER_SCOPES", "partner:read").split()
PROMPT = ("You are AnyCompany's event agent. An event arrived from the pull-request system; you act for that "
          "system, not for a person. For a 'pr.opened' event, run get_compliance_checks and summarize the result "
          "in two sentences. For a 'pr.approved' event, also record the result with record_compliance_result. "
          "If a call is refused, say in one line that the partner refused it and stop. Plain text only.")

app = BedrockAgentCoreApp()


def claims(tok):
    try:
        return json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
    except Exception:
        return {}


def jwt_view(tok):
    """A JWT for the console: header and every claim. The signature only as a length."""
    h, p, sig = tok.split(".")
    dec = lambda x: json.loads(base64.urlsafe_b64decode(x + "=="))
    return {"header": dec(h), "payload": dec(p), "signature": f"<{len(sig)} chars, not shown>"}


@requires_access_token(provider_name=E["EVENT_STEP1_PROVIDER"], scopes=SCOPES, auth_flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
                       force_authentication=True,
                       custom_parameters={"subject_token_type": "urn:ietf:params:oauth:token-type:access_token",
                                          "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag",
                                          "audience": E["PARTNER_MCP_ISSUER"]})
async def get_id_jag(*, access_token):          # step 1: T1 -> ID-JAG (subject = T1, bound by the Runtime)
    return access_token


@requires_access_token(provider_name=E["EVENT_STEP2_PROVIDER"], scopes=SCOPES, auth_flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
                       force_authentication=True)
async def redeem_id_jag(*, access_token):       # step 2: ID-JAG -> partner token
    return access_token


def tool_calls(messages):
    """The tool calls in the conversation, each with its result."""
    calls = {}
    for m in messages:
        for b in m["content"]:
            if "toolUse" in b:
                calls[b["toolUse"]["toolUseId"]] = {"tool": b["toolUse"]["name"], "args": b["toolUse"]["input"]}
            elif "toolResult" in b:
                text = " ".join(c.get("text", "") for c in b["toolResult"]["content"])
                calls[b["toolResult"]["toolUseId"]]["result"] = text[:1500]
    return list(calls.values())


@app.entrypoint
async def run(payload, context):
    event = payload.get("event") or {}
    t1 = context.request_headers["Authorization"][len("Bearer "):]
    trace = {"event": event, "jwt": {"t1": jwt_view(t1)}}
    c = claims(t1)
    if c.get("cid") != E["EVENT_SOURCE_CLIENT_ID"] or c.get("aud") != E["EVENT_AGENT_AUDIENCE"]:
        return {"error": "the bearer is not the event source's token for this agent", "trace": trace}
    try:
        id_jag = await get_id_jag()
        trace["jwt"]["id_jag"] = jwt_view(id_jag)
        # step 2's subject is the ID-JAG: bind it with a standalone workload identity
        wat = IdentityClient(REGION).get_workload_access_token(E["EVENT_WORKLOAD"], user_token=id_jag)
        BedrockAgentCoreContext.set_workload_access_token(wat["workloadAccessToken"])
        partner_token = await redeem_id_jag()
        trace["jwt"]["partner"] = jwt_view(partner_token)
    except Exception as e:
        return {"error": f"Okta refused: {str(e)[:300]}", "trace": trace}
    headers = {"Authorization": f"Bearer {partner_token}"}
    try:
        with MCPClient(lambda: streamablehttp_client(E["PARTNER_MCP_URL"], headers=headers)) as partner:
            tools = partner.list_tools_sync()
            trace["tools"] = [t.tool_name for t in tools]
            agent = Agent(model=BedrockModel(model_id=E["MODEL_ID"], region_name=REGION, temperature=0, max_tokens=800),
                          tools=tools, system_prompt=PROMPT, callback_handler=None)
            answer = await agent.invoke_async(json.dumps(event))
            trace["calls"] = tool_calls(agent.messages)
    except Exception as e:
        return {"error": f"The partner MCP server refused: {str(e)[:300]}", "trace": trace}
    return {"answer": str(answer).strip(), "trace": trace}


if __name__ == "__main__":
    app.run()
