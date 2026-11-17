"""PR Review Agent: a Strands agent on AgentCore Runtime. It streams AG-UI events to the console.

The Runtime accepts T2 (the token your backend got for this agent) and binds it to the agent's
workload identity. The agent turns T2 into T3 for the Gateway through AgentCore Identity, then
calls the Gateway's tools with T3 as the Bearer. It holds no Okta secret and no key.

  AGENT_MODE=obo  Pattern A: one token exchange, T2 -> T3 at anyco-gateway-as.
  AGENT_MODE=xaa  Pattern B: Cross App Access, T2 -> ID-JAG (org server) -> T3 at anyco-gateway-as.
"""
import base64
import json
import os
import uuid

from ag_ui.core import (CustomEvent, RunAgentInput, RunFinishedEvent, RunStartedEvent, TextMessageContentEvent,
                        TextMessageEndEvent, TextMessageStartEvent, ToolCallArgsEvent, ToolCallEndEvent,
                        ToolCallResultEvent, ToolCallStartEvent)
from bedrock_agentcore.identity.auth import requires_access_token
from bedrock_agentcore.runtime import AGUIApp
from bedrock_agentcore.runtime.context import BedrockAgentCoreContext
from bedrock_agentcore.services.identity import IdentityClient
from mcp.client.streamable_http import streamablehttp_client
from strands import Agent
from strands.models import BedrockModel
from strands.tools.mcp import MCPClient

E = os.environ
MODE = E["AGENT_MODE"]                                   # "obo" or "xaa"
REGION = E.get("AWS_REGION", "us-west-2")
ACCESS_TYPE_URN = "urn:ietf:params:oauth:token-type:access_token"   # an RFC 8693 token-type name, not a credential
PROMPT = ("You are AnyCompany's PR Review Agent, acting for the signed-in engineer. Use get_pull_request to read "
          "a PR, post_review to post a review for them, list_my_reviews to show their reviews. If a call is "
          "refused, say so in one short line and don't retry it. Never fill in the 'caller' argument. Keep "
          "answers short.")

app = AGUIApp()


def claims(tok):
    try:
        return json.loads(base64.urlsafe_b64decode(tok.split(".")[1] + "=="))
    except Exception:
        return {}


def jwt_view(tok):
    """A JWT for the UI: header and every claim. The signature only as a length, so it's not a credential."""
    h, p, sig = tok.split(".")
    dec = lambda x: json.loads(base64.urlsafe_b64decode(x + "=="))
    return {"header": dec(h), "payload": dec(p), "signature": f"<{len(sig)} chars, not shown>"}


# Each decorated function asks AgentCore Identity for a token. The subject is the workload access
# token in the request context: the Runtime binds T2 there before our code runs.
if MODE == "obo":
    @requires_access_token(provider_name=E["OKTA_PROVIDER"], scopes=E["DECLARED_SCOPES"].split(),
                           auth_flow="ON_BEHALF_OF_TOKEN_EXCHANGE",
                           custom_parameters={"audience": E["GATEWAY_AUDIENCE"], "subject_token_type": ACCESS_TYPE_URN})
    async def token_exchange(*, access_token):         # T2 -> T3
        return access_token
else:
    @requires_access_token(provider_name=E["XAA_STEP1_PROVIDER"], scopes=E["XAA_SCOPE"].split(),
                           auth_flow="ON_BEHALF_OF_TOKEN_EXCHANGE", force_authentication=True,
                           custom_parameters={"subject_token_type": ACCESS_TYPE_URN, "audience": E["XAA_CUSTOM_AS_ISSUER"],
                                              "requested_token_type": "urn:ietf:params:oauth:token-type:id-jag"})
    async def get_id_jag(*, access_token):             # step 1: T2 -> ID-JAG (Okta org server)
        return access_token

    @requires_access_token(provider_name=E["XAA_STEP2_PROVIDER"], scopes=E["XAA_SCOPE"].split(),
                           auth_flow="ON_BEHALF_OF_TOKEN_EXCHANGE", force_authentication=True)
    async def redeem_id_jag(*, access_token):          # step 2: ID-JAG -> T3 (anyco-gateway-as)
        return access_token


async def get_t3(t2):
    """T2 -> T3 for the Gateway. Returns T3 and a CUSTOM event with the tokens for the console."""
    if MODE == "obo":
        t3 = await token_exchange()
        return t3, CustomEvent(name="obo_token_jwt", value=jwt_view(t3))
    c = claims(t2)
    if c.get("cid") != E["XAA_BACKEND_CLIENT_ID"] or c.get("aud") != E["XAA_AGENT_AUDIENCE"]:
        raise PermissionError("the bearer is not your backend's token for this agent")
    id_jag = await get_id_jag()
    # step 2's subject is the ID-JAG: bind it with a standalone workload identity
    # (the Runtime's own workload identity can't do this from code)
    wat = IdentityClient(REGION).get_workload_access_token(E["XAA_WORKLOAD"], user_token=id_jag)
    BedrockAgentCoreContext.set_workload_access_token(wat["workloadAccessToken"])
    t3 = await redeem_id_jag()
    return t3, CustomEvent(name="xaa", value={"jwt": {"inbound": jwt_view(t2), "id_jag": jwt_view(id_jag),
                                                      "final": jwt_view(t3)}})


def to_agui(message):
    """One finished Strands message -> the AG-UI events the console draws."""
    for block in (message or {}).get("content", []):
        if block.get("text", "").strip() and message["role"] == "assistant":
            mid = str(uuid.uuid4())
            yield TextMessageStartEvent(message_id=mid, role="assistant")
            yield TextMessageContentEvent(message_id=mid, delta=block["text"])
            yield TextMessageEndEvent(message_id=mid)
        elif "toolUse" in block:
            use = block["toolUse"]
            yield ToolCallStartEvent(tool_call_id=use["toolUseId"], tool_call_name=use["name"])
            yield ToolCallArgsEvent(tool_call_id=use["toolUseId"], delta=json.dumps(use["input"]))
            yield ToolCallEndEvent(tool_call_id=use["toolUseId"])
        elif "toolResult" in block:
            res = block["toolResult"]
            text = " ".join(c.get("text", "") for c in res["content"])
            yield ToolCallResultEvent(message_id=str(uuid.uuid4()), tool_call_id=res["toolUseId"], content=text, role="tool")


@app.entrypoint
async def run(run_input: RunAgentInput, context):
    yield RunStartedEvent(thread_id=run_input.thread_id, run_id=run_input.run_id)
    t2 = (context.request_headers or {}).get("Authorization", "")[len("Bearer "):]   # passed to the code on Runtime B
    try:
        t3, token_event = await get_t3(t2)
    except Exception as e:      # Okta's refusal ends the run, visibly
        if MODE == "xaa":
            yield CustomEvent(name="xaa", value={"error": str(e)[:400]})
        raise
    run_id = context.session_id or str(uuid.uuid4())
    headers = {"Authorization": f"Bearer {t3}", "X-Agent-Run": run_id}
    with MCPClient(lambda: streamablehttp_client(E["GATEWAY_URL"], headers=headers)) as gateway:
        tools = gateway.list_tools_sync()
        yield CustomEvent(name="release", value={"run_id": run_id, "tools": [t.tool_name for t in tools], "mode": MODE})
        yield token_event
        agent = Agent(model=BedrockModel(model_id=E["MODEL_ID"], region_name=REGION, temperature=0, max_tokens=1200),
                      tools=tools, system_prompt=PROMPT, callback_handler=None)
        async for event in agent.stream_async(run_input.messages[-1].content):
            for out in to_agui(event.get("message")):
                yield out
    yield RunFinishedEvent(thread_id=run_input.thread_id, run_id=run_input.run_id)


if __name__ == "__main__":
    app.run()
