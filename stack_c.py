"""Event-triggered machine delegation stack (shown as Pattern C in the console): deploy / destroy
as generators of log lines. Needs the shared base (stack.py: table, code bucket) and the Pattern C Okta values (okta_values.py).

  SNS topic            anyco-pr-events (KMS-encrypted; only this account may publish)
  Trigger Lambda       anyco-event-trigger: gets T1 as the event source (client credentials,
                       KMS-signed), invokes the event agent with T1 as the bearer, writes a trace
  Runtime (agent)      anyco_event_agent: Strands, CUSTOM_JWT inbound: only T1s (issuer
                       anyco-event-agent-as, aud = the agent, cid = the event source). The Runtime
                       binds T1 to its own workload identity, which step 1 uses.
  Workload identity    anyco-event-agent-delegate (standalone): binds the ID-JAG for step 2
  AgentCore Identity   anyco-event-step1  Okta org AS · TOKEN_EXCHANGE          T1 -> ID-JAG
                       anyco-event-step2  partner AS · JWT_AUTHORIZATION_GRANT  ID-JAG -> partner token
                       both private_key_jwt with the agent's KMS key; the agent runs both steps
  Runtime (MCP)        anyco_partner_mcp: MCP protocol, CUSTOM_JWT inbound from the partner
                       authorization server only (aud api://anyco-partner-mcp-aud, cid = the agent).
                       The agent calls it directly with the partner token: no Gateway.
"""
import json
import time
import urllib.parse

import config as C
import deploy_aws as D
import release as R
import stack_b

ac, iam, lam = D.ac, D.iam, D.lam
sns = C.session().client("sns")
REG, ACCT = C.REGION, C.ACCOUNT
TAGS = {"project": "anyco-agentid"}
AGENT_RT, MCP_RT = "anyco_event_agent", "anyco_partner_mcp"
AGENT_ROLE, MCP_ROLE = "anyco-event-agent-role", "anyco-partner-mcp-role"
GW_NAME, GW_ROLE = "anyco-event-gw", "anyco-event-gateway-role"   # earlier design; removed on deploy
TRIGGER_FN, TRIGGER_ROLE = "anyco-event-trigger", "anyco-event-trigger-role"
TOPIC = "anyco-pr-events"
STEP1, STEP2 = "anyco-event-step1", "anyco-event-step2"
WORKLOAD = "anyco-event-agent-delegate"
PREFIX = "AnycoEvent_"                                     # Cedar permits of the earlier Gateway design
SCOPES = ["partner:read"]
WID = f"arn:aws:bedrock-agentcore:{REG}:{ACCT}:workload-identity-directory/default"
VAULT = f"arn:aws:bedrock-agentcore:{REG}:{ACCT}:token-vault/default"
LOGS = [
    {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
     "Resource": f"arn:aws:logs:{REG}:{ACCT}:log-group:/aws/bedrock-agentcore/runtimes/*"},
    {"Effect": "Allow", "Action": "logs:DescribeLogGroups", "Resource": f"arn:aws:logs:{REG}:{ACCT}:log-group:*"},
    {"Effect": "Allow", "Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules",
                                   "xray:GetSamplingTargets"], "Resource": "*"},
    {"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*",
     "Condition": {"StringEquals": {"cloudwatch:namespace": "bedrock-agentcore"}}},
]


def runtime_url(arn):
    return f"https://bedrock-agentcore.{REG}.amazonaws.com/runtimes/{urllib.parse.quote(arn, safe='')}/invocations?qualifier=DEFAULT"


def runtime(name, zip_name, entry, role_arn, protocol, env, auth=None, headers=None, description=""):
    """Create or update a code-deployed Runtime; returns (id, arn, version)."""
    s3 = C.session().client("s3")
    s3.upload_file(str(C.ROOT / "build" / zip_name), C.N["code_bucket"], zip_name, ExtraArgs={"ExpectedBucketOwner": C.ACCOUNT})
    kw = dict(agentRuntimeArtifact={"codeConfiguration": {"code": {"s3": {"bucket": C.N["code_bucket"], "prefix": zip_name}},
                                                          "runtime": "PYTHON_3_13", "entryPoint": [entry]}},
              roleArn=role_arn, networkConfiguration={"networkMode": "PUBLIC"},
              protocolConfiguration={"serverProtocol": protocol}, environmentVariables=env)
    if auth:
        kw["authorizerConfiguration"] = auth
    if headers:
        kw["requestHeaderConfiguration"] = {"requestHeaderAllowlist": headers}
    found = D.find_named(ac.list_agent_runtimes, "agentRuntimes", name, field="agentRuntimeName")
    if not found:
        for attempt in range(6):
            try:
                r = ac.create_agent_runtime(agentRuntimeName=name, **kw, tags=TAGS, description=description)
                break
            except ac.exceptions.ValidationException as e:
                if "role" in str(e).lower() and attempt < 5:
                    time.sleep(10)
                    continue
                raise
        rid, arn, ver = r["agentRuntimeId"], r["agentRuntimeArn"], r["agentRuntimeVersion"]
    else:
        rid, arn = found["agentRuntimeId"], found["agentRuntimeArn"]
        R.wait_runtime(ac, rid)
        ver = ac.update_agent_runtime(agentRuntimeId=rid, **kw)["agentRuntimeVersion"]
    R.wait_runtime(ac, rid)
    return rid, arn, ver


def drop_gateway(st):
    """Remove the Gateway, its target, its Cedar permits and its role (an earlier design used them)."""
    gid = st.get("event_gateway_id") or (D.find_named(ac.list_gateways, "items", GW_NAME) or {}).get("gatewayId")
    if st.get("policy_engine_id"):
        R.apply_policies(ac, st["policy_engine_id"], {}, PREFIX)
    if gid:
        for t in ac.list_gateway_targets(gatewayIdentifier=gid, maxResults=100)["items"]:
            ac.delete_gateway_target(gatewayIdentifier=gid, targetId=t["targetId"])
        for _ in range(30):
            if not ac.list_gateway_targets(gatewayIdentifier=gid, maxResults=100)["items"]:
                break
            time.sleep(3)
        try:
            ac.delete_gateway(gatewayIdentifier=gid)
            yield f"Gateway {gid} (earlier design) deleted, with its target and permits"
        except Exception as e:
            yield f"gateway: {str(e)[:120]}"
    try:
        iam.delete_role_policy(RoleName=GW_ROLE, PolicyName="main")
        iam.delete_role(RoleName=GW_ROLE)
    except iam.exceptions.NoSuchEntityException:
        pass
    s = C.state()
    for k in ("event_gateway_id", "event_gateway_arn", "event_gateway_url"):
        s.pop(k, None)
    C.STATE_FILE.write_text(json.dumps(s, indent=2))


def deploy():
    st = C.state()
    ev = st.get("event")
    if not ev:
        raise RuntimeError("No OKTA_EVENT_* values: set up the Pattern C Okta objects (docs/okta-setup.md), then run okta_values.py")
    if not st.get("policy_engine_id"):
        raise RuntimeError("Deploy the shared base first (stack.py: table, policy engine, code bucket)")
    okta = C.OKTA_DOMAIN
    keyed = {"client_id": ev["agent_client_id"], "kms_key_arn": ev["agent_kms_key_arn"], "kms_kid": ev["agent_kid"]}
    yield (f"Okta: event source {ev['source_client_id']} may delegate to AI agent {ev['agent_client_id']} "
           f"(machine access) · connection to anyco-partner-mcp-as {' '.join(ev['granted_scopes'])}")

    # 1. partner MCP server on Runtime, behind the partner MCP AS
    mrole = D.role(MCP_ROLE, "bedrock-agentcore.amazonaws.com", LOGS)
    mauth = {"customJWTAuthorizer": {"discoveryUrl": f"{ev['mcp_issuer']}/.well-known/openid-configuration",
                                     "allowedAudience": [ev["mcp_audience"]],
                                     "customClaims": [{"inboundTokenClaimName": "cid", "inboundTokenClaimValueType": "STRING",
                                                       "authorizingClaimMatchValue": {"claimMatchOperator": "EQUALS",
                                                                                      "claimMatchValue": {"matchValueString": ev["agent_client_id"]}}}]}}
    mid, marn, mver = runtime(MCP_RT, "partner_mcp.zip", "server.py", mrole, "MCP",
                              {"EVENT_AGENT_PRINCIPAL": ev["agent_id"]}, auth=mauth, headers=["Authorization"],
                              description="Partner compliance MCP server (its own Okta issuer)")
    C.save_state(event_mcp_runtime_id=mid, event_mcp_runtime_arn=marn)
    yield f"Runtime (MCP): {mid} v{mver} · inbound JWT from anyco-partner-mcp-as only (aud {ev['mcp_audience']}, cid = the agent)"

    # 2. AgentCore Identity: two providers signed with the agent's KMS key, and a workload identity
    stack_b.provider(STEP1, f"{okta}/.well-known/openid-configuration", "TOKEN_EXCHANGE", keyed)
    stack_b.provider(STEP2, f"{ev['mcp_issuer']}/.well-known/openid-configuration", "JWT_AUTHORIZATION_GRANT", keyed)
    try:
        ac.create_workload_identity(name=WORKLOAD, tags=TAGS)
    except Exception as e:
        if "already exists" not in str(e) and "Conflict" not in type(e).__name__:
            raise
    yield f"AgentCore Identity: step 1 {STEP1} (Okta org AS · TOKEN_EXCHANGE) · step 2 {STEP2} (partner AS · JWT_AUTHORIZATION_GRANT) · workload {WORKLOAD}"

    # 3. no Gateway in this pattern: remove one an earlier version of this stack created
    for line in drop_gateway(st):
        yield line

    # 4. the event agent on Runtime, OAuth inbound (CUSTOM_JWT: only T1 from the event source)
    arole = D.role(AGENT_ROLE, "bedrock-agentcore.amazonaws.com", LOGS + [
        {"Effect": "Allow", "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
         "Resource": ["arn:aws:bedrock:*::foundation-model/*", f"arn:aws:bedrock:{REG}:{ACCT}:inference-profile/*"]},
        {"Effect": "Allow", "Action": ["bedrock-agentcore:GetWorkloadAccessToken", "bedrock-agentcore:GetWorkloadAccessTokenForJWT"],
         "Resource": [WID, f"{WID}/workload-identity/{AGENT_RT}*"]},                 # the Runtime binds T1
        {"Effect": "Allow", "Action": "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
         "Resource": [WID, f"{WID}/workload-identity/{WORKLOAD}"]},                    # bind(ID-JAG) for step 2
        {"Effect": "Allow", "Action": "bedrock-agentcore:GetResourceOauth2Token",
         "Resource": [VAULT, WID, f"{WID}/workload-identity/{AGENT_RT}*", f"{WID}/workload-identity/{WORKLOAD}",
                      f"{VAULT}/oauth2credentialprovider/{STEP1}", f"{VAULT}/oauth2credentialprovider/{STEP2}"]},
        {"Effect": "Allow", "Action": "kms:Sign", "Resource": ev["agent_kms_key_arn"]},
    ])
    env = {"PARTNER_MCP_URL": runtime_url(marn), "MODEL_ID": C.MODEL_ID, "EVENT_WORKLOAD": WORKLOAD,
           "EVENT_STEP1_PROVIDER": STEP1, "EVENT_STEP2_PROVIDER": STEP2,
           "EVENT_SOURCE_CLIENT_ID": ev["source_client_id"], "EVENT_AGENT_AUDIENCE": ev["agent_audience"],
           "PARTNER_MCP_ISSUER": ev["mcp_issuer"], "PARTNER_SCOPES": " ".join(SCOPES)}
    aauth = {"customJWTAuthorizer": {"discoveryUrl": f"{ev['agent_issuer']}/.well-known/openid-configuration",
                                     "allowedAudience": [ev["agent_audience"]], "allowedScopes": ["agent.invoke"],
                                     # Okta names the client in cid (allowedClients checks client_id)
                                     "customClaims": [{"inboundTokenClaimName": "cid", "inboundTokenClaimValueType": "STRING",
                                                       "authorizingClaimMatchValue": {"claimMatchOperator": "EQUALS",
                                                                                      "claimMatchValue": {"matchValueString": ev["source_client_id"]}}}]}}
    aid, aarn, aver = runtime(AGENT_RT, "event_agent.zip", "main.py", arole, "HTTP", env, auth=aauth, headers=["Authorization"],
                              description="Event agent: acts for the app that fired the event (Okta machine access)")
    C.save_state(event_runtime_id=aid, event_runtime_arn=aarn, event_runtime_version=aver)
    yield f"Runtime (agent): {aid} v{aver} · inbound Okta JWT: only T1 (issuer anyco-event-agent-as · aud the agent · cid the event source) · its role: {STEP1} + {STEP2}, kms:Sign"

    # 5. SNS -> trigger Lambda
    table_arn = f"arn:aws:dynamodb:{REG}:{ACCT}:table/{C.N['table']}"
    trole = D.role(TRIGGER_ROLE, "lambda.amazonaws.com", [
        {"Effect": "Allow", "Action": "kms:Sign", "Resource": ev["source_kms_key_arn"]},
        {"Effect": "Allow", "Action": "dynamodb:PutItem", "Resource": table_arn},
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": f"arn:aws:logs:{REG}:{ACCT}:log-group:/aws/lambda/{TRIGGER_FN}*"},
    ])
    fenv = {"TABLE": C.N["table"], "EVENT_AGENT_ISSUER": ev["agent_issuer"], "EVENT_SOURCE_CLIENT_ID": ev["source_client_id"],
            "EVENT_SOURCE_KMS_KEY": ev["source_kms_key_arn"], "EVENT_SOURCE_KID": ev["source_kid"],
            "EVENT_AGENT_AUDIENCE": ev["agent_audience"], "EVENT_RUNTIME_ARN": aarn}
    code = D.zipped("lambdas/event_trigger.py", "event_trigger.py")
    for attempt in range(6):
        try:
            farn = lam.create_function(FunctionName=TRIGGER_FN, Runtime="python3.12", Role=trole,
                                       Handler="event_trigger.lambda_handler", Code={"ZipFile": code}, Timeout=120,
                                       MemorySize=256, Architectures=["arm64"], Environment={"Variables": fenv},
                                       Tags=TAGS)["FunctionArn"]
            break
        except lam.exceptions.ResourceConflictException:
            farn = lam.update_function_code(FunctionName=TRIGGER_FN, ZipFile=code)["FunctionArn"]
            lam.get_waiter("function_updated_v2").wait(FunctionName=TRIGGER_FN)
            lam.update_function_configuration(FunctionName=TRIGGER_FN, Role=trole, Timeout=120,
                                              Environment={"Variables": fenv})
            break
        except lam.exceptions.InvalidParameterValueException as e:
            if "assume" in str(e) and attempt < 5:
                time.sleep(5)
                continue
            raise
    lam.get_waiter("function_updated_v2").wait(FunctionName=TRIGGER_FN)
    lam.put_function_event_invoke_config(FunctionName=TRIGGER_FN, MaximumRetryAttempts=0)   # one run per event

    topic = sns.create_topic(Name=TOPIC, Attributes={"KmsMasterKeyId": "alias/aws/sns"}, Tags=[{"Key": "project", "Value": "anyco-agentid"}])["TopicArn"]
    # Whoever publishes makes the agent act as the event source, so only the producer may publish:
    # here the console operator (the console's "Publish to SNS"). The agent's token names the
    # configured event source, not the individual publisher.
    import kms_keys
    sns.set_topic_attributes(TopicArn=topic, AttributeName="Policy", AttributeValue=json.dumps({
        "Version": "2012-10-17", "Statement": [
            {"Sid": "OnlyTheProducerPublishes", "Effect": "Allow", "Principal": {"AWS": kms_keys.operator_arn()},
             "Action": "sns:Publish", "Resource": topic},
            {"Sid": "ThisAccountSubscribes", "Effect": "Allow", "Principal": {"AWS": f"arn:aws:iam::{ACCT}:root"},
             "Action": ["sns:Subscribe", "sns:GetTopicAttributes"], "Resource": topic}]}))
    try:
        lam.add_permission(FunctionName=TRIGGER_FN, StatementId="sns-invoke", Action="lambda:InvokeFunction",
                           Principal="sns.amazonaws.com", SourceArn=topic, SourceAccount=ACCT)
    except lam.exceptions.ResourceConflictException:
        pass
    sns.subscribe(TopicArn=topic, Protocol="lambda", Endpoint=farn)
    C.save_state(event_topic_arn=topic, event_trigger_arn=farn)
    yield f"SNS {TOPIC} (KMS-encrypted, only the console operator publishes) -> Lambda {TRIGGER_FN} (kms:Sign as the event source; no AWS rights on the agent: it calls with T1)"
    yield "done"


def destroy():
    st = C.state()
    if st.get("event_topic_arn"):
        for s in sns.list_subscriptions_by_topic(TopicArn=st["event_topic_arn"]).get("Subscriptions", []):
            if s["SubscriptionArn"].startswith("arn:"):
                sns.unsubscribe(SubscriptionArn=s["SubscriptionArn"])
        sns.delete_topic(TopicArn=st["event_topic_arn"])
        yield f"SNS topic {TOPIC} deleted"
    try:
        lam.delete_function(FunctionName=TRIGGER_FN)
        yield f"Lambda {TRIGGER_FN} deleted"
    except lam.exceptions.ResourceNotFoundException:
        pass
    for key in ("event_runtime_id", "event_mcp_runtime_id"):
        if st.get(key):
            try:
                ac.delete_agent_runtime(agentRuntimeId=st[key])
                yield f"Runtime {st[key]} deleted"
            except Exception as e:
                yield f"runtime {st[key]}: {str(e)[:120]}"
    yield from drop_gateway(st)
    st = C.state()
    for name in (STEP1, STEP2):
        try:
            ac.delete_oauth2_credential_provider(name=name)
        except Exception:
            pass
    try:
        ac.delete_workload_identity(name=WORKLOAD)
    except Exception:
        pass
    yield f"AgentCore Identity providers {STEP1}, {STEP2} and workload identity {WORKLOAD} deleted"
    for k in [k for k in st if k.startswith("event_")]:
        st.pop(k, None)
    C.STATE_FILE.write_text(json.dumps(st, indent=2))
    yield "done"


if __name__ == "__main__":
    for line in deploy():
        print(line, flush=True)
