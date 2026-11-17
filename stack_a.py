"""Pattern A · OBO/Delegation (token exchange) stack: deploy / destroy as generators of log lines.

Reuses the shared base (stack.py): tool Lambdas, interceptor, table, policy engine. Adds:

  Credential provider  the agent's Okta app, grant TOKEN_EXCHANGE (RFC 8693), no actor token
  Runtime A            same Strands agent code, AGENT_MODE=obo, CUSTOM_JWT inbound (engineer's token)
  IAM role A           may ask AgentCore Identity for the exchange (no Gateway IAM rights needed)
  the Gateway            CUSTOM_JWT inbound: trusts Okta anyco-gateway-as, aud api://anyco-gateway-aud
  Cedar (A permits)    cid == the agent's Okta app AND uid present AND the tool's scope
"""
import json
import time

import config as C
import deploy_aws as D
import release as R

ac, iam = D.ac, D.iam
REG, ACCT = C.REGION, C.ACCOUNT
GW_NAME, RT_NAME = "anyco-agentid-gw-obo", "anyco_pr_agent_obo"
ROLE = "anyco-agentid-runtime-obo-role"
PROVIDER = C.N["obo_provider"]
TOOLS = ["github___get_pull_request", "github___post_review", "github___list_my_reviews"]
SCOPES = "pr:read pr:review"
PREFIX = "AnycoA_"


def permits(gw_arn, agent_cid, backend_cid):
    out = {}
    for tool in TOOLS:
        scope = C.TOOLS[tool]["scope"]
        out[f"{PREFIX}{tool.split('___', 1)[1]}"] = (
            "permit(\n  principal is AgentCore::OAuthUser,\n"
            f'  action == AgentCore::Action::"{tool}",\n'
            f'  resource == AgentCore::Gateway::"{gw_arn}"\n'
            ") when {\n"
            f'  principal.hasTag("cid") && principal.getTag("cid") == "{agent_cid}" &&\n'
            # the trail: the backend acted before the agent (act.act.sub)
            f'  principal.hasTag("act") && principal.getTag("act") like "*\\"{backend_cid}\\"*" &&\n'
            '  principal.hasTag("uid") &&\n'
            f'  principal.hasTag("scp") && principal.getTag("scp") like "*\\"{scope}\\"*"\n'
            "};")
    return out


def deploy():
    st = C.state()
    ok = st.get("okta")
    if not ok or not st.get("policy_engine_id"):
        raise RuntimeError("Deploy the shared base first (stack.py: Lambdas, policy engine, code bucket)")
    pe_id, pe_arn = st["policy_engine_id"], st["policy_engine_arn"]
    tools_arn = D.lam.get_function(FunctionName=C.N["tools_fn"])["Configuration"]["FunctionArn"]
    icpt_arn = D.lam.get_function(FunctionName=C.N["interceptor_fn"])["Configuration"]["FunctionArn"]
    grole = iam.get_role(RoleName=C.N["gateway_role"])["Role"]["Arn"]
    yield "Reusing the shared base: tool Lambdas, interceptor, policy engine, gateway service role"

    # gateway B: trusts Okta anyco-gateway-as tokens
    gw_kw = dict(name=GW_NAME, roleArn=grole, protocolType="MCP", authorizerType="CUSTOM_JWT",
                 authorizerConfiguration={"customJWTAuthorizer": {
                     "discoveryUrl": f"{ok['gateway_issuer']}/.well-known/openid-configuration",
                     "allowedAudience": [ok["gateway_audience"]]}},
                 interceptorConfigurations=[{"interceptor": {"lambda": {"arn": icpt_arn}},
                                             "interceptionPoints": ["REQUEST", "RESPONSE"],
                                             "inputConfiguration": {"passRequestHeaders": True}}],
                 exceptionLevel="DEBUG",
                 # Cedar in ENFORCE mode from creation: with no permit yet, every tool call is denied
                 # (default deny), so a deploy that stops before the permits leaves nothing callable
                 policyEngineConfiguration={"arn": pe_arn, "mode": "ENFORCE"})
    gw = D.find_named(ac.list_gateways, "items", GW_NAME)
    if not gw:
        gw = ac.create_gateway(**gw_kw, description="AnyCompany Pattern A (token exchange) and B (Cross App Access)", tags={"project": "anyco-agentid"})
    gid = gw["gatewayId"]
    gw = D.wait(lambda: ac.get_gateway(gatewayIdentifier=gid), label="gateway B")
    C.save_state(gateway_b_id=gid, gateway_b_arn=gw["gatewayArn"], gateway_b_url=gw["gatewayUrl"])
    yield f"Gateway: {gid} (CUSTOM_JWT · Okta anyco-gateway-as · aud {ok['gateway_audience']})"

    existing = {t["name"]: t for t in ac.list_gateway_targets(gatewayIdentifier=gid, maxResults=100)["items"]}
    for tname, tools in (("github", D.GITHUB_TOOLS), ("context", D.CONTEXT_TOOLS)):
        cfg = {"mcp": {"lambda": {"lambdaArn": tools_arn, "toolSchema": {"inlinePayload": tools}}}}
        creds = [{"credentialProviderType": "GATEWAY_IAM_ROLE"}]
        if tname in existing:
            tid = existing[tname]["targetId"]
            ac.update_gateway_target(gatewayIdentifier=gid, targetId=tid, name=tname, targetConfiguration=cfg,
                                     credentialProviderConfigurations=creds)
        else:
            tid = ac.create_gateway_target(gatewayIdentifier=gid, name=tname, targetConfiguration=cfg,
                                           credentialProviderConfigurations=creds)["targetId"]
        D.wait(lambda: ac.get_gateway_target(gatewayIdentifier=gid, targetId=tid), label=f"target {tname}")
    yield "Gateway targets: github, context (same tool Lambdas)"

    # the agent's one Okta app, as an RFC 8693 token-exchange client
    cfg = {"customOauth2ProviderConfig": {
        "oauthDiscovery": {"discoveryUrl": f"{ok['gateway_issuer']}/.well-known/openid-configuration"},
        "clientId": ok["agent_client_id"], "clientSecret": C.os.environ["OKTA_AGENT_CLIENT_SECRET"],
        "clientAuthenticationMethod": "CLIENT_SECRET_POST",
        "onBehalfOfTokenExchangeConfig": {"grantType": "TOKEN_EXCHANGE",
                                          "tokenExchangeGrantTypeConfig": {"actorTokenContent": "NONE"}}}}
    try:
        parn = ac.create_oauth2_credential_provider(name=PROVIDER, credentialProviderVendor="CustomOauth2",
                                                    oauth2ProviderConfigInput=cfg, tags={"project": "anyco-agentid"})["credentialProviderArn"]
    except (ac.exceptions.ConflictException, ac.exceptions.ValidationException) as e:
        if "already exists" not in str(e) and not isinstance(e, ac.exceptions.ConflictException):
            raise
        parn = ac.update_oauth2_credential_provider(name=PROVIDER, credentialProviderVendor="CustomOauth2",
                                                    oauth2ProviderConfigInput=cfg)["credentialProviderArn"]
    C.save_state(obo_provider_arn=parn)
    yield f"AgentCore Identity: credential provider {PROVIDER} (TOKEN_EXCHANGE · actor token NONE)"

    # Cedar for gateway B
    R.apply_policies(ac, pe_id, permits(gw["gatewayArn"], ok["agent_client_id"], ok["backend_client_id"]), PREFIX)
    ac.update_gateway(gatewayIdentifier=gid, **gw_kw)        # gw_kw keeps the policy engine in ENFORCE mode
    D.wait(lambda: ac.get_gateway(gatewayIdentifier=gid), label="gateway B update")
    yield "AgentCore Policy: Pattern A permits attached (cid = agent · act includes the backend · uid present · scope)"

    # runtime B role
    vault = f"arn:aws:bedrock-agentcore:{REG}:{ACCT}:token-vault/default"
    wid = f"arn:aws:bedrock-agentcore:{REG}:{ACCT}:workload-identity-directory/default"
    role_arn = D.role(ROLE, "bedrock-agentcore.amazonaws.com", [
        {"Effect": "Allow", "Action": ["bedrock:InvokeModel", "bedrock:InvokeModelWithResponseStream"],
         "Resource": ["arn:aws:bedrock:*::foundation-model/*", f"arn:aws:bedrock:{REG}:{ACCT}:inference-profile/*"]},
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents", "logs:DescribeLogStreams"],
         "Resource": f"arn:aws:logs:{REG}:{ACCT}:log-group:/aws/bedrock-agentcore/runtimes/*"},
        {"Effect": "Allow", "Action": "logs:DescribeLogGroups", "Resource": f"arn:aws:logs:{REG}:{ACCT}:log-group:*"},
        {"Effect": "Allow", "Action": ["xray:PutTraceSegments", "xray:PutTelemetryRecords", "xray:GetSamplingRules",
                                       "xray:GetSamplingTargets"], "Resource": "*"},
        {"Effect": "Allow", "Action": "cloudwatch:PutMetricData", "Resource": "*",
         "Condition": {"StringEquals": {"cloudwatch:namespace": "bedrock-agentcore"}}},
        {"Effect": "Allow", "Action": ["bedrock-agentcore:GetWorkloadAccessToken", "bedrock-agentcore:GetWorkloadAccessTokenForJWT"],
         "Resource": [wid, f"{wid}/workload-identity/{RT_NAME}*"]},
        {"Effect": "Allow", "Action": "bedrock-agentcore:GetResourceOauth2Token",
         "Resource": [vault, wid, f"{wid}/workload-identity/{RT_NAME}*", f"{vault}/oauth2credentialprovider/{PROVIDER}"]},
        {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue",
         "Resource": f"arn:aws:secretsmanager:{REG}:{ACCT}:secret:bedrock-agentcore-identity!default/oauth2/{PROVIDER}-*"},
    ])
    yield f"IAM: {ROLE} (token exchange via AgentCore Identity; no Gateway IAM rights)"

    # runtime B (the shared agent code, AGENT_MODE=obo)
    s3 = C.session().client("s3")
    s3.upload_file(str(C.ROOT / "build" / "agent.zip"), C.N["code_bucket"], "agent.zip", ExtraArgs={"ExpectedBucketOwner": C.ACCOUNT})
    artifact = {"codeConfiguration": {"code": {"s3": {"bucket": C.N["code_bucket"], "prefix": "agent.zip"}},
                                      "runtime": "PYTHON_3_13", "entryPoint": ["main.py"]}}
    # inbound: only tokens the backend got by token exchange at anyco-agent-a-as (cid = the backend)
    auth = {"customJWTAuthorizer": {"discoveryUrl": f"{ok['agent_a_issuer']}/.well-known/openid-configuration",
                                    "allowedAudience": [ok["agent_a_audience"]], "allowedScopes": ["agent-a.invoke"],
                                    "customClaims": [{"inboundTokenClaimName": "cid", "inboundTokenClaimValueType": "STRING",
                                                      "authorizingClaimMatchValue": {"claimMatchOperator": "EQUALS",
                                                                                     "claimMatchValue": {"matchValueString": ok["backend_client_id"]}}}]}}
    env = {"AGENT_MODE": "obo", "GATEWAY_URL": gw["gatewayUrl"], "MODEL_ID": C.MODEL_ID, "AGENT_ID": C.AGENT_ID,
           "OKTA_PROVIDER": PROVIDER, "DECLARED_SCOPES": SCOPES, "GATEWAY_AUDIENCE": ok["gateway_audience"],
           "AGENT_BUILD": "obo"}
    found = D.find_named(ac.list_agent_runtimes, "agentRuntimes", RT_NAME, field="agentRuntimeName")
    kw = dict(agentRuntimeArtifact=artifact, roleArn=role_arn, networkConfiguration={"networkMode": "PUBLIC"},
              protocolConfiguration={"serverProtocol": "AGUI"}, authorizerConfiguration=auth, environmentVariables=env)
    if not found:
        for attempt in range(6):
            try:
                r = ac.create_agent_runtime(agentRuntimeName=RT_NAME, **kw, tags={"project": "anyco-agentid"},
                                            description="AnyCompany PR Review Agent, Pattern A (token exchange)")
                break
            except ac.exceptions.ValidationException as e:
                if "role" in str(e).lower() and attempt < 5:
                    time.sleep(10)
                    continue
                raise
        rid, rarn, ver = r["agentRuntimeId"], r["agentRuntimeArn"], r["agentRuntimeVersion"]
    else:
        rid, rarn = found["agentRuntimeId"], found["agentRuntimeArn"]
        R.wait_runtime(ac, rid)
        ver = ac.update_agent_runtime(agentRuntimeId=rid, **kw)["agentRuntimeVersion"]
    R.wait_runtime(ac, rid)
    C.save_state(runtime_b_id=rid, runtime_b_arn=rarn, runtime_b_version=ver)
    yield f"Runtime A: {rid} version {ver} (Strands, our env var AGENT_MODE=obo, Okta JWT inbound)"
    yield "done"


def destroy():
    st = C.state()
    if st.get("runtime_b_id"):
        try:
            ac.delete_agent_runtime(agentRuntimeId=st["runtime_b_id"])
        except Exception as e:
            yield f"runtime B: {str(e)[:120]}"
        yield f"Runtime A {st['runtime_b_id']} deleted"
    if st.get("policy_engine_id"):
        R.apply_policies(ac, st["policy_engine_id"], {}, PREFIX)
        yield "Pattern A permits deleted"
    gid = st.get("gateway_b_id")
    if gid:
        for t in ac.list_gateway_targets(gatewayIdentifier=gid, maxResults=100)["items"]:
            ac.delete_gateway_target(gatewayIdentifier=gid, targetId=t["targetId"])
        for _ in range(30):
            if not ac.list_gateway_targets(gatewayIdentifier=gid, maxResults=100)["items"]:
                break
            time.sleep(3)
        try:
            ac.delete_gateway(gatewayIdentifier=gid)
        except Exception as e:
            yield f"gateway B: {str(e)[:120]}"
        yield f"the Gateway {gid} deleted"
    try:
        ac.delete_oauth2_credential_provider(name=PROVIDER)
    except Exception:
        pass
    for k in ("runtime_b_id", "runtime_b_arn", "runtime_b_version", "gateway_b_id", "gateway_b_arn", "gateway_b_url",
              "obo_provider_arn"):
        st.pop(k, None)
    C.STATE_FILE.write_text(json.dumps(st, indent=2))
    yield "done"


if __name__ == "__main__":
    for line in deploy():
        print(line, flush=True)
