"""Pattern B · Cross App Access with a user (Okta for AI Agents, ID-JAG): deploy / destroy as
generators of log lines. Needs Pattern A deployed (its Gateway) and the Pattern B Okta values (okta_values.py).

  AgentCore Identity   two CustomOauth2 providers, both private_key_jwt signed with the agent's
                       KMS key (no client secret):
                         anyco-xaa-step1  Okta org AS · TOKEN_EXCHANGE  T2 -> ID-JAG
                         anyco-xaa-step2  anyco-gateway-as · JWT_AUTHORIZATION_GRANT  ID-JAG -> token
  Runtime B            same Strands agent code, AGENT_MODE=xaa, CUSTOM_JWT inbound: only T2s from
                       anyco-agent-b-as issued to your backend's AI agent (custom claim cid);
                       Authorization passed through to the code (request-header allowlist)
  Workload identity    anyco-pr-agent-xaa-delegate (standalone): binds the ID-JAG as step 2's subject
                       (the Runtime binds T2, step 1's subject, itself)
  IAM role B           may bind JWTs to that workload identity and ask the two providers for
                       tokens; kms:Sign with the agent's key; no Gateway IAM
  the Gateway (reused)   CUSTOM_JWT, Okta anyco-gateway-as, aud api://anyco-gateway-aud
  Cedar (B permits)    cid == the AI agent AND act names the AI agent AND uid AND the scope
"""
import json
import time

import config as C
import deploy_aws as D
import release as R

ac = D.ac
REG, ACCT = C.REGION, C.ACCOUNT
RT_NAME = "anyco_pr_agent_xaa"
ROLE = "anyco-agentid-runtime-xaa-role"
TOOLS = ["github___get_pull_request", "github___post_review", "github___list_my_reviews"]
PREFIX = "AnycoB_"
STEP1, STEP2 = "anyco-xaa-step1", "anyco-xaa-step2"
# A standalone workload identity: the Runtime's own one is "linked to a service" and refuses
# GetWorkloadAccessTokenForJWT from the caller (seen), which both steps need.
WORKLOAD = "anyco-pr-agent-xaa-delegate"


def provider(name, discovery, grant, xa):
    """An AgentCore Identity provider that authenticates to Okta as the AI agent (private_key_jwt, KMS)."""
    obo = {"grantType": grant}
    if grant == "TOKEN_EXCHANGE":
        obo["tokenExchangeGrantTypeConfig"] = {"actorTokenContent": "NONE"}
    cfg = {"customOauth2ProviderConfig": {
        "oauthDiscovery": {"discoveryUrl": discovery}, "clientId": xa["client_id"],
        "clientAuthenticationMethod": "PRIVATE_KEY_JWT",
        "privateKeyJwtConfig": {"privateKeySource": {"kmsKeySource": {"kmsKeyArn": xa["kms_key_arn"]}},
                                "signingAlgorithm": "RS256", "additionalHeaderClaims": {"kid": xa["kms_kid"]}},
        "onBehalfOfTokenExchangeConfig": obo}}
    try:
        ac.create_oauth2_credential_provider(name=name, credentialProviderVendor="CustomOauth2",
                                             oauth2ProviderConfigInput=cfg, tags={"project": "anyco-agentid"})
    except (ac.exceptions.ConflictException, ac.exceptions.ValidationException) as e:
        if "already exists" not in str(e) and not isinstance(e, ac.exceptions.ConflictException):
            raise
        ac.update_oauth2_credential_provider(name=name, credentialProviderVendor="CustomOauth2", oauth2ProviderConfigInput=cfg)


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
            f'  principal.hasTag("act") && principal.getTag("act") like "*\\"{agent_cid}\\"*" &&\n'
            # the trail: your backend acted before the agent
            f'  principal.getTag("act") like "*\\"{backend_cid}\\"*" &&\n'
            '  principal.hasTag("uid") &&\n'
            f'  principal.hasTag("scp") && principal.getTag("scp") like "*\\"{scope}\\"*"\n'
            "};")
    return out


def deploy():
    st = C.state()
    ok, xa = st.get("okta"), st.get("xaa")
    if not st.get("gateway_b_id"):
        raise RuntimeError("Deploy Pattern A first (its Gateway is reused)")
    if not xa:
        raise RuntimeError("No OKTA_AGENT_B_* values: set up Pattern B in Okta (docs/okta-setup.md), then run okta_values.py")
    if not xa.get("kms_key_arn"):
        raise RuntimeError("Run kms_keys.py first (the agent's KMS signing key)")
    gid, gw_arn, gw_url = st["gateway_b_id"], st["gateway_b_arn"], st["gateway_b_url"]
    yield f"Okta AI agent {xa['client_id']} (ACTIVE · private_key_jwt · connection to anyco-gateway-as {' '.join(xa['scopes'])})"
    yield f"Reusing the Gateway: {gid} (CUSTOM_JWT · Okta anyco-gateway-as · aud {ok['gateway_audience']})"

    lrole = D.iam.get_role(RoleName=C.N["lambda_role"])["Role"]["Arn"]
    D.function(C.N["tools_fn"], "lambdas/tools.py", "tools.lambda_handler", lrole, C.N["table"])
    D.function(C.N["interceptor_fn"], "lambdas/interceptor.py", "interceptor.lambda_handler", lrole, C.N["table"])
    yield "Lambda: tools + interceptor updated (the interceptor stamps acting_agent from the act claim)"

    R.apply_policies(ac, st["policy_engine_id"], permits(gw_arn, xa["client_id"], xa["backend_agent_client_id"]), PREFIX)
    yield "AgentCore Policy: Pattern B permits attached (cid = AI agent · act names the AI agent and the backend · uid · scope)"

    provider(STEP1, f"{C.OKTA_DOMAIN}/.well-known/openid-configuration", "TOKEN_EXCHANGE", xa)
    provider(STEP2, f"{ok['gateway_issuer']}/.well-known/openid-configuration", "JWT_AUTHORIZATION_GRANT", xa)
    try:
        ac.create_workload_identity(name=WORKLOAD, tags={"project": "anyco-agentid"})
    except Exception as e:
        if "already exists" not in str(e) and "Conflict" not in type(e).__name__:
            raise
    yield (f"AgentCore Identity: workload identity {WORKLOAD} · {STEP1} (Okta org AS · TOKEN_EXCHANGE) + {STEP2} (anyco-gateway-as · "
           f"JWT_AUTHORIZATION_GRANT) · private_key_jwt with KMS key {xa['kms_kid']}")

    wid = f"arn:aws:bedrock-agentcore:{REG}:{ACCT}:workload-identity-directory/default"
    vault = f"arn:aws:bedrock-agentcore:{REG}:{ACCT}:token-vault/default"
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
        {"Effect": "Allow", "Action": "bedrock-agentcore:GetWorkloadAccessTokenForJWT",
         "Resource": [wid, f"{wid}/workload-identity/{WORKLOAD}"]},
        {"Effect": "Allow", "Action": "bedrock-agentcore:GetResourceOauth2Token",
         "Resource": [vault, wid, f"{wid}/workload-identity/{WORKLOAD}", f"{wid}/workload-identity/{RT_NAME}*",
                      f"{vault}/oauth2credentialprovider/{STEP1}", f"{vault}/oauth2credentialprovider/{STEP2}"]},
        {"Effect": "Allow", "Action": "kms:Sign", "Resource": xa["kms_key_arn"]},
    ])
    yield f"IAM: {ROLE} (its workload identity, the two providers, kms:Sign on the agent's key; no Gateway IAM rights)"

    s3 = C.session().client("s3")
    s3.upload_file(str(C.ROOT / "build" / "agent.zip"), C.N["code_bucket"], "agent.zip", ExtraArgs={"ExpectedBucketOwner": C.ACCOUNT})
    artifact = {"codeConfiguration": {"code": {"s3": {"bucket": C.N["code_bucket"], "prefix": "agent.zip"}},
                                      "runtime": "PYTHON_3_13", "entryPoint": ["main.py"]}}
    # inbound: only T2s, which your backend (the AI agent anyco-backend-agent-oai) got by XAA at anyco-agent-b-as
    auth = {"customJWTAuthorizer": {"discoveryUrl": f"{xa['agent_b_issuer']}/.well-known/openid-configuration",
                                    "allowedAudience": [xa["agent_b_audience"]], "allowedScopes": ["agent-b.invoke"],
                                    # Okta names the client in cid (allowedClients checks client_id)
                                    "customClaims": [{"inboundTokenClaimName": "cid", "inboundTokenClaimValueType": "STRING",
                                                      "authorizingClaimMatchValue": {"claimMatchOperator": "EQUALS",
                                                                                     "claimMatchValue": {"matchValueString": xa["backend_agent_client_id"]}}}]}}
    env = {"AGENT_MODE": "xaa", "GATEWAY_URL": gw_url, "MODEL_ID": C.MODEL_ID, "AGENT_ID": C.AGENT_ID,
           "OKTA_DOMAIN": C.OKTA_DOMAIN, "XAA_CLIENT_ID": xa["client_id"], "XAA_CUSTOM_AS_ISSUER": ok["gateway_issuer"],
           "XAA_SCOPE": " ".join(xa["scopes"]), "XAA_WORKLOAD": WORKLOAD,
           "XAA_BACKEND_CLIENT_ID": xa["backend_agent_client_id"], "XAA_AGENT_AUDIENCE": xa["agent_b_audience"], "XAA_STEP1_PROVIDER": STEP1, "XAA_STEP2_PROVIDER": STEP2,
           "AGENT_BUILD": "xaa"}
    found = D.find_named(ac.list_agent_runtimes, "agentRuntimes", RT_NAME, field="agentRuntimeName")
    kw = dict(agentRuntimeArtifact=artifact, roleArn=role_arn, networkConfiguration={"networkMode": "PUBLIC"},
              protocolConfiguration={"serverProtocol": "AGUI"}, authorizerConfiguration=auth, environmentVariables=env,
              requestHeaderConfiguration={"requestHeaderAllowlist": ["Authorization"]})
    if not found:
        for attempt in range(6):
            try:
                r = ac.create_agent_runtime(agentRuntimeName=RT_NAME, **kw, tags={"project": "anyco-agentid"},
                                            description="AnyCompany PR Review Agent, Cross App Access (Okta ID-JAG)")
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
    C.save_state(runtime_c_id=rid, runtime_c_arn=rarn, runtime_c_version=ver)
    yield f"Runtime B: {rid} version {ver} (Strands, our env var AGENT_MODE=xaa, Okta JWT inbound, Authorization passed to code)"
    yield "done"


def destroy():
    st = C.state()
    if st.get("runtime_c_id"):
        try:
            ac.delete_agent_runtime(agentRuntimeId=st["runtime_c_id"])
        except Exception as e:
            yield f"runtime C: {str(e)[:120]}"
        yield f"Runtime B {st['runtime_c_id']} deleted"
    if st.get("policy_engine_id"):
        R.apply_policies(ac, st["policy_engine_id"], {}, PREFIX)
        yield "Pattern B permits deleted"
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
    for k in ("runtime_c_id", "runtime_c_arn", "runtime_c_version"):
        st.pop(k, None)
    C.STATE_FILE.write_text(json.dumps(st, indent=2))
    yield "done"


if __name__ == "__main__":
    for line in deploy():
        print(line, flush=True)
