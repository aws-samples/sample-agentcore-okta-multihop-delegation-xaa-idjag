"""Shared base for Patterns B and C: deploy / destroy, as generators of log lines (the console streams them).

  Okta              engineers sign in (anyco-users-as auth server, scope pr-agent.invoke); set up by hand (docs/okta-setup.md)
  DynamoDB          reviews + trace records (tools, interceptor, event trigger)
  Tools             mock GitHub + context service (Lambda), behind the Gateway
  Interceptor       stamps caller.* from the agent's headers and the inbound token; records each call
  AgentCore Policy  the Cedar engine; each pattern adds its own permits
  Gateway role      the service role the Gateway uses to invoke the Lambdas and the policy engine
  Code bucket       private S3 bucket for the Runtimes' code (agent.zip)
"""
import config as C
import deploy_aws as D

S = C.session()
ac, s3 = D.ac, S.client("s3")
REG, ACCT = C.REGION, C.ACCOUNT


def deploy():
    st = C.state()
    ok = st.get("okta")
    if not ok:
        raise RuntimeError("No Okta values: follow docs/okta-setup.md, then run okta_values.py")
    yield f"Okta: users sign in at {ok['users_issuer']} (scope pr-agent.invoke)"

    try:
        D.ddb.create_table(TableName=C.N["table"], BillingMode="PAY_PER_REQUEST",
                           AttributeDefinitions=[{"AttributeName": "pk", "AttributeType": "S"},
                                                 {"AttributeName": "sk", "AttributeType": "S"}],
                           KeySchema=[{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
                           Tags=[{"Key": "project", "Value": "anyco-agentid"}])
        D.ddb.get_waiter("table_exists").wait(TableName=C.N["table"])
    except D.ddb.exceptions.ResourceInUseException:
        pass
    # records carry review text, tool arguments and identity claims: expire them about a day after
    # they're written (each record sets ttl = write time + 86400; DynamoDB deletes expired items
    # asynchronously, usually within a few days, so this isn't an exact 24-hour deletion)
    ttl = D.ddb.describe_time_to_live(TableName=C.N["table"])["TimeToLiveDescription"]
    if ttl.get("TimeToLiveStatus") not in ("ENABLED", "ENABLING"):
        D.ddb.update_time_to_live(TableName=C.N["table"],
                                  TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"})
    yield f"DynamoDB: {C.N['table']} · TTL on attribute ttl (records expire about a day after they're written)"
    table_arn = f"arn:aws:dynamodb:{REG}:{ACCT}:table/{C.N['table']}"
    lrole = D.role(C.N["lambda_role"], "lambda.amazonaws.com", [
        {"Effect": "Allow", "Action": ["dynamodb:PutItem", "dynamodb:Query"], "Resource": table_arn},
        {"Effect": "Allow", "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
         "Resource": f"arn:aws:logs:{REG}:{ACCT}:log-group:/aws/lambda/anyco-agentid-*"}])
    tools_arn = D.function(C.N["tools_fn"], "lambdas/tools.py", "tools.lambda_handler", lrole, C.N["table"])
    icpt_arn = D.function(C.N["interceptor_fn"], "lambdas/interceptor.py", "interceptor.lambda_handler", lrole, C.N["table"])
    yield "Lambda: tools (mock GitHub + context) and interceptor ready"

    pe = D.find_named(ac.list_policy_engines, "policyEngines", C.N["policy_engine"])
    if not pe:
        pe = ac.create_policy_engine(name=C.N["policy_engine"], description="AnyCompany agent-identity Cedar", tags={"project": "anyco-agentid"})
    pe = D.wait(lambda: ac.get_policy_engine(policyEngineId=pe["policyEngineId"]), label="policy engine")
    C.save_state(policy_engine_id=pe["policyEngineId"], policy_engine_arn=pe["policyEngineArn"])
    yield f"AgentCore Policy: engine {pe['policyEngineId']}"

    D.role(C.N["gateway_role"], "bedrock-agentcore.amazonaws.com", [
        {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": [tools_arn, icpt_arn]},
        {"Effect": "Allow", "Action": ["bedrock-agentcore:GetPolicyEngine", "bedrock-agentcore:AuthorizeAction",
                                       "bedrock-agentcore:PartiallyAuthorizeActions"],
         "Resource": [f"arn:aws:bedrock-agentcore:{REG}:{ACCT}:policy-engine/*",
                      f"arn:aws:bedrock-agentcore:{REG}:{ACCT}:gateway/*"]}])
    yield f"IAM: gateway service role {C.N['gateway_role']} (invokes the tool Lambdas and the interceptor)"

    b = C.N["code_bucket"]
    try:
        s3.create_bucket(Bucket=b, CreateBucketConfiguration={"LocationConstraint": REG})
    except s3.exceptions.BucketAlreadyOwnedByYou:
        pass
    except s3.exceptions.BucketAlreadyExists:
        raise RuntimeError(f"S3 bucket {b} exists in another account: set a different ANYCO bucket name, never upload there")
    s3.head_bucket(Bucket=b, ExpectedBucketOwner=ACCT)            # fails unless this account owns it
    s3.put_public_access_block(Bucket=b, PublicAccessBlockConfiguration={
        k: True for k in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")})
    s3.upload_file(str(C.ROOT / "build" / "agent.zip"), b, "agent.zip", ExtraArgs={"ExpectedBucketOwner": ACCT})
    yield "Code: agent.zip uploaded (private bucket)"
    yield "done"


def destroy():
    yield "Shared base kept (Lambdas, table, policy engine, roles, bucket); teardown.py removes it"
    yield "done"


if __name__ == "__main__":
    for line in deploy():
        print(line, flush=True)
