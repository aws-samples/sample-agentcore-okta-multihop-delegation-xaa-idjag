"""Shared settings for the demo: names, region, Okta org, and the two state files.

state.json holds the ids the setup scripts create. .env holds your environment (Okta org,
AWS profile) and the secrets (Okta API token, client secrets, demo password). Both are
git-ignored; copy .env.example to .env to start.
"""
import json
import os
import pathlib

import boto3

ROOT = pathlib.Path(__file__).resolve().parent
STATE_FILE = ROOT / "state.json"
ENV_FILE = ROOT / ".env"


def load_env():
    if ENV_FILE.exists():
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def required(name):
    value = os.environ.get(name)
    if not value:
        raise SystemExit(f"Set {name} in .env (see .env.example)")
    return value


load_env()

AWS_PROFILE = os.environ.get("ANYCO_AWS_PROFILE") or None     # None: the default credential chain
REGION = os.environ.get("ANYCO_AWS_REGION", "us-west-2")
ACCOUNT = os.environ.get("ANYCO_AWS_ACCOUNT") or \
    boto3.Session(profile_name=AWS_PROFILE, region_name=REGION).client("sts").get_caller_identity()["Account"]
MODEL_ID = os.environ.get("ANYCO_MODEL_ID", "us.anthropic.claude-sonnet-4-6")

OKTA_DOMAIN = required("ANYCO_OKTA_DOMAIN").rstrip("/")      # https://<your-org>.okta.com
CONSOLE_PORT = 8010
REDIRECT_URI = f"http://localhost:{CONSOLE_PORT}/callback"

# The one agent in the story (a Runtime environment variable; names the agent in its own logs).
AGENT_ID = "pr-review"

# Every tool on the gateway, the Okta scope that approves it, and what it does.
TOOLS = {
    "github___get_pull_request": {"scope": "pr:read", "label": "Read a pull request"},
    "github___post_review": {"scope": "pr:review", "label": "Post a review"},
    "github___merge_pull_request": {"scope": "pr:merge", "label": "Merge a pull request"},
    "github___list_my_reviews": {"scope": "pr:read", "label": "List my reviews"},
    "context___search_context": {"scope": "context:search", "label": "Search a context corpus"},
}

# What the agent may do on behalf of a signed-in engineer (pattern B).
OBO_TOOLS = ["github___get_pull_request", "github___post_review", "github___list_my_reviews"]

N = {
    "table": "anyco-agentid-records",
    "tools_fn": "anyco-agentid-tools",
    "interceptor_fn": "anyco-agentid-interceptor",
    "lambda_role": "anyco-agentid-lambda-role",
    "gateway_role": "anyco-agentid-gateway-role",
    "policy_engine": "anyco_agentid_policies",
    "obo_provider": "anyco-pr-review-agent-obo",
    "runtime_b": "anyco_pr_agent_obo",
    "code_bucket": f"anyco-agentid-code-{ACCOUNT}-{REGION}",
    "console_workload": "anyco-agentid-console",
}


def write_env(updates):
    """Add or replace keys in .env without printing values."""
    lines = ENV_FILE.read_text().splitlines() if ENV_FILE.exists() else []
    keys = set(updates)
    kept = [l for l in lines if l.split("=", 1)[0].strip() not in keys]
    kept += [f"{k}={v}" for k, v in updates.items()]
    ENV_FILE.write_text("\n".join(kept) + "\n")
    ENV_FILE.chmod(0o600)
    for k, v in updates.items():
        os.environ[k] = v


def state():
    return json.loads(STATE_FILE.read_text()) if STATE_FILE.exists() else {}


def save_state(**updates):
    s = state()
    s.update(updates)
    STATE_FILE.write_text(json.dumps(s, indent=2))
    return s


def session():
    return boto3.Session(profile_name=AWS_PROFILE, region_name=REGION)
