"""
Safe: Credentials loaded from environment variables only.
"""
import os
from mcp.server.fastmcp import FastMCP

# SAFE: all secrets from environment — never hardcoded
AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
AWS_REGION = os.getenv("AWS_REGION", "us-east-1")

OPENAI_API_KEY = os.environ["OPENAI_API_KEY"]
DATABASE_URL = os.environ["DATABASE_URL"]
JWT_SECRET = os.environ["JWT_SECRET"]

mcp = FastMCP("Safe Server")

@mcp.tool()
def get_cloud_resources():
    """List AWS resources using environment credentials."""
    import boto3
    # boto3 automatically uses AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from env
    ec2 = boto3.client("ec2", region_name=AWS_REGION)
    return ec2.describe_instances()
