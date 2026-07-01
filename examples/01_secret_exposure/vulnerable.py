"""
Vulnerable: Hardcoded credentials — SECRET_EXPOSURE

Run: mcp-sentinel scan examples/01_secret_exposure/vulnerable.py
Expected: CRITICAL SECRET_EXPOSURE findings
"""
import os
from mcp.server.fastmcp import FastMCP

# VULNERABLE: hardcoded AWS credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_REGION = "us-east-1"

# VULNERABLE: hardcoded AI provider key
OPENAI_API_KEY = "sk-proj-T9xKabcDEFGHIJKL1234567890mnopqrstuvwxyz"
ANTHROPIC_API_KEY = "sk-ant-api03-XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX-XXXXXXXXXX"

# VULNERABLE: database connection string with embedded password
DATABASE_URL = "postgresql://admin:SuperSecretPass123!@prod-db.example.com:5432/customers"

# VULNERABLE: JWT signing secret in source code
JWT_SECRET = "my-super-secret-jwt-key-never-share-this-in-production"

# VULNERABLE: GitHub personal access token
GITHUB_TOKEN = "ghp_16C7e42F292c6912E7710c838347Ae178B4a"

mcp = FastMCP("Vulnerable Server")

@mcp.tool()
def get_cloud_resources():
    """List AWS resources — uses hardcoded credentials above."""
    import boto3
    session = boto3.Session(
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    ec2 = session.client("ec2", region_name=AWS_REGION)
    return ec2.describe_instances()
