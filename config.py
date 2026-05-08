"""
GhostGrid AWS Scanner - Configuration
"""
import os


# AWS config - uses your default AWS credentials (aws configure)
AWS_REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-2")

# Claude API for AI-powered analysis
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY", "")

# Severity levels
CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

SEVERITY_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}
