# GhostGrid AWS Scanner

AI-powered AWS vulnerability scanner. Finds misconfigurations, then uses Claude to analyze attack paths and prioritize remediation.

## What It Scans

| Scanner | What It Checks |
|---------|---------------|
| **IAM** | Root MFA, user MFA, old access keys, admin policies, inline policies |
| **S3** | Public buckets, encryption, versioning, access logging |
| **EC2** | IMDSv1 (SSRF risk), default security groups, unencrypted EBS, public IPs |
| **Security Groups** | Open SSH/RDP/DB ports, unrestricted ingress, permissive egress |

## Quick Start

```bash
# 1. Install dependencies
pip install -r requirements.txt

# 2. Configure AWS credentials (if not already done)
aws configure

# 3. Set your Anthropic API key (for AI analysis)
export ANTHROPIC_API_KEY="sk-ant-..."

# 4. Run the scanner
python scan.py
```

## Usage

```bash
# Full scan with AI analysis
python scan.py

# Scan specific services only
python scan.py --scanners iam s3

# Skip AI analysis (just raw findings)
python scan.py --no-ai

# Output as JSON (for piping to other tools)
python scan.py --json-output

# Save report to file
python scan.py --output report.md

# Scan a different region
python scan.py --region us-west-2
```

## Project Structure

```
ghostgrid-aws-scanner/
├── scan.py              # CLI entry point
├── config.py            # Configuration
├── requirements.txt     # Python dependencies
├── scanners/            # AWS scanning modules
│   ├── base.py          # Base scanner class
│   ├── iam_scanner.py   # IAM checks
│   ├── s3_scanner.py    # S3 checks
│   ├── ec2_scanner.py   # EC2 checks
│   └── sg_scanner.py    # Security group checks
├── ai/                  # AI analysis layer
│   └── analyzer.py      # Claude-powered risk assessment
├── utils/               # Shared utilities
│   └── finding.py       # Finding data model
└── reports/             # Generated reports go here
```

## Adding New Scanners

Create a new file in `scanners/`, inherit from `BaseScanner`:

```python
from .base import BaseScanner
from utils.finding import Finding, FindingCollection

class MyScanner(BaseScanner):
    name = "my_scanner"
    description = "Checks for XYZ"

    def scan(self) -> FindingCollection:
        client = self._get_client("service-name")
        # Your checks here
        self.findings.add(Finding(
            title="Something bad",
            severity="HIGH",
            resource_type="AWS::Service::Resource",
            resource_id="resource-id",
            description="What's wrong",
            remediation="How to fix it",
            scanner=self.name,
            region=self.region,
            account_id=self.account_id,
        ))
        return self.findings
```

Then add it to `scanners/__init__.py`.

## Required AWS Permissions

The scanner needs read-only access. Attach the `SecurityAudit` managed policy or these specific permissions:

- `iam:GetAccountSummary`, `iam:ListUsers`, `iam:ListMFADevices`, `iam:GetLoginProfile`
- `iam:ListAccessKeys`, `iam:ListPolicies`, `iam:GetPolicyVersion`, `iam:ListUserPolicies`
- `s3:ListAllMyBuckets`, `s3:GetBucketPublicAccessBlock`, `s3:GetBucketPolicy`
- `s3:GetBucketEncryption`, `s3:GetBucketVersioning`, `s3:GetBucketLogging`
- `ec2:DescribeInstances`, `ec2:DescribeVolumes`, `ec2:DescribeSecurityGroups`
- `sts:GetCallerIdentity`

## Next Steps / Ideas

- [ ] Add Lambda scanner (public functions, execution role checks)
- [ ] Add RDS scanner (public instances, encryption, backups)
- [ ] Add CloudTrail scanner (is it enabled? multi-region?)
- [ ] Add KMS scanner (key rotation, key policies)
- [ ] HTML report output with charts
- [ ] Multi-region scanning
- [ ] Scheduled scans with drift detection
- [ ] Client dashboard (web UI)
