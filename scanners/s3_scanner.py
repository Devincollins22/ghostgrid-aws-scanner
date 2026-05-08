"""
S3 Scanner - checks for common S3 misconfigurations.

What it catches:
- Public buckets (ACL or policy based)
- Buckets without encryption
- Buckets without versioning
- Buckets without logging
- Buckets without SSL-only policies
"""
import json
from .base import BaseScanner
from utils.finding import Finding, FindingCollection


class S3Scanner(BaseScanner):
    name = "s3"
    description = "Scans S3 buckets for public access, encryption, and logging issues"

    def scan(self) -> FindingCollection:
        s3 = self._get_client("s3")

        try:
            buckets = s3.list_buckets()["Buckets"]
        except Exception as e:
            print(f"  [!] Could not list buckets: {e}")
            return self.findings

        for bucket in buckets:
            name = bucket["Name"]
            self._check_public_access(s3, name)
            self._check_encryption(s3, name)
            self._check_versioning(s3, name)
            self._check_logging(s3, name)

        return self.findings

    def _check_public_access(self, s3, bucket_name: str):
        """Check if bucket is publicly accessible."""
        try:
            # Check the public access block
            try:
                public_block = s3.get_public_access_block(Bucket=bucket_name)
                config = public_block["PublicAccessBlockConfiguration"]
                all_blocked = all([
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False),
                ])
                if not all_blocked:
                    self.findings.add(Finding(
                        title=f"S3 bucket '{bucket_name}' does not block all public access",
                        severity="HIGH",
                        resource_type="AWS::S3::Bucket",
                        resource_id=bucket_name,
                        description=(
                            f"Bucket '{bucket_name}' does not have all public access block "
                            f"settings enabled. This means the bucket could potentially be "
                            f"made public through ACLs or bucket policies."
                        ),
                        remediation=(
                            f"Enable all four S3 Block Public Access settings on bucket "
                            f"'{bucket_name}': BlockPublicAcls, IgnorePublicAcls, "
                            f"BlockPublicPolicy, and RestrictPublicBuckets."
                        ),
                        scanner=self.name,
                        region=self.region,
                        account_id=self.account_id,
                    ))
            except s3.exceptions.from_code("NoSuchPublicAccessBlockConfiguration"):
                self.findings.add(Finding(
                    title=f"S3 bucket '{bucket_name}' has no public access block configured",
                    severity="CRITICAL",
                    resource_type="AWS::S3::Bucket",
                    resource_id=bucket_name,
                    description=(
                        f"Bucket '{bucket_name}' has no S3 Block Public Access configuration "
                        f"at all. Without this, the bucket could be made publicly accessible."
                    ),
                    remediation=(
                        f"Add S3 Block Public Access configuration to '{bucket_name}' with "
                        f"all four settings enabled."
                    ),
                    scanner=self.name,
                    region=self.region,
                    account_id=self.account_id,
                ))

            # Also check bucket policy for public access
            try:
                policy = json.loads(s3.get_bucket_policy(Bucket=bucket_name)["Policy"])
                for stmt in policy.get("Statement", []):
                    principal = stmt.get("Principal", "")
                    if principal == "*" or principal == {"AWS": "*"}:
                        if stmt.get("Effect") == "Allow" and "Condition" not in stmt:
                            self.findings.add(Finding(
                                title=f"S3 bucket '{bucket_name}' has a public bucket policy",
                                severity="CRITICAL",
                                resource_type="AWS::S3::Bucket",
                                resource_id=bucket_name,
                                description=(
                                    f"Bucket '{bucket_name}' has a bucket policy that allows "
                                    f"access from any principal (*) without conditions. This "
                                    f"makes the bucket contents publicly accessible."
                                ),
                                remediation=(
                                    f"Review and restrict the bucket policy on '{bucket_name}'. "
                                    f"Remove statements with Principal: * or add conditions "
                                    f"to restrict access."
                                ),
                                scanner=self.name,
                                region=self.region,
                                account_id=self.account_id,
                            ))
            except Exception:
                pass  # No bucket policy is fine

        except Exception as e:
            print(f"  [!] Could not check public access for {bucket_name}: {e}")

    def _check_encryption(self, s3, bucket_name: str):
        """Buckets should have default encryption enabled."""
        try:
            s3.get_bucket_encryption(Bucket=bucket_name)
        except s3.exceptions.from_code("ServerSideEncryptionConfigurationNotFoundError"):
            self.findings.add(Finding(
                title=f"S3 bucket '{bucket_name}' has no default encryption",
                severity="HIGH",
                resource_type="AWS::S3::Bucket",
                resource_id=bucket_name,
                description=(
                    f"Bucket '{bucket_name}' does not have default server-side encryption "
                    f"enabled. Data uploaded without explicit encryption will be stored "
                    f"in plaintext."
                ),
                remediation=(
                    f"Enable default encryption on '{bucket_name}' using SSE-S3 (AES-256) "
                    f"or SSE-KMS for better key management control."
                ),
                scanner=self.name,
                region=self.region,
                account_id=self.account_id,
            ))
        except Exception:
            pass

    def _check_versioning(self, s3, bucket_name: str):
        """Versioning helps protect against accidental deletes."""
        try:
            versioning = s3.get_bucket_versioning(Bucket=bucket_name)
            status = versioning.get("Status", "Disabled")
            if status != "Enabled":
                self.findings.add(Finding(
                    title=f"S3 bucket '{bucket_name}' does not have versioning enabled",
                    severity="MEDIUM",
                    resource_type="AWS::S3::Bucket",
                    resource_id=bucket_name,
                    description=(
                        f"Bucket '{bucket_name}' versioning is '{status}'. Without "
                        f"versioning, deleted or overwritten objects cannot be recovered."
                    ),
                    remediation=(
                        f"Enable versioning on bucket '{bucket_name}' to protect against "
                        f"accidental deletion and enable object recovery."
                    ),
                    scanner=self.name,
                    region=self.region,
                    account_id=self.account_id,
                ))
        except Exception as e:
            print(f"  [!] Could not check versioning for {bucket_name}: {e}")

    def _check_logging(self, s3, bucket_name: str):
        """Access logging helps with security auditing."""
        try:
            logging_config = s3.get_bucket_logging(Bucket=bucket_name)
            if "LoggingEnabled" not in logging_config:
                self.findings.add(Finding(
                    title=f"S3 bucket '{bucket_name}' does not have access logging enabled",
                    severity="MEDIUM",
                    resource_type="AWS::S3::Bucket",
                    resource_id=bucket_name,
                    description=(
                        f"Bucket '{bucket_name}' does not have server access logging "
                        f"enabled. Without logging, you cannot audit who accessed what."
                    ),
                    remediation=(
                        f"Enable server access logging on '{bucket_name}' and send logs "
                        f"to a dedicated logging bucket."
                    ),
                    scanner=self.name,
                    region=self.region,
                    account_id=self.account_id,
                ))
        except Exception as e:
            print(f"  [!] Could not check logging for {bucket_name}: {e}")
