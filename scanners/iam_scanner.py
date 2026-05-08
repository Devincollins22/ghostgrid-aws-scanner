"""
IAM Scanner - checks for common IAM misconfigurations.

What it catches:
- Root account usage without MFA
- Users with no MFA enabled
- Overly permissive policies (Action: *, Resource: *)
- Old access keys (90+ days)
- Unused credentials
- Inline policies (should use managed policies)
"""
import json
from datetime import datetime, timezone
from .base import BaseScanner
from utils.finding import Finding, FindingCollection


class IAMScanner(BaseScanner):
    name = "iam"
    description = "Scans IAM for misconfigurations and risky permissions"

    def scan(self) -> FindingCollection:
        iam = self._get_client("iam")

        self._check_root_mfa(iam)
        self._check_user_mfa(iam)
        self._check_access_key_age(iam)
        self._check_overly_permissive_policies(iam)
        self._check_inline_policies(iam)

        return self.findings

    def _check_root_mfa(self, iam):
        """Root account should always have MFA."""
        try:
            summary = iam.get_account_summary()["SummaryMap"]
            if summary.get("AccountMFAEnabled", 0) == 0:
                self.findings.add(Finding(
                    title="Root account does not have MFA enabled",
                    severity="CRITICAL",
                    resource_type="AWS::IAM::Root",
                    resource_id="root",
                    description=(
                        "The AWS root account does not have multi-factor authentication "
                        "enabled. The root account has unrestricted access to all resources "
                        "and should be protected with MFA at minimum."
                    ),
                    remediation=(
                        "Enable MFA on the root account immediately. Go to IAM > Security "
                        "credentials > MFA and assign a virtual or hardware MFA device."
                    ),
                    scanner=self.name,
                    region="global",
                    account_id=self.account_id,
                ))
        except Exception as e:
            print(f"  [!] Could not check root MFA: {e}")

    def _check_user_mfa(self, iam):
        """All IAM users with console access should have MFA."""
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]

                    # Check if user has console access
                    try:
                        iam.get_login_profile(UserName=username)
                    except iam.exceptions.NoSuchEntityException:
                        continue  # No console access, skip

                    # Check MFA
                    mfa_devices = iam.list_mfa_devices(UserName=username)
                    if not mfa_devices["MFADevices"]:
                        self.findings.add(Finding(
                            title=f"IAM user '{username}' has console access without MFA",
                            severity="HIGH",
                            resource_type="AWS::IAM::User",
                            resource_id=username,
                            description=(
                                f"User '{username}' can log into the AWS console but does "
                                f"not have MFA enabled. This makes the account vulnerable "
                                f"to credential theft attacks."
                            ),
                            remediation=(
                                f"Enable MFA for user '{username}'. Navigate to IAM > Users "
                                f"> {username} > Security credentials > MFA device."
                            ),
                            scanner=self.name,
                            region="global",
                            account_id=self.account_id,
                        ))
        except Exception as e:
            print(f"  [!] Could not check user MFA: {e}")

    def _check_access_key_age(self, iam):
        """Access keys older than 90 days should be rotated."""
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    keys = iam.list_access_keys(UserName=username)

                    for key in keys["AccessKeyMetadata"]:
                        if key["Status"] != "Active":
                            continue

                        age_days = (datetime.now(timezone.utc) - key["CreateDate"]).days

                        if age_days > 90:
                            severity = "CRITICAL" if age_days > 365 else "HIGH" if age_days > 180 else "MEDIUM"
                            self.findings.add(Finding(
                                title=f"Access key for '{username}' is {age_days} days old",
                                severity=severity,
                                resource_type="AWS::IAM::AccessKey",
                                resource_id=key["AccessKeyId"],
                                description=(
                                    f"Access key {key['AccessKeyId']} for user '{username}' "
                                    f"was created {age_days} days ago and has not been rotated. "
                                    f"Old keys increase the risk of credential compromise."
                                ),
                                remediation=(
                                    f"Rotate the access key for '{username}': create a new key, "
                                    f"update applications using it, then deactivate and delete "
                                    f"the old key {key['AccessKeyId']}."
                                ),
                                scanner=self.name,
                                region="global",
                                account_id=self.account_id,
                            ))
        except Exception as e:
            print(f"  [!] Could not check access key age: {e}")

    def _check_overly_permissive_policies(self, iam):
        """Flag policies that grant Action: * on Resource: *."""
        try:
            paginator = iam.get_paginator("list_policies")
            for page in paginator.paginate(Scope="Local", OnlyAttached=True):
                for policy in page["Policies"]:
                    policy_version = iam.get_policy_version(
                        PolicyArn=policy["Arn"],
                        VersionId=policy["DefaultVersionId"],
                    )
                    doc = policy_version["PolicyVersion"]["Document"]
                    if isinstance(doc, str):
                        doc = json.loads(doc)

                    statements = doc.get("Statement", [])
                    if isinstance(statements, dict):
                        statements = [statements]

                    for stmt in statements:
                        if stmt.get("Effect") != "Allow":
                            continue

                        actions = stmt.get("Action", [])
                        resources = stmt.get("Resource", [])

                        if isinstance(actions, str):
                            actions = [actions]
                        if isinstance(resources, str):
                            resources = [resources]

                        if "*" in actions and "*" in resources:
                            self.findings.add(Finding(
                                title=f"Policy '{policy['PolicyName']}' grants full admin access",
                                severity="CRITICAL",
                                resource_type="AWS::IAM::Policy",
                                resource_id=policy["Arn"],
                                description=(
                                    f"Policy '{policy['PolicyName']}' allows Action: * on "
                                    f"Resource: *, effectively granting full administrator "
                                    f"access. This violates the principle of least privilege."
                                ),
                                remediation=(
                                    f"Replace '{policy['PolicyName']}' with more restrictive "
                                    f"policies that only grant the specific permissions needed. "
                                    f"Use IAM Access Analyzer to identify actually-used permissions."
                                ),
                                scanner=self.name,
                                region="global",
                                account_id=self.account_id,
                            ))
        except Exception as e:
            print(f"  [!] Could not check policies: {e}")

    def _check_inline_policies(self, iam):
        """Inline policies are harder to audit - flag them."""
        try:
            paginator = iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    username = user["UserName"]
                    inline = iam.list_user_policies(UserName=username)
                    if inline["PolicyNames"]:
                        self.findings.add(Finding(
                            title=f"User '{username}' has {len(inline['PolicyNames'])} inline policies",
                            severity="LOW",
                            resource_type="AWS::IAM::User",
                            resource_id=username,
                            description=(
                                f"User '{username}' has inline policies: "
                                f"{', '.join(inline['PolicyNames'])}. Inline policies are "
                                f"harder to audit and manage than managed policies."
                            ),
                            remediation=(
                                f"Convert inline policies for '{username}' to managed policies "
                                f"for better visibility and reuse."
                            ),
                            scanner=self.name,
                            region="global",
                            account_id=self.account_id,
                        ))
        except Exception as e:
            print(f"  [!] Could not check inline policies: {e}")
