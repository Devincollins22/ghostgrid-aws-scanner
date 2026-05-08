"""
EC2 Scanner - checks for common EC2 misconfigurations.

What it catches:
- Instances with public IPs that shouldn't have them
- Unencrypted EBS volumes
- Instances using default security groups
- IMDSv1 (vulnerable to SSRF token theft)
"""
from .base import BaseScanner
from utils.finding import Finding, FindingCollection


class EC2Scanner(BaseScanner):
    name = "ec2"
    description = "Scans EC2 instances for security misconfigurations"

    def scan(self) -> FindingCollection:
        ec2 = self._get_client("ec2")

        self._check_instances(ec2)
        self._check_ebs_encryption(ec2)

        return self.findings

    def _check_instances(self, ec2):
        """Check running instances for common issues."""
        try:
            paginator = ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        if instance["State"]["Name"] != "running":
                            continue

                        instance_id = instance["InstanceId"]
                        name_tag = ""
                        for tag in instance.get("Tags", []):
                            if tag["Key"] == "Name":
                                name_tag = tag["Value"]
                                break

                        display = f"{instance_id} ({name_tag})" if name_tag else instance_id

                        # Check IMDSv1 - vulnerable to SSRF attacks
                        metadata_options = instance.get("MetadataOptions", {})
                        if metadata_options.get("HttpTokens") != "required":
                            self.findings.add(Finding(
                                title=f"EC2 instance {display} allows IMDSv1",
                                severity="HIGH",
                                resource_type="AWS::EC2::Instance",
                                resource_id=instance_id,
                                description=(
                                    f"Instance {display} does not require IMDSv2. IMDSv1 is "
                                    f"vulnerable to SSRF attacks that can steal IAM role "
                                    f"credentials from the metadata service. This is one of "
                                    f"the most exploited AWS attack vectors."
                                ),
                                remediation=(
                                    f"Enforce IMDSv2 on {instance_id} by setting "
                                    f"HttpTokens=required. Test your applications first, then: "
                                    f"aws ec2 modify-instance-metadata-options "
                                    f"--instance-id {instance_id} --http-tokens required"
                                ),
                                scanner=self.name,
                                region=self.region,
                                account_id=self.account_id,
                            ))

                        # Check if using default security group
                        for sg in instance.get("SecurityGroups", []):
                            if sg["GroupName"] == "default":
                                self.findings.add(Finding(
                                    title=f"EC2 instance {display} uses the default security group",
                                    severity="MEDIUM",
                                    resource_type="AWS::EC2::Instance",
                                    resource_id=instance_id,
                                    description=(
                                        f"Instance {display} is using the VPC default security "
                                        f"group. Default SGs often have overly broad rules and "
                                        f"should not be used for production workloads."
                                    ),
                                    remediation=(
                                        f"Create a purpose-specific security group for "
                                        f"{instance_id} with only the minimum required ports "
                                        f"and replace the default SG."
                                    ),
                                    scanner=self.name,
                                    region=self.region,
                                    account_id=self.account_id,
                                ))

                        # Check for public IP
                        if instance.get("PublicIpAddress"):
                            self.findings.add(Finding(
                                title=f"EC2 instance {display} has a public IP address",
                                severity="INFO",
                                resource_type="AWS::EC2::Instance",
                                resource_id=instance_id,
                                description=(
                                    f"Instance {display} has public IP "
                                    f"{instance['PublicIpAddress']}. Verify this instance "
                                    f"needs direct internet exposure."
                                ),
                                remediation=(
                                    f"If {instance_id} does not need direct internet access, "
                                    f"place it in a private subnet and use a NAT gateway or "
                                    f"VPC endpoints for outbound access."
                                ),
                                scanner=self.name,
                                region=self.region,
                                account_id=self.account_id,
                            ))

        except Exception as e:
            print(f"  [!] Could not check instances: {e}")

    def _check_ebs_encryption(self, ec2):
        """Unencrypted EBS volumes are a compliance risk."""
        try:
            paginator = ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for volume in page["Volumes"]:
                    if not volume["Encrypted"]:
                        vol_id = volume["VolumeId"]
                        attachments = volume.get("Attachments", [])
                        attached_to = attachments[0]["InstanceId"] if attachments else "unattached"

                        self.findings.add(Finding(
                            title=f"EBS volume {vol_id} is not encrypted",
                            severity="HIGH",
                            resource_type="AWS::EC2::Volume",
                            resource_id=vol_id,
                            description=(
                                f"EBS volume {vol_id} (attached to {attached_to}) is not "
                                f"encrypted. Data at rest should always be encrypted to meet "
                                f"compliance requirements and protect against data theft."
                            ),
                            remediation=(
                                f"Create an encrypted snapshot of {vol_id}, then create a new "
                                f"encrypted volume from it. Also enable EBS encryption by "
                                f"default for new volumes in this region."
                            ),
                            scanner=self.name,
                            region=self.region,
                            account_id=self.account_id,
                        ))
        except Exception as e:
            print(f"  [!] Could not check EBS encryption: {e}")
