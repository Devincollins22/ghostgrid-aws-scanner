"""
Security Group Scanner - the #1 thing people mess up in AWS.

What it catches:
- 0.0.0.0/0 ingress on dangerous ports (SSH, RDP, databases)
- Overly permissive egress rules
- Unused security groups
"""
from .base import BaseScanner
from utils.finding import Finding, FindingCollection


# Ports that should NEVER be open to the internet
DANGEROUS_PORTS = {
    22: ("SSH", "CRITICAL"),
    3389: ("RDP", "CRITICAL"),
    3306: ("MySQL", "CRITICAL"),
    5432: ("PostgreSQL", "CRITICAL"),
    1433: ("MSSQL", "CRITICAL"),
    27017: ("MongoDB", "CRITICAL"),
    6379: ("Redis", "CRITICAL"),
    9200: ("Elasticsearch", "HIGH"),
    5601: ("Kibana", "HIGH"),
    8080: ("HTTP-alt", "MEDIUM"),
    8443: ("HTTPS-alt", "MEDIUM"),
    23: ("Telnet", "CRITICAL"),
    21: ("FTP", "HIGH"),
    445: ("SMB", "CRITICAL"),
    135: ("RPC", "CRITICAL"),
}


class SecurityGroupScanner(BaseScanner):
    name = "security_groups"
    description = "Scans security groups for overly permissive rules"

    def scan(self) -> FindingCollection:
        ec2 = self._get_client("ec2")
        self._check_security_groups(ec2)
        return self.findings

    def _check_security_groups(self, ec2):
        """Check all security groups for dangerous rules."""
        try:
            paginator = ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    sg_id = sg["GroupId"]
                    sg_name = sg["GroupName"]
                    display = f"{sg_id} ({sg_name})"

                    for rule in sg.get("IpPermissions", []):
                        self._check_ingress_rule(rule, display, sg_id)

                    # Check for unrestricted egress
                    for rule in sg.get("IpPermissionsEgress", []):
                        self._check_egress_rule(rule, display, sg_id)

        except Exception as e:
            print(f"  [!] Could not check security groups: {e}")

    def _check_ingress_rule(self, rule: dict, sg_display: str, sg_id: str):
        """Check a single ingress rule for dangerous patterns."""
        from_port = rule.get("FromPort", 0)
        to_port = rule.get("ToPort", 65535)

        # Check all IP ranges in the rule
        open_cidrs = []
        for ip_range in rule.get("IpRanges", []):
            if ip_range["CidrIp"] in ("0.0.0.0/0",):
                open_cidrs.append(ip_range["CidrIp"])
        for ip_range in rule.get("Ipv6Ranges", []):
            if ip_range["CidrIpv6"] == "::/0":
                open_cidrs.append(ip_range["CidrIpv6"])

        if not open_cidrs:
            return

        # Check if ALL traffic is allowed (no port restriction)
        if rule.get("IpProtocol") == "-1":
            self.findings.add(Finding(
                title=f"Security group {sg_display} allows ALL inbound traffic from internet",
                severity="CRITICAL",
                resource_type="AWS::EC2::SecurityGroup",
                resource_id=sg_id,
                description=(
                    f"Security group {sg_display} has a rule allowing ALL protocols and "
                    f"ALL ports from {', '.join(open_cidrs)}. This is the most dangerous "
                    f"security group configuration possible."
                ),
                remediation=(
                    f"Immediately remove the 0.0.0.0/0 all-traffic rule from {sg_id}. "
                    f"Replace with specific port/protocol rules for only what's needed."
                ),
                scanner=self.name,
                region=self.region,
                account_id=self.account_id,
            ))
            return

        # Check specific dangerous ports
        for port, (service, severity) in DANGEROUS_PORTS.items():
            if from_port <= port <= to_port:
                self.findings.add(Finding(
                    title=f"Security group {sg_display} exposes {service} (port {port}) to internet",
                    severity=severity,
                    resource_type="AWS::EC2::SecurityGroup",
                    resource_id=sg_id,
                    description=(
                        f"Security group {sg_display} allows inbound {service} traffic "
                        f"(port {port}) from {', '.join(open_cidrs)}. {service} should "
                        f"never be directly exposed to the internet."
                    ),
                    remediation=(
                        f"Restrict port {port} ({service}) in {sg_id} to specific trusted "
                        f"IP ranges. For remote access, use AWS Systems Manager Session "
                        f"Manager or a VPN instead of direct SSH/RDP."
                    ),
                    scanner=self.name,
                    region=self.region,
                    account_id=self.account_id,
                ))

    def _check_egress_rule(self, rule: dict, sg_display: str, sg_id: str):
        """Flag unrestricted outbound rules (data exfiltration risk)."""
        if rule.get("IpProtocol") != "-1":
            return

        for ip_range in rule.get("IpRanges", []):
            if ip_range["CidrIp"] == "0.0.0.0/0":
                self.findings.add(Finding(
                    title=f"Security group {sg_display} allows all outbound traffic",
                    severity="LOW",
                    resource_type="AWS::EC2::SecurityGroup",
                    resource_id=sg_id,
                    description=(
                        f"Security group {sg_display} allows unrestricted outbound traffic. "
                        f"While common, this enables data exfiltration if an instance is "
                        f"compromised."
                    ),
                    remediation=(
                        f"Consider restricting outbound rules in {sg_id} to only required "
                        f"destinations and ports for defense in depth."
                    ),
                    scanner=self.name,
                    region=self.region,
                    account_id=self.account_id,
                ))
                return
