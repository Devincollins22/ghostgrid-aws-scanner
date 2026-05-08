"""
Base scanner class - all scanners inherit from this.
"""
from abc import ABC, abstractmethod
import boto3
from utils.finding import FindingCollection


class BaseScanner(ABC):
    """Base class for all AWS scanners."""

    name: str = "base"
    description: str = "Base scanner"

    def __init__(self, session: boto3.Session = None, region: str = "us-east-1"):
        self.session = session or boto3.Session(region_name=region)
        self.region = region
        self.findings = FindingCollection()
        try:
            sts = self.session.client("sts")
            self.account_id = sts.get_caller_identity()["Account"]
        except Exception:
            self.account_id = "unknown"

    @abstractmethod
    def scan(self) -> FindingCollection:
        """Run the scan and return findings."""
        pass

    def _get_client(self, service: str):
        return self.session.client(service, region_name=self.region)
