from .iam_scanner import IAMScanner
from .s3_scanner import S3Scanner
from .ec2_scanner import EC2Scanner
from .sg_scanner import SecurityGroupScanner

ALL_SCANNERS = [IAMScanner, S3Scanner, EC2Scanner, SecurityGroupScanner]
