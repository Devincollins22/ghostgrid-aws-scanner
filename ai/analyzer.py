"""
AI Analysis Layer - uses Claude to turn raw findings into actionable intelligence.

This is what makes GhostGrid different from just running Prowler.
Instead of dumping 200 findings, we give clients a prioritized risk narrative.
"""
import json
import anthropic
from config import ANTHROPIC_API_KEY
from utils.finding import FindingCollection


class AIAnalyzer:
    """Uses Claude to analyze scan findings and generate risk assessments."""

    def __init__(self, api_key: str = None):
        self.api_key = api_key or ANTHROPIC_API_KEY
        if not self.api_key:
            raise ValueError(
                "Set ANTHROPIC_API_KEY environment variable or pass api_key. "
                "Get one at https://console.anthropic.com/"
            )
        self.client = anthropic.Anthropic(api_key=self.api_key)

    def analyze_findings(self, findings: FindingCollection) -> str:
        """
        Send all findings to Claude for a big-picture risk analysis.
        Returns a structured risk report.
        """
        if not findings.findings:
            return "No findings to analyze. Your AWS environment looks clean."

        findings_json = findings.to_json()
        summary = findings.summary()

        prompt = f"""You are GhostGrid, an AI-powered AWS security analyst. You've just
completed a scan of a client's AWS environment. Analyze these findings and produce a
professional security assessment.

SCAN SUMMARY:
- Total findings: {summary['total']}
- Critical: {summary['critical']}
- High: {summary['high']}
- Medium: {summary['medium']}
- Low: {summary['low']}
- Info: {summary['info']}

RAW FINDINGS:
{findings_json}

Produce a report with these sections:

## Executive Summary
2-3 sentences a non-technical executive can understand. What's the overall risk posture?
What's the single most important thing to fix?

## Critical Attack Paths
Identify how an attacker could CHAIN these findings together. For example:
- Public S3 bucket + unencrypted data = data breach
- IMDSv1 + public instance = credential theft via SSRF
- No MFA + admin policy = account takeover
Think like a red teamer.

## Priority Remediation Plan
Ordered list of what to fix first, with estimated effort (quick win / afternoon / project).
Group related fixes together.

## Risk Score
Give an overall score from 0-100 (0 = perfect, 100 = actively being breached).
Justify the score.

Keep the tone professional but direct. No fluff. This is a real security assessment
that a CISO would read."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=4096,
            messages=[{"role": "user", "content": prompt}],
        )

        return response.content[0].text

    def analyze_single_finding(self, finding_dict: dict) -> str:
        """
        Deep-dive analysis on a single finding.
        Useful for the detailed view when a client clicks into a specific issue.
        """
        prompt = f"""You are GhostGrid, an AI security analyst. Analyze this specific
AWS security finding in depth.

FINDING:
{json.dumps(finding_dict, indent=2)}

Provide:
1. **Why this matters** - Real-world attack scenario (be specific, not generic)
2. **Blast radius** - What could an attacker access if they exploit this?
3. **Step-by-step fix** - Exact AWS CLI commands or console steps
4. **Verification** - How to confirm the fix worked
5. **Prevention** - How to prevent this from recurring (SCPs, Config rules, etc.)

Be specific and actionable. Include actual AWS CLI commands."""

        response = self.client.messages.create(
            model="claude-sonnet-4-20250514",
            max_tokens=2048,
            messages=[{"role": "user", "content": prompt}],
        )

        return response.content[0].text
