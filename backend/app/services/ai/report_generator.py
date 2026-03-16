"""
AI-powered security report generator using Anthropic Claude
"""
import json
import logging
from typing import Optional
import anthropic

from app.core.config import settings

logger = logging.getLogger(__name__)


class AIReportGenerator:
    """Generate professional security reports using Claude AI."""

    def __init__(self):
        self.client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY) if settings.ANTHROPIC_API_KEY else None

    async def generate_report(
        self,
        target_info: dict,
        findings: list,
        risk_score: float,
    ) -> dict:
        """Generate a comprehensive AI security report."""
        if not self.client:
            return self._fallback_report(target_info, findings, risk_score)

        try:
            findings_summary = self._summarize_findings(findings)
            prompt = self._build_prompt(target_info, findings_summary, risk_score)

            message = self.client.messages.create(
                model="claude-sonnet-4-20250514",
                max_tokens=2000,
                messages=[{"role": "user", "content": prompt}],
            )

            response_text = message.content[0].text
            return self._parse_ai_response(response_text, target_info, findings, risk_score)

        except Exception as e:
            logger.error(f"AI report generation failed: {e}")
            return self._fallback_report(target_info, findings, risk_score)

    def _build_prompt(self, target_info: dict, findings_summary: str, risk_score: float) -> str:
        target_name = target_info.get("name", "Unknown")
        domain = target_info.get("domain", "N/A")

        return f"""You are a senior cybersecurity analyst. Generate a professional security assessment report.

Target: {target_name}
Domain: {domain}
Overall Risk Score: {risk_score}/100

Security Findings:
{findings_summary}

Generate a JSON response with this exact structure:
{{
  "title": "Security Assessment Report - {target_name}",
  "executive_summary": "2-3 paragraph non-technical summary for business stakeholders. Mention the risk level, key issues found, and business impact.",
  "technical_findings": {{
    "overview": "Technical overview paragraph",
    "categories": [
      {{
        "name": "category name",
        "findings_count": number,
        "max_severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
        "summary": "brief technical summary"
      }}
    ]
  }},
  "recommendations": {{
    "immediate": ["action 1", "action 2"],
    "short_term": ["action 1", "action 2"],
    "long_term": ["action 1", "action 2"]
  }},
  "risk_assessment": "One paragraph explaining the overall risk level and potential business impact"
}}

Respond ONLY with the JSON, no markdown, no extra text."""

    def _summarize_findings(self, findings: list) -> str:
        if not findings:
            return "No findings detected."

        lines = []
        for f in findings:
            severity = f.get("severity", "INFO")
            title = f.get("title", "Unknown")
            category = f.get("category", "general")
            lines.append(f"[{severity}] ({category}) {title}")
        return "\n".join(lines)

    def _parse_ai_response(self, response_text: str, target_info: dict, findings: list, risk_score: float) -> dict:
        try:
            cleaned = response_text.strip()
            if cleaned.startswith("```"):
                cleaned = cleaned.split("```")[1]
                if cleaned.startswith("json"):
                    cleaned = cleaned[4:]
            data = json.loads(cleaned)
            return data
        except json.JSONDecodeError:
            logger.warning("Failed to parse AI response as JSON, using fallback")
            return self._fallback_report(target_info, findings, risk_score)

    def _fallback_report(self, target_info: dict, findings: list, risk_score: float) -> dict:
        """Generate a fallback report without AI."""
        target_name = target_info.get("name", "Unknown Target")
        critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
        high = sum(1 for f in findings if f.get("severity") == "HIGH")
        medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")

        risk_label = "Critical" if risk_score >= 75 else "High" if risk_score >= 50 else "Medium" if risk_score >= 25 else "Low"

        executive_summary = (
            f"A security assessment was conducted on {target_name}. "
            f"The overall risk score is {risk_score:.1f}/100, indicating a {risk_label} risk level. "
            f"The scan identified {len(findings)} findings including {critical} critical, "
            f"{high} high, and {medium} medium severity issues. "
            f"Immediate attention is recommended for critical and high severity findings."
        )

        immediate = [
            f["title"] for f in findings if f.get("severity") in ["CRITICAL", "HIGH"]
        ][:5]

        short_term = [
            f["title"] for f in findings if f.get("severity") == "MEDIUM"
        ][:5]

        # Group by category
        categories = {}
        for f in findings:
            cat = f.get("category", "general")
            if cat not in categories:
                categories[cat] = {"count": 0, "max_severity": "INFO"}
            categories[cat]["count"] += 1
            severities = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
            current_max = categories[cat]["max_severity"]
            new_sev = f.get("severity", "INFO")
            if severities.index(new_sev) > severities.index(current_max):
                categories[cat]["max_severity"] = new_sev

        return {
            "title": f"Security Assessment Report — {target_name}",
            "executive_summary": executive_summary,
            "technical_findings": {
                "overview": f"Automated security scan completed. {len(findings)} findings identified across {len(categories)} categories.",
                "categories": [
                    {
                        "name": cat,
                        "findings_count": info["count"],
                        "max_severity": info["max_severity"],
                        "summary": f"{info['count']} issues found.",
                    }
                    for cat, info in categories.items()
                ],
            },
            "recommendations": {
                "immediate": immediate or ["Review security configuration"],
                "short_term": short_term or ["Apply security patches"],
                "long_term": [
                    "Implement continuous security monitoring",
                    "Conduct regular penetration testing",
                    "Security awareness training for staff",
                ],
            },
            "risk_assessment": f"The {risk_label.lower()} risk score of {risk_score:.1f}/100 indicates that this target has security vulnerabilities that need to be addressed.",
        }
