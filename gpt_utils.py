import json
from openai import OpenAI
from utils import calculate_risk
import os

client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

def summarize_with_gpt(inventory_summary, top_n=10):
    """
    Generate an executive summary of the top N riskiest devices using GPT.
    """
    # Risk score per device
    def calculate_risk(vulns):
        """
        Calculate a risk score based on the severity of vulnerabilities.
        """
        score = 0
        for v in vulns:
            severity = v.get("sir", "").lower()
            if severity == "critical":
                score += 5
            elif severity == "high":
                score += 3
            elif severity == "medium":
                score += 1
            elif severity == "low":
                score += 0.5
        return score

    # Sort devices by risk score
    ranked = sorted(inventory_summary, key=lambda item: calculate_risk(item["vulnerabilities"]), reverse=True)

    # Take top N
    top_devices = ranked[:top_n]

    # Minimal data sent to GPT
    summary_input = []
    for item in top_devices:
        device = item["device"]
        vulns = item["vulnerabilities"]
        summary_input.append({
            "hostname": device["hostname"],
            "version": device["softwareVersion"],
            "total_vulnerabilities": len(vulns),
            "critical": sum(1 for v in vulns if v.get("sir", "").lower() == "critical"),
            "high": sum(1 for v in vulns if v.get("sir", "").lower() == "high"),
            "medium": sum(1 for v in vulns if v.get("sir", "").lower() == "medium"),
            "low": sum(1 for v in vulns if v.get("sir", "").lower() == "low"),
        })

    # Build GPT prompt
    prompt = (
        f"You are a network security advisor. Here are the top {top_n} riskiest devices based on vulnerability severity.\n"
        "- Provide a 2-sentence executive summary\n"
        "- Suggest which devices should be patched first\n"
        "- Group by urgency or software version if useful\n"
        "- Format as clean Markdown with bullet points and bold headings\n\n"
        "Top vulnerable devices:\n" + json.dumps(summary_input, indent=2)
    )

    response = client.chat.completions.create(
        model="gpt-4-turbo",
        messages=[
            {"role": "user", "content": prompt}
        ]
    )

    return response.choices[0].message.content