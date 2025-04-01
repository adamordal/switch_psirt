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

custom_colors = {
    "Critical": "red",
    "High": "gold",
    "Medium": "orange",
    "Low": "deepskyblue"
}