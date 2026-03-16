SEVERITY_POINTS = {
    "critical": 25,
    "high":     15,
    "medium":    7,
    "low":       3,
    "info":      0,
}

GRADE_MAP = [
    (20,  "A", "MINIMAL"),
    (40,  "B", "LOW"),
    (60,  "C", "MODERATE"),
    (80,  "D", "HIGH"),
    (101, "F", "CRITICAL"),
]

GRADE_COLORS = {
    "A": "bright_green",
    "B": "green",
    "C": "yellow",
    "D": "red",
    "F": "bright_red",
}


def calculate(findings: list[dict]) -> tuple[int, str, str]:
    """Returns (score 0-100, letter grade, label)."""
    score = sum(SEVERITY_POINTS.get(f["severity"], 0) for f in findings)
    score = min(score, 100)

    for threshold, grade, label in GRADE_MAP:
        if score < threshold:
            return score, grade, label

    return 100, "F", "CRITICAL"
