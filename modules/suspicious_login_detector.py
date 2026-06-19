import pandas as pd

def detect_suspicious_login(username, device, ip):

    risk = 0
    reasons = []

    df = pd.read_csv("data/sessions.csv")

    df["Username"] = df["Username"].str.lower()

    user_sessions = df[df["Username"] == username.lower()]

    # Device Check
    if device not in user_sessions["Device"].values:
        risk += 30
        reasons.append("Unknown Device")

    # IP Check
    if ip not in user_sessions["IP"].values:
        risk += 20
        reasons.append("New IP Address")

    # Multiple Login Check
    if user_sessions["Device"].nunique() > 1:
        risk += 20
        reasons.append("Multiple Device Login")

    return {
        "risk": risk,
        "reasons": reasons
    }