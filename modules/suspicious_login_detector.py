import pandas as pd
import os

def detect_suspicious_login(username, device, ip):

    risk = 0
    reasons = []

    file_path = "data/sessions.csv"

    # 1. File safety check
    if not os.path.exists(file_path):
        return {
            "risk": 0,
            "reasons": ["Session database not found"]
        }

    df = pd.read_csv(file_path)

    # Normalize
    df["Username"] = df["Username"].str.lower()
    username = username.lower()

    user_sessions = df[df["Username"] == username]

    # 2. New user handling
    if user_sessions.empty:
        return {
            "risk": 50,
            "reasons": ["First time login - no history found"]
        }

    # 3. Device check
    if device not in user_sessions["Device"].values:
        risk += 30
        reasons.append("Unknown Device")

    # 4. IP check
    if ip not in user_sessions["IP"].values:
        risk += 20
        reasons.append("New IP Address")

    # 5. Real suspicious behavior check (improved logic)
    device_count = user_sessions["Device"].value_counts().get(device, 0)

    if device_count == 0 and len(user_sessions) > 3:
        risk += 15
        reasons.append("Unusual Device Pattern")

    # 6. Risk capping (important in SOC systems)
    risk = min(risk, 100)

    return {
        "risk": risk,
        "reasons": reasons
    }
