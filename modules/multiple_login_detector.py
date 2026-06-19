from modules.db import get_sessions

def check_multiple_logins(username):

    sessions = get_sessions()

    user_sessions = [s for s in sessions if s[0] == username]

    devices = set()
    ips = set()

    for s in user_sessions:
        devices.add(s[1])
        ips.add(s[2])

    device_count = len(devices)
    ip_count = len(ips)

    multiple_login = False
    reasons = []

    # 🔴 Rule 1: multiple devices
    if device_count > 1:
        multiple_login = True
        reasons.append("Multiple devices detected")

    # 🔴 Rule 2: multiple IPs
    if ip_count > 1:
        multiple_login = True
        reasons.append("Multiple IP addresses detected")

    # 🔴 Rule 3: high-risk combo
    if device_count > 1 and ip_count > 1:
        reasons.append("Possible account takeover pattern")

    return {
        "multiple_login": multiple_login,
        "device_count": device_count,
        "ip_count": ip_count,
        "reasons": reasons
    }