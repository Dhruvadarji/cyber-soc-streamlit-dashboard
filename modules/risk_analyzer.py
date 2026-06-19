# modules/risk_analyzer.py

def calculate_risk(username, device, ip):
    risk = 0

    # 1. Device risk
    if "hacker" in device.lower():
        risk += 40

    if "unknown" in device.lower():
        risk += 20

    # 2. IP risk (simple heuristic)
    if ip.startswith("45.") or ip.startswith("103."):
        risk += 25

    if ip.startswith("192.168."):
        risk -= 10  # trusted local network

    # 3. Final clamp
    if risk < 0:
        risk = 0
    if risk > 100:
        risk = 100

    return risk