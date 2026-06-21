from modules.db import init_db, insert_session, get_sessions, insert_alert

init_db()

from modules.risk_analyzer import calculate_risk
from modules.multiple_login_detector import check_multiple_logins
from modules.hash_generator import generate_hashes
from modules.hash_identifier import identify_hash
from modules.device_checker import check_device
from modules.suspicious_login_detector import detect_suspicious_login
from modules.security_analyzer import analyze_security
from modules.session_fingerprint import generate_fingerprint

import streamlit as st
import pandas as pd
import sqlite3

# ------------------ PAGE CONFIG ------------------

st.set_page_config(
    page_title="SOC Monitoring System",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ------------------ CYBER UI THEME ------------------

st.markdown("""
<style>

.stApp {
    background-color: #0d1117;
    color: #00ff9f;
    font-family: 'Courier New';
}

section[data-testid="stSidebar"] {
    background-color: #111827;
}

h1, h2, h3 {
    color: #00ff9f;
    text-shadow: 0px 0px 10px #00ff9f;
}

div[data-testid="stDataFrame"] {
    border: 1px solid #00ff9f;
}

button {
    background-color: #00ff9f !important;
    color: black !important;
    font-weight: bold;
}

[data-testid="stMetric"] {
    background-color: #111827;
    border: 1px solid #00ff9f;
    padding: 10px;
    border-radius: 10px;
}

</style>
""", unsafe_allow_html=True)

# ------------------ HEADER ------------------

st.markdown("""
# 🛡️ SOC SECURITY MONITORING SYSTEM
### Real-Time Session Integrity & Threat Detection Engine
""")

# ------------------ SIDEBAR MENU ------------------

menu = st.sidebar.selectbox(
    "Select Option",
    [
        "Hash Generator",
        "Hash Identifier",
        "Session Monitor",
        "Session Dashboard",
        "Multiple Login Detector",
        "Suspicious Login Detector",
        "Project Overview",
        "Risk Analytics Dashboard",
        "Executive Overview",
        "Alert Dashboard"
    ]
)

# ------------------ HASH GENERATOR ------------------

if menu == "Hash Generator":

    password = st.text_input("Enter Password", type="password")

    if st.button("Generate Hashes"):
        hashes = generate_hashes(password)

        for algo, value in hashes.items():
            st.write(algo)
            st.code(value)

# ------------------ HASH IDENTIFIER ------------------

elif menu == "Hash Identifier":

    hash_input = st.text_input("Enter Hash")

    if st.button("Identify Hash"):

        result = identify_hash(hash_input)
        st.success(f"Detected Hash Type: {result}")

        security = analyze_security(result)
        st.write(f"Security Level: {security['level']}")
        st.info(security["message"])

# ------------------ SESSION MONITOR ------------------

elif menu == "Session Monitor":

    st.header("Employee Login Simulation")

    username = st.text_input("Username").lower()
    device = st.text_input("Device Name")
    ip = st.text_input("IP Address")

    if st.button("Login"):

        session_hash = generate_fingerprint(username, device, ip)

        insert_session(username, device, ip, session_hash)

        known_device = check_device(username, device)
        risk = calculate_risk(username, device, ip)

        st.success("Session Logged Successfully")

        st.write("Session Fingerprint:", session_hash)

        if known_device:
            st.success("Known Device Verified")
        else:
            st.error("Unknown Device Detected")
            risk += 30

        st.write(f"Risk Score: {risk}")

        if risk >= 30:
            st.warning("High Risk Login")
            insert_alert(username, "High Risk Login Detected", risk)
        else:
            st.success("Normal Login")
# ------------------ SESSION DASHBOARD ------------------

# ------------------ SESSION DASHBOARD ------------------

elif menu == "Session Dashboard":

    from streamlit_autorefresh import st_autorefresh
    st_autorefresh(interval=3000, key="refresh")

    st.header("Session Monitoring Dashboard")

    data = get_sessions()

    df = pd.DataFrame(
        data,
        columns=["Username", "Device", "IP", "Login Time"]
    )

    if df.empty:
        st.info("No session data available yet.")
        st.stop()

    st.markdown("## 🛡️ SYSTEM STATUS")

    col1, col2, col3 = st.columns(3)

    col1.metric("Active Sessions", len(df))
    col2.metric("Unique Devices", df["Device"].nunique())
    col3.metric("Unique IPs", df["IP"].nunique())

    st.markdown("---")

    st.markdown("### 📡 LIVE SESSION STREAM")
    st.dataframe(df, use_container_width=True)
    # ------------------ MULTIPLE LOGIN ------------------

# ------------------ MULTIPLE LOGIN ------------------

elif menu == "Multiple Login Detector":

    st.header("Multiple Login Detection")

    username = st.text_input("Username")

    if st.button("Check"):

        result = check_multiple_logins(username)

        st.write(f"Unique Devices: {result['device_count']}")
        st.write(f"Unique IPs: {result['ip_count']}")

        if result["multiple_login"]:
            st.error("🚨 Suspicious Login Pattern Detected")

            for reason in result["reasons"]:
                st.write("•", reason)

            insert_alert(
                username,
                "Multiple Login Attack Pattern",
                70
            )

        else:
            st.success("Normal Activity")

# ------------------ SUSPICIOUS LOGIN ------------------

elif menu == "Suspicious Login Detector":

    st.header("Suspicious Login Detection System")

    username = st.text_input("Username")
    device = st.text_input("Device Name")
    ip = st.text_input("IP Address")

    if st.button("Analyze Login"):

        result = detect_suspicious_login(username, device, ip)

        st.markdown("### 🚨 SECURITY ALERT PANEL")

        st.write(f"Risk Score: {result['risk']}")

        if result["reasons"]:
            st.warning("Suspicious Activity Detected")

            for reason in result["reasons"]:
                st.write("•", reason)

        else:
            st.success("Normal Login - No Suspicious Activity")

# ------------------ PROJECT OVERVIEW ------------------

elif menu == "Project Overview":

    st.title("Hash-Based Session Integrity Monitoring System")

    st.write("""
    This system monitors login sessions, detects anomalies,
    and calculates risk using hashing and behavioral analysis.
    """)

# ------------------ RISK ANALYTICS ------------------

# ------------------ RISK ANALYTICS ------------------

elif menu == "Risk Analytics Dashboard":

    st.title("📊 Risk Analytics Engine")

    data = get_sessions()

    df = pd.DataFrame(
        data,
        columns=["Username", "Device", "IP", "Login Time"]
    )

    # Prevent crash if no session data exists
    if df.empty:
        st.warning("No session data available.")
        st.stop()

    # Apply risk calculation
    df["Risk"] = df.apply(
        lambda x: calculate_risk(
            x["Username"],
            x["Device"],
            x["IP"]
        ),
        axis=1
    )

    st.subheader("📈 Risk Distribution")
    st.area_chart(df["Risk"])

    st.subheader("🚨 High Risk Sessions")

    high_risk = df[df["Risk"] >= 30]

    st.dataframe(
        high_risk,
        use_container_width=True
    )

    st.subheader("📊 Risk Summary")

    col1, col2, col3 = st.columns(3)

    col1.metric(
        "Total Sessions",
        len(df)
    )

    col2.metric(
        "High Risk Users",
        len(high_risk)
    )

    col3.metric(
        "Avg Risk Score",
        round(df["Risk"].mean(), 2)
    )
# ------------------ EXECUTIVE OVERVIEW ------------------

# ------------------ EXECUTIVE OVERVIEW ------------------

elif menu == "Executive Overview":

    st.title("🛡 SOC Executive Overview")

    data = get_sessions()

    df = pd.DataFrame(
        data,
        columns=["Username", "Device", "IP", "Login Time"]
    )

    # Prevent crash when database is empty
    if df.empty:
        st.warning("No session data available.")
        st.stop()

    st.subheader("📊 System Summary")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Logins", len(df))
    col2.metric("Unique Users", df["Username"].nunique())
    col3.metric("Unique Devices", df["Device"].nunique())
    col4.metric("Unique IPs", df["IP"].nunique())

    st.markdown("---")

    st.subheader("📈 Device Activity Distribution")
    st.bar_chart(df["Device"].value_counts())

    st.subheader("🌍 IP Activity Distribution")
    st.bar_chart(df["IP"].value_counts())

    st.subheader("📡 Recent Sessions")
    st.dataframe(df.tail(10), use_container_width=True)

# ------------------ Alert Dashboard ------------------

elif menu == "Alert Dashboard":

    st.title("🚨 SOC Alert Center")

    conn = sqlite3.connect("sessions.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT username, reason, risk, time FROM alerts"
    )

    alerts = cursor.fetchall()

    df = pd.DataFrame(
        alerts,
        columns=["User", "Reason", "Risk", "Time"]
    )

    if df.empty:
        st.info("No alerts generated yet.")
        st.stop()

    st.subheader("Active Alerts")

    st.dataframe(df, use_container_width=True)

    st.subheader("Alert Severity Overview")

    col1, col2 = st.columns(2)

    col1.metric("Total Alerts", len(df))
    col2.metric(
        "Critical Alerts",
        len(df[df["Risk"] >= 70])
    )

    st.bar_chart(df["Risk"])
