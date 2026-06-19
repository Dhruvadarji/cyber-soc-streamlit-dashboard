import pandas as pd
from datetime import datetime

def save_session(username, device, ip):

    login_time = datetime.now()

    session = pd.DataFrame([{
        "Username": username,
        "Device": device,
        "IP": ip,
        "LoginTime": login_time
    }])

    session.to_csv(
        "data/sessions.csv",
        mode="a",
        header=False,
        index=False
    )