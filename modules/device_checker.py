import pandas as pd

def check_device(username, device):

    df = pd.read_csv("data/known_devices.csv")

    match = df[
        (df["Username"] == username) &
        (df["Device"] == device)
    ]

    return len(match) > 0