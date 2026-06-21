import pandas as pd
import os

def check_device(username, device):

    if not os.path.exists("data/known_devices.csv"):
        return False

    df = pd.read_csv("data/known_devices.csv")

    return ((df["username"] == username) &
            (df["device"] == device)).any()
