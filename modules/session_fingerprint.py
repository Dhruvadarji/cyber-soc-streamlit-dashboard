import hashlib

def generate_fingerprint(username, device, ip):
    data = f"{username}-{device}-{ip}"
    return hashlib.sha256(data.encode()).hexdigest()