import hashlib

def generate_hashes(password):

    return {
        "MD5": hashlib.md5(password.encode()).hexdigest(),
        "SHA1": hashlib.sha1(password.encode()).hexdigest(),
        "SHA256": hashlib.sha256(password.encode()).hexdigest(),
        "SHA512": hashlib.sha512(password.encode()).hexdigest()
    }