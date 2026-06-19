def identify_hash(hash_value):

    length = len(hash_value)

    if length == 32:
        return "MD5"

    elif length == 40:
        return "SHA1"

    elif length == 64:
        return "SHA256"

    elif length == 128:
        return "SHA512"

    return "Unknown"