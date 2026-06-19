def analyze_security(hash_type):

    security = {

        "MD5": {
            "level": "Weak",
            "message": "MD5 is broken and should not be used for passwords."
        },

        "SHA1": {
            "level": "Weak",
            "message": "SHA1 is deprecated and vulnerable."
        },

        "SHA256": {
            "level": "Strong",
            "message": "SHA256 is widely used and secure."
        },

        "SHA512": {
            "level": "Very Strong",
            "message": "SHA512 provides strong security."
        }
    }

    return security.get(
        hash_type,
        {
            "level": "Unknown",
            "message": "Hash type not recognized."
        }
    )