import hashlib

def get_difficult_password_for_user(username, difficulty):
    DIFFICULT_PASSWORD_SALT = "no_secrets"

    # Concatenate salt, difficulty, and username
    input_string = DIFFICULT_PASSWORD_SALT + str(difficulty) + username

    # Compute SHA1 hash
    hashed_username = hashlib.sha1(input_string.encode()).hexdigest()

    # Convert hexadecimal hash to base-26 string using 'a' to 'z'
    base_26_string = to_base_26_string(hashed_username)

    # Return the first 16 characters
    return base_26_string[:16]

def to_base_26_string(hex_string):
    # Convert the hexadecimal string to an integer
    num = int(hex_string, 16)

    # Base-26 mapping with letters 'a' to 'z'
    alphabet = "abcdefghijklmnopqrstuvwxyz"
    base_26_result = []

    # Convert to base-26
    while num > 0:
        num, remainder = divmod(num, 26)
        base_26_result.append(alphabet[remainder])

    # Reverse to get the correct order and join to form the string
    return ''.join(reversed(base_26_result))

# Example usage
username = "asd"
difficulty = 1  # Default difficulty
password = get_difficult_password_for_user(username, difficulty)

print("Password for username", username, "is:", password)
