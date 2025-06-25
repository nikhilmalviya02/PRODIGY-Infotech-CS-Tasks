def checkPassword(password):
    upperChars = lowerChars = specialChars = digits = length = 0
    length = len(password)

    if length < 8: #check minimum length
        print("❌For Security, your password must be 8 characters or more!\n")
        return

    # Count character types
    for char in password:
        if char.isupper():
            upperChars += 1
        elif char.islower():
            lowerChars += 1
        elif char.isdigit():
            digits += 1
        else:
            specialChars += 1

    missing = []
    if upperChars == 0:
        missing.append("Password must contain at least one uppercase letter")
    if lowerChars == 0:
        missing.append("Password must contain at least one lowercase letter")
    if digits == 0:
        missing.append("Password must contain at least one digit")
    if specialChars == 0:
        missing.append("Password must contain at least one special character")

    if not missing:
        if length >= 10:
            print("✅Strong Password\n")
        else:
            print("⚠️Moderate Password\n")
    else:
        print("❌Weak Password\n")
        for item in missing:
            print(f"- {item}")
        print()


password = input("Enter the password: ")
checkPassword(password)