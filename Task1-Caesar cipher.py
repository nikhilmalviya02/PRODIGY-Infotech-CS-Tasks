def encrypt(text, shift):
    result = ""
    for char in text:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            result += chr((ord(char) - base + shift) % 26 + base)
        else:
            result += char
    return result

def decrypt(text, shift):
    return encrypt(text, -shift)

choice = input("Encrypt or Decrypt? (e/d): ").lower()
message = input("Enter your message: ")
shift = int(input("Enter shift value: "))

if choice == 'e':
    print("Encrypted message:", encrypt(message, shift))
elif choice == 'd':
    print("Decrypted message:", decrypt(message, shift))
else:
    print("Invalid choice.")
