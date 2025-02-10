import re
import random
import string

def password_strength(password):
    length_error = len(password) < 8
    digit_error = re.search(r"\d", password) is None
    uppercase_error = re.search(r"[A-Z]", password) is None
    lowercase_error = re.search(r"[a-z]", password) is None
    symbol_error = re.search(r"[ @!#$%^&*()<>?/\|}{~:]", password) is None
    password_ok = not (length_error or digit_error or uppercase_error or lowercase_error or symbol_error)
    
    return {
        'password_ok': password_ok,
        'length_error': length_error,
        'digit_error': digit_error,
        'uppercase_error': uppercase_error,
        'lowercase_error': lowercase_error,
        'symbol_error': symbol_error,
    }

def generate_password(length=12, use_digits=True, use_uppercase=True, use_lowercase=True, use_symbols=True):
    characters = ""
    if use_digits:
        characters += string.digits
    if use_uppercase:
        characters += string.ascii_uppercase
    if use_lowercase:
        characters += string.ascii_lowercase
    if use_symbols:
        characters += string.punctuation

    if not characters:
        raise ValueError("At least one character set must be selected")

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def main():
    while True:
        print("1. Check password strength")
        print("2. Generate a password")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            password = input("Enter the password to check: ")
            result = password_strength(password)
            if result['password_ok']:
                print("Password is strong")
            else:
                print("Password is weak")
                if result['length_error']:
                    print("Password must be at least 8 characters long")
                if result['digit_error']:
                    print("Password must contain at least one digit")
                if result['uppercase_error']:
                    print("Password must contain at least one uppercase letter")
                if result['lowercase_error']:
                    print("Password must contain at least one lowercase letter")
                if result['symbol_error']:
                    print("Password must contain at least one special character")
        elif choice == '2':
            length = int(input("Enter the desired length of the password: "))
            use_digits = input("Include digits? (yes/no): ").lower() == 'yes'
            use_uppercase = input("Include uppercase letters? (yes/no): ").lower() == 'yes'
            use_lowercase = input("Include lowercase letters? (yes/no): ").lower() == 'yes'
            use_symbols = input("Include symbols? (yes/no): ").lower() == 'yes'
            password = generate_password(length, use_digits, use_uppercase, use_lowercase, use_symbols)
            print(f"Generated password: {password}")
        elif choice == '3':
            break
        else:
            print("Invalid choice, please try again")

if __name__ == "__main__":
    main()