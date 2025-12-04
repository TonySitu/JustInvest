
import re
import os


class PasswordChecker:
    """Password checker implementing justInvest password policy"""

    def __init__(self, weak_passwords_file="weak_passwords.txt"):
        self.weak_passwords_file = weak_passwords_file
        self.weak_passwords = self._load_weak_passwords()

    @staticmethod
    def get_password_requirements():
        """Return a formatted string of password requirements"""
        requirements = """
            Password Requirements:
            - Length: 8-12 characters
            - Must include at least:
            * One uppercase letter (A-Z)
            * One lowercase letter (a-z)
            * One numerical digit (0-9)
            * One special character (!, @, #, $, %, *, &)
            - Must not be a common weak password
            - Must not match your username
        """
        return requirements.strip()

    def _load_weak_passwords(self):
        """Load list of weak passwords from file"""
        weak_passwords = set()

        if os.path.exists(self.weak_passwords_file):
            try:
                with open(self.weak_passwords_file, 'r') as f:
                    for line in f:
                        password = line.strip().lower()
                        if password:
                            weak_passwords.add(password)
            except Exception as e:
                print(f"Warning: Could not load weak passwords file: {e}")

        return weak_passwords

    def check_password(self, username: str, password: str) -> tuple:
        """
        Check if password meets all policy requirements
        """
        errors = []

        # Rule 1: Length between 8 and 12 characters
        if len(password) < 8:
            errors.append("Password must be at least 8 characters long")
        elif len(password) > 12:
            errors.append("Password must not exceed 12 characters")

        # Rule 2: At least one uppercase letter
        if not re.search(r'[A-Z]', password):
            errors.append("Password must contain at least one uppercase letter")

        # Rule 3: At least one lowercase letter
        if not re.search(r'[a-z]', password):
            errors.append("Password must contain at least one lowercase letter")

        # Rule 4: At least one numerical digit
        if not re.search(r'[0-9]', password):
            errors.append("Password must contain at least one numerical digit")

        # Rule 5: At least one special character from: !, @, #, $, %, *, &
        if not re.search(r'[!@#$%*&]', password):
            errors.append("Password must contain at least one special character from: !, @, #, $, %, *, &")

        # Rule 6: Not in weak passwords list
        if password.lower() in self.weak_passwords:
            errors.append("Password is too common and appears on the list of weak passwords")

        # Rule 7: Password must not match username
        if password.lower() == username.lower():
            errors.append("Password must not match the username")

        is_valid = len(errors) == 0
        return is_valid, errors


def create_weak_passwords_file():
    """Create a sample weak passwords file"""
    weak_passwords = [
        "password",
        "password1",
        "password123",
        "12345678",
        "qwerty123",
        "letmein",
        "welcome1",
        "admin123",
        "monkey123",
        "dragon123",
        "abc12345",
        "iloveyou",
        "trustno1",
        "sunshine",
        "football",
        "princess",
        "starwars",
        "Password1!",
        "Welcome1!",
        "Admin123!",
        "Passw0rd!",
        "Test1234!",
        "User123@",
        "Login1#",
        "Secret1$"
    ]

    with open("weak_passwords.txt", 'w') as f:
        for pwd in weak_passwords:
            f.write(pwd.lower() + '\n')


# Test cases for password checker
def test_password_checker():
    """Test the proactive password checker"""
    print("Testing Proactive Password Checker\n")

    # Create weak passwords file
    create_weak_passwords_file()

    # Initialize checker
    checker = PasswordChecker()

    # Test cases
    test_cases = [
        # (username, password, expected_result, description)
        ("john.doe", "SecureP@ss1", True, "Valid password"),
        ("jane.smith", "MyP@ssw0rd", True, "Valid password with all requirements"),
        ("user", "Short1!", False, "Too short (less than 8 characters)"),
        ("user", "ThisPasswordIsMuchTooLong!!", False, "Too long (more than 12 characters)"),
        ("user", "nouppercase1!", False, "Missing uppercase letter"),
        ("user", "NOLOWERCASE1!", False, "Missing lowercase letter"),
        ("user", "NoDigits!@#", False, "Missing numerical digit"),
        ("user", "NoSpecial123", False, "Missing special character"),
        ("user", "WrongChar1^", False, "Wrong special character (^ not allowed)"),
        ("admin", "Password1!", False, "Common weak password"),
        ("testuser", "testuser1!", False, "Password matches username"),
        ("user", "password", False, "Multiple violations"),
        ("alice", "Welcome1!", False, "Weak password from list"),
        ("bob.jones", "MySecure#9", True, "Valid with # character"),
        ("charlie", "Strong&P4ss", True, "Valid with & character")
    ]

    print("Test Results:\n")
    passed = 0
    failed = 0

    for username, password, expected_valid, description in test_cases:
        is_valid, errors = checker.check_password(username, password)

        test_passed = (is_valid == expected_valid)
        status = "PASS" if test_passed else "FAIL"

        if test_passed:
            passed += 1
        else:
            failed += 1

        print(f"{status} | {description}")
        print(f"      Username: {username}, Password: {password}")
        print(f"      Expected: {'Valid' if expected_valid else 'Invalid'}, Got: {'Valid' if is_valid else 'Invalid'}")

        if errors:
            print(f"      Errors:")
            for error in errors:
                print(f"        - {error}")
        print()

    print(f"Summary: {passed} passed, {failed} failed out of {len(test_cases)} tests\n")

    # Display requirements
    print("=" * 60)
    print(checker.get_password_requirements())
    print("=" * 60)


if __name__ == "__main__":
    test_password_checker()
