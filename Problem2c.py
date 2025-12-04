
import hashlib
import secrets
import os


class PasswordFileManager:
    """Manages password file operations with secure hashing"""

    def __init__(self, password_file="passwd.txt"):
        self.password_file = password_file
        self.salt_length = 16  # (128 bits)
        self.hash_iterations = 100000

    def _generate_salt(self):
        """Generate a cryptographically secure random salt"""
        return secrets.token_hex(self.salt_length)

    def _hash_password(self, password: str, salt: str) -> str:
        """
        Hash password
        """
        password_bytes = password.encode('utf-8')
        salt_bytes = bytes.fromhex(salt)

        # Hashes with 100,000 iterations
        hash_bytes = hashlib.pbkdf2_hmac(
            'sha256',
            password_bytes,
            salt_bytes,
            self.hash_iterations,
            dklen=32  # 32 bytes = 256 bits
        )

        return hash_bytes.hex()

    def add_user(self, username: str, password: str, role: str) -> bool:
        """
        Add a new user record to the password file
        Record format: username:salt:hash:role
        """
        try:
            # Check if user already exists
            if self._user_exists(username):
                print(f"Error: User '{username}' already exists")
                return False

            # Generate salt and hash password
            salt = self._generate_salt()
            password_hash = self._hash_password(password, salt)

            # Create record
            record = f"{username}:{salt}:{password_hash}:{role}\n"

            # Append to password file
            with open(self.password_file, 'a') as f:
                f.write(record)

            print(f"User '{username}' added successfully")
            return True

        except Exception as e:
            print(f"Error adding user: {e}")
            return False

    def _user_exists(self, username: str) -> bool:
        """Check if a user already exists in the password file"""
        if not os.path.exists(self.password_file):
            return False

        try:
            with open(self.password_file, 'r') as f:
                for line in f:
                    stored_username = line.split(':')[0]
                    if stored_username == username:
                        return True
        except Exception:
            pass

        return False

    def verify_user(self, username: str, password: str) -> tuple:
        """
        Verify user credentials
        Returns: (bool, dict) - (success, user_data)
        """
        if not os.path.exists(self.password_file):
            return False, None

        try:
            with open(self.password_file, 'r') as f:
                for line in f:
                    line_data = line.strip().split(':')
                    if len(line_data) != 4:
                        continue

                    stored_username, salt, stored_hash, role = line_data

                    if stored_username == username:
                        # Hash the provided password with stored salt
                        computed_hash = self._hash_password(password, salt)

                        # Compare hashes
                        if secrets.compare_digest(computed_hash, stored_hash):
                            user_data = {
                                'username': username,
                                'role': role
                            }
                            return True, user_data
                        else:
                            return False, None

            # User not found
            return False, None

        except Exception as e:
            print(f"Error verifying user: {e}")
            return False, None

    def get_user_role(self, username: str) -> str | None:
        """Returns the role of a user"""
        if not os.path.exists(self.password_file):
            return None

        try:
            with open(self.password_file, 'r') as f:
                for line in f:
                    line_data = line.strip().split(':')
                    if len(line_data) == 4 and line_data[0] == username:
                        return line_data[3]
        except Exception:
            pass

        return None


# Test cases for Problem 2
def test_password_file():
    """Test password file functionality"""
    print("Testing Password File Management\n")

    # Initialize manager
    pfm = PasswordFileManager("test_passwd.txt")

    # Clean up any existing test file
    if os.path.exists("test_passwd.txt"):
        os.remove("test_passwd.txt")

    # Test data
    test_users = [
        ("sasha.kim", "SecurePass1!", "Client"),
        ("emery.blake", "MyP@ssw0rd", "Client"),
        ("noor.abbasi", "Premium123#", "Premium Client"),
        ("mikael.chen", "Advisor$99", "Financial Advisor"),
    ]

    print("Test Results:\n")
    passed = 0
    failed = 0

    # Test Case 1: Add new users
    print("Test Category: Adding New Users\n")
    for username, password, role in test_users:
        success = pfm.add_user(username, password, role)
        test_passed = success
        status = "PASS" if test_passed else "FAIL"

        if test_passed:
            passed += 1
        else:
            failed += 1

        print(f"{status} | Add user '{username}'")
        print(f"      Role: {role}")
        print(f"      Expected: Success, Got: {'Success' if success else 'Failed'}")
        print()

    # Test Case 2: Prevent duplicate users
    print("Test Category: Duplicate User Prevention\n")
    duplicate_test = pfm.add_user("sasha.kim", "AnotherPass1!", "Client")
    test_passed = not duplicate_test
    status = "PASS" if test_passed else "FAIL"

    if test_passed:
        passed += 1
    else:
        failed += 1

    print(f"{status} | Duplicate username rejection")
    print(f"      Attempted: sasha.kim (already exists)")
    print(f"      Expected: Rejected, Got: {'Rejected' if not duplicate_test else 'Accepted (ERROR)'}")
    print()

    # Test Case 3: Verify correct passwords
    print("Test Category: Correct Password Verification\n")
    for username, password, role in test_users:
        success, user_data = pfm.verify_user(username, password)
        test_passed = success and user_data and user_data['role'] == role
        status = "PASS" if test_passed else "FAIL"

        if test_passed:
            passed += 1
        else:
            failed += 1

        print(f"{status} | Verify user '{username}'")
        print(f"      Expected: Success with role '{role}'")
        print(f"      Got: {'Success' if success else 'Failed'}")
        if success and user_data:
            print(f"      Role returned: {user_data['role']}")
        print()

    # Test Case 4: Reject incorrect passwords
    print("Test Category: Incorrect Password Rejection\n")
    wrong_tests = [
        ("sasha.kim", "WrongPassword1!", "Existing user, wrong password"),
        ("mikael.chen", "incorrect", "Existing user, wrong password"),
        ("nonexistent.user", "SomePass1!", "Non-existent user"),
    ]

    for username, password, description in wrong_tests:
        success, _ = pfm.verify_user(username, password)
        test_passed = not success
        status = "PASS" if test_passed else "FAIL"

        if test_passed:
            passed += 1
        else:
            failed += 1

        print(f"{status} | {description}")
        print(f"      Username: {username}")
        print(f"      Expected: Rejected, Got: {'Rejected' if not success else 'Accepted (ERROR)'}")
        print()

    # Test Case 5: Password file structure validation
    print("Test Category: Password File Structure\n")
    with open("test_passwd.txt", 'r') as f:
        lines = f.readlines()
        structure_valid = True

        for i, line in enumerate(lines[:2], 1):
            parts = line.strip().split(':')

            # Check field count
            field_count_ok = len(parts) == 4
            # Check salt length (32 hex chars = 16 bytes)
            salt_length_ok = len(parts[1]) == 32
            # Check hash length (64 hex chars = 32 bytes)
            hash_length_ok = len(parts[2]) == 64

            record_valid = field_count_ok and salt_length_ok and hash_length_ok
            test_passed = record_valid
            status = "PASS" if test_passed else "FAIL"

            if test_passed:
                passed += 1
            else:
                failed += 1

            print(f"{status} | Record {i} structure validation")
            print(f"      Username: {parts[0]}")
            print(f"      Fields: {len(parts)} (expected: 4)")
            print(f"      Salt length: {len(parts[1])} chars (expected: 32)")
            print(f"      Hash length: {len(parts[2])} chars (expected: 64)")
            print(f"      Role: {parts[3]}")
            print()

    print(f"Summary: {passed} passed, {failed} failed out of {passed + failed} tests\n")

    # Clean up test file
    os.remove("test_passwd.txt")
    print("Test file cleaned up.")


if __name__ == "__main__":
    test_password_file()