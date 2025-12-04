
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

    # Test Case 1: Add new users
    print("Test Case 1: Adding New Users")
    test_users = [
        ("sasha.kim", "SecurePass1!", "Client"),
        ("emery.blake", "MyP@ssw0rd", "Client"),
        ("noor.abbasi", "Premium123#", "Premium Client"),
        ("mikael.chen", "Advisor$99", "Financial Advisor"),
    ]

    for username, password, role in test_users:
        success = pfm.add_user(username, password, role)
        print(f"  {username}: {'Success' if success else 'Failed'}")
    print()

    # Test Case 2: Prevent duplicate users
    print("Test Case 2: Duplicate User Prevention")
    pfm.add_user("sasha.kim", "AnotherPass1!", "Client")
    print()

    # Test Case 3: Verify correct passwords
    print("Test Case 3: Correct Password Verification")
    for username, password, _ in test_users:
        success, user_data = pfm.verify_user(username, password)
        print(f"  {username}: {'Verified' if success else 'Failed'}")
        if success:
            print(f"    Role: {user_data['role']}")
    print()

    # Test Case 4: Reject incorrect passwords
    print("Test Case 4: Incorrect Password Rejection")
    wrong_tests = [
        ("sasha.kim", "WrongPassword1!"),
        ("mikael.chen", "incorrect"),
        ("nonexistent.user", "SomePass1!")
    ]

    for username, password in wrong_tests:
        success, _ = pfm.verify_user(username, password)
        print(f"  {username} with wrong password: {'ERROR - Accepted!' if success else 'Correctly rejected'}")
    print()

    # Test Case 5: Display password file structure
    print("Test Case 5: Password File Structure")
    print("Example records from passwd.txt:")
    with open("test_passwd.txt", 'r') as f:
        lines = f.readlines()[:2]  # Show first 2 records
        for i, line in enumerate(lines, 1):
            line_data = line.strip().split(':')
            print(f"\nRecord {i}:")
            print(f"  Username: {line_data[0]}")
            print(f"  Salt: {line_data[1][:16]}...")
            print(f"  Hash: {line_data[2][:16]}...")
            print(f"  Role: {line_data[3]}")
    print()

    # Clean up test file
    os.remove("test_passwd.txt")
    print("Test completed. Test file cleaned up.")


if __name__ == "__main__":
    test_password_file()
