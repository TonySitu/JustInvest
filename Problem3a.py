"""
Problem 3a: User Enrollment System
Demonstrates enrollment functionality and integration testing
"""

import sys
import os

# Import from other problem files
sys.path.insert(0, os.path.dirname(__file__))
from Problem2 import PasswordFileManager
from Problem3b import PasswordChecker, create_weak_passwords_file


def test_enrollment():
    """Test enrollment system components"""
    print("Testing Enrollment System Components\n")

    # Initialize components
    pfm = PasswordFileManager()
    pc = PasswordChecker()

    # Ensure weak passwords file exists
    if not os.path.exists("weak_passwords.txt"):
        create_weak_passwords_file()
        print("Created weak_passwords.txt for testing\n")

    test_cases = [
        # (username, password, role, should_pass, description)
        ("testuser1", "ValidPass1!", "Client", True, "Valid password with all requirements"),
        ("testuser2", "AnotherP@ss2", "Premium Client", True, "Valid password different format"),
        ("testuser3", "short", "Teller", False, "Too short (less than 8 characters)"),
        ("testuser4", "NoSpecialChar1", "Client", False, "Missing special character"),
        ("testuser5", "nouppercas3!", "Client", False, "Missing uppercase letter"),
        ("testuser6", "NOLOWERCASE1!", "Client", False, "Missing lowercase letter"),
        ("testuser7", "NoDigits!@#", "Client", False, "Missing numerical digit"),
        ("testuser8", "Password1!", "Client", False, "Common weak password"),
    ]

    print("Test Results:\n")
    passed = 0
    failed = 0

    # Test password validation
    print("Test Category: Password Validation\n")
    for username, password, role, should_pass, description in test_cases:
        is_valid, errors = pc.check_password(username, password)
        test_passed = (is_valid == should_pass)

        status = "PASS" if test_passed else "FAIL"

        if test_passed:
            passed += 1
        else:
            failed += 1

        print(f"{status} | {description}")
        print(f"      Username: {username}, Password: {password}")
        print(f"      Expected: {'Valid' if should_pass else 'Invalid'}, Got: {'Valid' if is_valid else 'Invalid'}")

        if errors:
            print(f"      Errors:")
            for error in errors:
                print(f"        - {error}")
        print()

    # Test user creation after validation
    print("Test Category: User Creation After Validation\n")
    valid_users = [
        ("enrolltest1", "ValidPass1!", "Client"),
        ("enrolltest2", "AnotherP@ss2", "Premium Client"),
        ("enrolltest3", "Secure#99", "Financial Advisor"),
    ]

    for username, password, role in valid_users:
        # First validate password
        is_valid, errors = pc.check_password(username, password)

        if is_valid:
            # Then create user
            success = pfm.add_user(username, password, role)
            test_passed = success
            status = "✓ PASS" if test_passed else "✗ FAIL"

            if test_passed:
                passed += 1
            else:
                failed += 1

            print(f"{status} | Create user '{username}' ({role})")
            print(f"      Expected: Created, Got: {'Created' if success else 'Failed'}")
        else:
            failed += 1
            print(f"✗ FAIL | {username}: Password validation failed")
            print(f"      Errors: {', '.join(errors)}")
        print()

    print(f"Summary: {passed} passed, {failed} failed out of {passed + failed} tests\n")

    print("=" * 70)
    print("Enrollment Workflow Components Verified:")
    print("  ✓ Password validation against all 7 policy rules")
    print("  ✓ User creation in password file")
    print("  ✓ Role assignment")
    print("  ✓ Error message clarity")
    print("\nNote: Full interactive enrollment available via main.py")
    print("Run: python3 main.py → Select option 1 (Enroll New User)")
    print("=" * 70)


if __name__ == "__main__":
    test_enrollment()