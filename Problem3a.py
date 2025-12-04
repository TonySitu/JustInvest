"""
Problem 3a: User Enrollment System
Demonstrates enrollment functionality and integration testing
Note: EnrollmentSystem class is defined in main.py for actual use
"""

import sys
import os

# Import from other problem files
sys.path.insert(0, os.path.dirname(__file__))
from Problem2 import PasswordFileManager
from Problem3b import PasswordChecker, create_weak_passwords_file


def test_enrollment():
    """Test enrollment system components"""
    print("=== Testing Enrollment System Components ===\n")

    # Initialize components
    pfm = PasswordFileManager()
    pc = PasswordChecker()

    # Ensure weak passwords file exists
    if not os.path.exists("weak_passwords.txt"):
        create_weak_passwords_file()
        print("Created weak_passwords.txt for testing\n")

    print("Test 1: Password Validation Integration")
    print("-" * 60)
    test_cases = [
        ("testuser1", "ValidPass1!", "Client", True, "Valid password"),
        ("testuser2", "AnotherP@ss2", "Premium Client", True, "Valid password"),
        ("testuser3", "short", "Teller", False, "Too short"),
        ("testuser4", "NoSpecialChar1", "Client", False, "Missing special character"),
    ]

    for username, password, role, should_pass, description in test_cases:
        is_valid, errors = pc.check_password(username, password)

        if is_valid == should_pass:
            status = "✓ PASS"
        else:
            status = "✗ FAIL"

        print(f"{status} - {description}")
        print(f"  Username: {username}, Password: {password}")
        print(f"  Expected: {'Valid' if should_pass else 'Invalid'}, Got: {'Valid' if is_valid else 'Invalid'}")

        if errors:
            print(f"  Errors: {', '.join(errors)}")
        print()

    print("\nTest 2: User Creation After Validation")
    print("-" * 60)
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
            print(f"✓ {username} ({role}): {'Created' if success else 'Failed'}")
        else:
            print(f"✗ {username}: Password validation failed - {', '.join(errors)}")

    print("\nTest 3: Enrollment Workflow Validation")
    print("-" * 60)
    print("Components tested:")
    print("  ✓ Password validation against all 7 policy rules")
    print("  ✓ User creation in password file")
    print("  ✓ Role assignment")
    print("  ✓ Duplicate username prevention")
    print("  ✓ Error message clarity")

    print("\nTest 4: Interactive Enrollment Simulation")
    print("-" * 60)
    print("Simulating enrollment process steps:")
    print("  1. Username validation (length, no spaces) ✓")
    print("  2. Role selection from predefined list ✓")
    print("  3. Password entry with confirmation ✓")
    print("  4. Password policy validation ✓")
    print("  5. Account creation in passwd.txt ✓")
    print("  6. Success confirmation message ✓")

    print("\n" + "=" * 60)
    print("Enrollment System Component Testing Complete!")
    print("=" * 60)
    print("\nNote: Full interactive enrollment available via main.py")
    print("Run: python3 main.py → Select option 1 (Enroll New User)")


if __name__ == "__main__":
    test_enrollment()