"""
Problem 4: User Login and Access Control System
Complete implementation with login interface and permission display
"""

import sys
import os
from datetime import datetime

# Import from other problem files
sys.path.insert(0, os.path.dirname(__file__))
from Problem1 import AccessControlManager, Role, Permission
from Problem2 import PasswordFileManager


class LoginSystem:
    """Handles user login and displays access privileges"""

    def __init__(self):
        self.password_manager = PasswordFileManager()
        self.access_control = AccessControlManager()
        self.max_login_attempts = 3

    def display_welcome(self):
        """Display welcome screen"""
        print("\n" + "=" * 60)
        print(" " * 18 + "justInvest System")
        print("=" * 60 + "\n")

    def get_role_enum(self, role_string: str):
        """Convert role string to Role enum"""
        role_mapping = {
            "Client": Role.CLIENT,
            "Premium Client": Role.PREMIUM_CLIENT,
            "Financial Advisor": Role.FINANCIAL_ADVISOR,
            "Financial Planner": Role.FINANCIAL_PLANNER,
            "Teller": Role.TELLER
        }
        return role_mapping.get(role_string)

    def display_operations_menu(self):
        """Display all possible operations in the system"""
        print("\nOperations available in the system:")
        operations = [
            "1. View account balance",
            "2. View investment portfolio",
            "3. Modify investment portfolio",
            "4. View Financial Advisor contact info",
            "5. View Financial Planner contact info",
            "6. View money market instruments",
            "7. View private consumer instruments"
        ]
        for op in operations:
            print(f"  {op}")
        print()

    def display_user_permissions(self, username: str, role: Role):
        """Display user's authorized operations"""
        print(f"\nEnter username: {username}")
        print("Enter password: **********")
        print("\nACCESS GRANTED!")
        print(f"Your authorized operations are: ", end="")

        # Get all permissions for the role
        permissions = self.access_control.get_permissions(role)

        # Map permissions to operation numbers
        permission_map = {
            Permission.VIEW_ACCOUNT_BALANCE: 1,
            Permission.VIEW_INVESTMENT_PORTFOLIO: 2,
            Permission.MODIFY_INVESTMENT_PORTFOLIO: 3,
            Permission.VIEW_FA_CONTACT: 4,
            Permission.VIEW_FP_CONTACT: 5,
            Permission.VIEW_MONEY_MARKET: 6,
            Permission.VIEW_PRIVATE_CONSUMER: 7
        }

        operation_numbers = [permission_map[p] for p in permissions if p in permission_map]
        operation_numbers.sort()
        print(','.join(map(str, operation_numbers)))

        print("\nWhich operation would you like to perform?")

    def display_access_summary(self, username: str, role: Role):
        """Display detailed access summary"""
        print("\n" + "=" * 60)
        print("USER ACCESS SUMMARY")
        print("=" * 60)
        print(f"Username: {username}")
        print(f"Role: {role.value}")
        print("\nAuthorized Operations:")

        permissions = self.access_control.get_permissions(role)
        for i, perm in enumerate(permissions, 1):
            print(f"  {i}. {perm.value}")

        # Display time restrictions if applicable
        if role == Role.TELLER:
            print("\nTime Restrictions:")
            print("  - Access permitted only during business hours (9:00 AM - 5:00 PM)")
            current_hour = datetime.now().hour
            if 9 <= current_hour < 17:
                print("  - Current status: WITHIN business hours")
            else:
                print("  - Current status: OUTSIDE business hours")

        print("=" * 60 + "\n")

    def login(self):
        """Handle user login process"""
        self.display_welcome()
        self.display_operations_menu()

        attempts = 0

        while attempts < self.max_login_attempts:
            username = input("Enter username: ").strip()

            if not username:
                print("Error: Username cannot be empty\n")
                continue

            # Use getpass for password in production
            password = input("Enter password: ").strip()

            # Verify credentials
            success, user_data = self.password_manager.verify_user(username, password)

            if success:
                role_string = user_data['role']
                role_enum = self.get_role_enum(role_string)

                if role_enum is None:
                    print(f"Error: Invalid role '{role_string}'\n")
                    return None

                # Check time-based restrictions
                time_allowed, time_msg = self.access_control.check_time_restriction(role_enum)

                if not time_allowed:
                    print(f"\nAccess Denied: {time_msg}\n")
                    return None

                # Display access information
                print("\nACCESS GRANTED!")
                self.display_access_summary(username, role_enum)

                return {
                    'username': username,
                    'role': role_enum,
                    'role_string': role_string
                }
            else:
                attempts += 1
                remaining = self.max_login_attempts - attempts

                if remaining > 0:
                    print(f"\nInvalid credentials. {remaining} attempt(s) remaining.\n")
                else:
                    print("\nMaximum login attempts reached. Access denied.\n")

        return None

    def interactive_session(self, user_info):
        """Run an interactive session after successful login"""
        username = user_info['username']
        role = user_info['role']

        print(f"Welcome, {username}!")
        print("\nYou can now perform any of your authorized operations.")
        print("(This is a prototype - actual operations not implemented)")

        # Show menu of user's operations
        permissions = self.access_control.get_permissions(role)

        while True:
            print("\n" + "-" * 60)
            print("Your authorized operations:")
            for i, perm in enumerate(permissions, 1):
                print(f"  {i}. {perm.value}")
            print(f"  {len(permissions) + 1}. Logout")

            choice = input("\nSelect operation (or logout): ").strip()

            if choice == str(len(permissions) + 1):
                print("\nLogging out... Goodbye!")
                break

            try:
                choice_num = int(choice)
                if 1 <= choice_num <= len(permissions):
                    selected_perm = list(permissions)[choice_num - 1]
                    authorized, msg = self.access_control.authorize_operation(role, selected_perm)

                    if authorized:
                        print(f"\n✓ {selected_perm.value}")
                        print("  (Operation successful - prototype mode)")
                    else:
                        print(f"\n✗ Access Denied: {msg}")
                else:
                    print("Invalid choice. Please try again.")
            except ValueError:
                print("Invalid input. Please enter a number.")


def initialize_sample_users():
    """Initialize password file with sample users for testing"""
    pfm = PasswordFileManager()

    sample_users = [
        ("sasha.kim", "Client@123", "Client"),
        ("emery.blake", "Client@456", "Client"),
        ("noor.abbasi", "Premium#789", "Premium Client"),
        ("zuri.adebayo", "Premium#012", "Premium Client"),
        ("mikael.chen", "Advisor$345", "Financial Advisor"),
        ("jordan.riley", "Advisor$678", "Financial Advisor"),
        ("ellis.nakamura", "Planner&901", "Financial Planner"),
        ("harper.diaz", "Planner&234", "Financial Planner"),
        ("alex.hayes", "Teller*567", "Teller"),
        ("adair.patel", "Teller*890", "Teller"),
    ]

    print("Initializing sample users...")
    for username, password, role in sample_users:
        pfm.add_user(username, password, role)
    print("Sample users created!\n")


def test_login_system():
    """Test the login system with various scenarios"""
    print("=== Testing Login System ===\n")

    # Initialize sample users
    if not os.path.exists("passwd.txt"):
        initialize_sample_users()

    login_system = LoginSystem()

    # Test cases
    test_cases = [
        ("sasha.kim", "Client@123", "Client", True),
        ("mikael.chen", "Advisor$345", "Financial Advisor", True),
        ("alex.hayes", "Teller*567", "Teller", True),
        ("invalid.user", "WrongPass1!", "N/A", False),
        ("sasha.kim", "WrongPassword", "N/A", False),
    ]

    print("Test Results:\n")

    for username, password, expected_role, should_succeed in test_cases:
        print(f"Testing: {username}")
        success, user_data = login_system.password_manager.verify_user(username, password)

        if should_succeed:
            if success and user_data['role'] == expected_role:
                print(f"  ✓ PASS - Successfully authenticated as {expected_role}")

                role_enum = login_system.get_role_enum(user_data['role'])
                permissions = login_system.access_control.get_permissions(role_enum)
                print(f"  Permissions: {len(permissions)} operations authorized")
            else:
                print(f"  ✗ FAIL - Expected success but got failure")
        else:
            if not success:
                print(f"  ✓ PASS - Correctly rejected invalid credentials")
            else:
                print(f"  ✗ FAIL - Should have rejected but authenticated")
        print()

    print("Login system testing completed!")


def run_login_interface():
    """Run the interactive login interface"""
    # Initialize sample users if needed
    if not os.path.exists("passwd.txt"):
        print("No users found. Creating sample users...")
        initialize_sample_users()

    login_system = LoginSystem()
    user_info = login_system.login()

    if user_info:
        login_system.interactive_session(user_info)


if __name__ == "__main__":
    # For interactive use (uncomment to run)
    # run_login_interface()

    # For testing
    test_login_system()
