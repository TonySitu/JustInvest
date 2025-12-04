"""
justInvest User Authentication and Access Control System
Main entry point for the complete system
"""

import sys
import os

from Problem2 import PasswordFileManager
from Problem3b import PasswordChecker, create_weak_passwords_file
from Problem4 import LoginSystem, initialize_sample_users

class EnrollmentSystem:
    """Handles user enrollment with password validation"""

    def __init__(self):
        self.password_manager = PasswordFileManager()
        self.password_checker = PasswordChecker()

        # Available roles for enrollment
        self.available_roles = {
            '1': 'Client',
            '2': 'Premium Client',
            '3': 'Financial Advisor',
            '4': 'Financial Planner',
            '5': 'Teller'
        }

    def display_welcome(self):
        """Display welcome message"""
        print("\n" + "=" * 60)
        print(" " * 15 + "justInvest System")
        print(" " * 15 + "User Enrollment")
        print("=" * 60 + "\n")

    def get_username(self):
        """Get and validate username from user"""
        while True:
            username = input("Enter username: ").strip()

            if not username:
                print("Error: Username cannot be empty\n")
                continue

            if len(username) < 3:
                print("Error: Username must be at least 3 characters\n")
                continue

            if ' ' in username:
                print("Error: Username cannot contain spaces\n")
                continue

            return username

    def get_role(self):
        """Get role selection from user"""
        print("\nSelect your role:")
        for key, role in self.available_roles.items():
            print(f"  {key}. {role}")

        while True:
            choice = input("\nEnter role number (1-5): ").strip()

            if choice in self.available_roles:
                return self.available_roles[choice]
            else:
                print("Error: Invalid choice. Please enter a number between 1 and 5")

    def get_password(self, username):
        """Get and validate password from user"""
        print("\n" + "-" * 60)
        print(self.password_checker.get_password_requirements())
        print("-" * 60 + "\n")

        max_attempts = 3
        attempts = 0

        while attempts < max_attempts:
            password = input("Enter password: ").strip()
            confirm_password = input("Confirm password: ").strip()

            # Check if passwords match
            if password != confirm_password:
                print("\nError: Passwords do not match. Please try again.\n")
                attempts += 1
                continue

            # Validate password against policy
            is_valid, errors = self.password_checker.check_password(username, password)

            if is_valid:
                return password
            else:
                print("\nPassword does not meet requirements:")
                for error in errors:
                    print(f"  - {error}")
                print()
                attempts += 1

                if attempts < max_attempts:
                    print(f"Attempts remaining: {max_attempts - attempts}\n")

        return None

    def enroll_user(self):
        """Main enrollment flow"""
        self.display_welcome()

        # Get username
        username = self.get_username()

        # Get role
        role = self.get_role()

        # Get and validate password
        password = self.get_password(username)

        if password is None:
            print("\nEnrollment failed: Maximum password attempts reached")
            return False

        # Add user to password file
        print("\nCreating account...")
        success = self.password_manager.add_user(username, password, role)

        if success:
            print("\n" + "=" * 60)
            print("SUCCESS! Your account has been created.")
            print(f"Username: {username}")
            print(f"Role: {role}")
            print("\nYou can now log in to the justInvest system.")
            print("=" * 60 + "\n")
            return True
        else:
            print("\nEnrollment failed: Unable to create account")
            return False

class JustInvestSystem:
    """Main system orchestrator"""

    def __init__(self):
        self.enrollment = EnrollmentSystem()
        self.login = LoginSystem()

    def display_main_menu(self):
        """Display main menu"""
        print("\n" + "=" * 60)
        print(" " * 15 + "justInvest System")
        print(" " * 10 + "User Authentication and Access Control")
        print("=" * 60)
        print("\nMain Menu:")
        print("  1. Enroll New User")
        print("  2. Login to System")
        print("  3. Initialize Sample Users (Testing)")
        print("  4. Exit")
        print("=" * 60)

    def run(self):
        """Main system loop"""
        # Ensure weak passwords file exists
        if not os.path.exists("weak_passwords.txt"):
            print("Creating weak passwords file...")
            create_weak_passwords_file()

        while True:
            self.display_main_menu()
            choice = input("\nEnter your choice (1-4): ").strip()

            if choice == '1':
                # Enrollment
                self.enrollment.enroll_user()
                input("\nPress Enter to continue...")

            elif choice == '2':
                # Login
                if not os.path.exists("passwd.txt"):
                    print("\nNo users enrolled yet. Please enroll first or initialize sample users.")
                    input("\nPress Enter to continue...")
                    continue

                user_info = self.login.login()
                if user_info:
                    self.login.interactive_session(user_info)
                input("\nPress Enter to continue...")

            elif choice == '3':
                # Initialize sample users for testing
                confirm = input("\nThis will create sample users. Continue? (yes/no): ").strip().lower()
                if confirm in ['yes', 'y']:
                    initialize_sample_users()
                    print("\nSample users created successfully!")
                    print("You can now login with any of these users.")
                    print("(Check README.md for credentials)")
                input("\nPress Enter to continue...")

            elif choice == '4':
                print("\nThank you for using justInvest System. Goodbye!")
                break

            else:
                print("\nInvalid choice. Please try again.")
                input("\nPress Enter to continue...")

def main():
    """Entry point"""
    system = JustInvestSystem()
    system.run()

if __name__ == "__main__":
    main()