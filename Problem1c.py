
from datetime import datetime
from enum import Enum


class Role(Enum):
    """User roles in the justInvest system"""
    CLIENT = "Client"
    PREMIUM_CLIENT = "Premium Client"
    FINANCIAL_ADVISOR = "Financial Advisor"
    FINANCIAL_PLANNER = "Financial Planner"
    TELLER = "Teller"


class Permission(Enum):
    """System permissions"""
    VIEW_ACCOUNT_BALANCE = "View account balance"
    VIEW_INVESTMENT_PORTFOLIO = "View investment portfolio"
    MODIFY_INVESTMENT_PORTFOLIO = "Modify investment portfolio"
    VIEW_FA_CONTACT = "View Financial Advisor contact info"
    VIEW_FP_CONTACT = "View Financial Planner contact info"
    VIEW_MONEY_MARKET = "View money market instruments"
    VIEW_PRIVATE_CONSUMER = "View private consumer instruments"


class AccessControlManager:
    """Manages access control using RBAC model"""

    def __init__(self):
        # Define role-permission mappings based on justInvest policy
        self.role_permissions = {
            Role.CLIENT: [
                Permission.VIEW_ACCOUNT_BALANCE,
                Permission.VIEW_INVESTMENT_PORTFOLIO,
                Permission.VIEW_FA_CONTACT
            ],
            Role.PREMIUM_CLIENT: [
                Permission.VIEW_ACCOUNT_BALANCE,
                Permission.VIEW_INVESTMENT_PORTFOLIO,
                Permission.VIEW_FA_CONTACT,
                Permission.MODIFY_INVESTMENT_PORTFOLIO,
                Permission.VIEW_FP_CONTACT
            ],
            Role.FINANCIAL_ADVISOR: [
                Permission.VIEW_ACCOUNT_BALANCE,
                Permission.VIEW_INVESTMENT_PORTFOLIO,
                Permission.MODIFY_INVESTMENT_PORTFOLIO,
                Permission.VIEW_PRIVATE_CONSUMER
            ],
            Role.FINANCIAL_PLANNER: [
                Permission.VIEW_ACCOUNT_BALANCE,
                Permission.VIEW_INVESTMENT_PORTFOLIO,
                Permission.MODIFY_INVESTMENT_PORTFOLIO,
                Permission.VIEW_MONEY_MARKET,
                Permission.VIEW_PRIVATE_CONSUMER
            ],
            Role.TELLER: [
                Permission.VIEW_ACCOUNT_BALANCE,
                Permission.VIEW_INVESTMENT_PORTFOLIO
            ]
        }

    def get_permissions(self, role: Role) -> list:
        """Get all permissions for a given role"""
        return self.role_permissions.get(role, [])

    def has_permission(self, role: Role, permission: Permission) -> bool:
        """Check if a role has a specific permission"""
        return permission in self.role_permissions.get(role, [])

    def check_time_restriction(self, role: Role) -> tuple:
        """Check if user can access system based on time restrictions"""
        if role == Role.TELLER:
            current_hour = datetime.now().hour
            # Business hours: 9:00 AM to 5:00 PM (09:00 to 17:00)
            if not (9 <= current_hour < 17):
                return False, "Tellers can only access the system during business hours (9:00 AM - 5:00 PM)"
        return True, "Access granted"

    def authorize_operation(self, role: Role, permission: Permission) -> tuple:
        """
        Authorize an operation for a role
        Returns: (bool, str) - (authorized, message)
        """
        # Check time restrictions first
        time_check, time_msg = self.check_time_restriction(role)
        if not time_check:
            return False, time_msg

        # Check permission
        if self.has_permission(role, permission):
            return True, "Operation authorized"
        else:
            return False, f"Access denied: {role.value} does not have permission to {permission.value}"


# Test cases for Problem 1c
def test_access_control():
    """Test the access control mechanism"""
    print("Testing Access Control Mechanism\n")

    acm = AccessControlManager()

    # Test cases with expected results
    test_cases = [
        # (role, permission_to_check, expected_result, description)
        (Role.CLIENT, Permission.VIEW_ACCOUNT_BALANCE, True, "Client can view account balance"),
        (Role.CLIENT, Permission.VIEW_INVESTMENT_PORTFOLIO, True, "Client can view portfolio"),
        (Role.CLIENT, Permission.MODIFY_INVESTMENT_PORTFOLIO, False, "Client cannot modify portfolio"),
        (Role.CLIENT, Permission.VIEW_FA_CONTACT, True, "Client can view FA contact"),
        (Role.CLIENT, Permission.VIEW_FP_CONTACT, False, "Client cannot view FP contact"),

        (Role.PREMIUM_CLIENT, Permission.MODIFY_INVESTMENT_PORTFOLIO, True, "Premium Client can modify portfolio"),
        (Role.PREMIUM_CLIENT, Permission.VIEW_FP_CONTACT, True, "Premium Client can view FP contact"),

        (Role.FINANCIAL_ADVISOR, Permission.VIEW_PRIVATE_CONSUMER, True, "FA can view private consumer"),
        (Role.FINANCIAL_ADVISOR, Permission.VIEW_MONEY_MARKET, False, "FA cannot view money market"),
        (Role.FINANCIAL_ADVISOR, Permission.MODIFY_INVESTMENT_PORTFOLIO, True, "FA can modify portfolio"),

        (Role.FINANCIAL_PLANNER, Permission.VIEW_MONEY_MARKET, True, "FP can view money market"),
        (Role.FINANCIAL_PLANNER, Permission.VIEW_PRIVATE_CONSUMER, True, "FP can view private consumer"),

        (Role.TELLER, Permission.VIEW_ACCOUNT_BALANCE, True, "Teller can view balance"),
        (Role.TELLER, Permission.MODIFY_INVESTMENT_PORTFOLIO, False, "Teller cannot modify portfolio"),
    ]

    print("Test Results:\n")
    passed = 0
    failed = 0

    for role, permission, expected, description in test_cases:
        has_perm = acm.has_permission(role, permission)
        test_passed = (has_perm == expected)

        status = "PASS" if test_passed else "FAIL"

        if test_passed:
            passed += 1
        else:
            failed += 1

        print(f"{status} | {description}")
        print(f"      Role: {role.value}, Permission: {permission.value}")
        print(f"      Expected: {expected}, Got: {has_perm}")
        print()

    # Test Teller time restrictions
    print("Time Restriction Tests:\n")
    time_check, msg = acm.check_time_restriction(Role.TELLER)
    current_time = __import__('datetime').datetime.now().hour

    if 9 <= current_time < 17:
        expected_time_result = True
        time_desc = "within business hours"
    else:
        expected_time_result = False
        time_desc = "outside business hours"

    time_passed = (time_check == expected_time_result)
    status = "PASS" if time_passed else "FAIL"

    if time_passed:
        passed += 1
    else:
        failed += 1

    print(f"{status} | Teller time restriction (currently {time_desc})")
    print(f"      Current hour: {current_time}")
    print(f"      Expected: {expected_time_result}, Got: {time_check}")
    print(f"      Message: {msg}")
    print()

    # Test complete permission sets
    print("Complete Permission Sets:\n")
    expected_counts = {
        Role.CLIENT: 3,
        Role.PREMIUM_CLIENT: 5,
        Role.FINANCIAL_ADVISOR: 4,
        Role.FINANCIAL_PLANNER: 5,
        Role.TELLER: 2
    }

    for role, expected_count in expected_counts.items():
        permissions = acm.get_permissions(role)
        actual_count = len(permissions)
        count_passed = (actual_count == expected_count)

        status = "PASS" if count_passed else "FAIL"

        if count_passed:
            passed += 1
        else:
            failed += 1

        print(f"{status} | {role.value} permission count")
        print(f"Expected: {expected_count}, Got: {actual_count}")
        print(f"Permissions: {[p.value for p in permissions]}")
        print()

    print(f"Summary: {passed} passed, {failed} failed out of {passed + failed} tests\n")


if __name__ == "__main__":
    test_access_control()
