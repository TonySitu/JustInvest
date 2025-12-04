
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
    acm = AccessControlManager()

    print("=== Testing Access Control Mechanism ===\n")

    # Test Case 1: Client permissions
    print("Test Case 1: Client Access")
    role = Role.CLIENT
    print(f"Role: {role.value}")
    print(f"  - View account balance: {acm.has_permission(role, Permission.VIEW_ACCOUNT_BALANCE)}")
    print(f"  - View portfolio: {acm.has_permission(role, Permission.VIEW_INVESTMENT_PORTFOLIO)}")
    print(f"  - Modify portfolio: {acm.has_permission(role, Permission.MODIFY_INVESTMENT_PORTFOLIO)}")
    print(f"  - View FA contact: {acm.has_permission(role, Permission.VIEW_FA_CONTACT)}")
    print()

    # Test Case 2: Premium Client permissions
    print("Test Case 2: Premium Client Access")
    role = Role.PREMIUM_CLIENT
    print(f"Role: {role.value}")
    print(f"  - Modify portfolio: {acm.has_permission(role, Permission.MODIFY_INVESTMENT_PORTFOLIO)}")
    print(f"  - View FP contact: {acm.has_permission(role, Permission.VIEW_FP_CONTACT)}")
    print()

    # Test Case 3: Financial Advisor permissions
    print("Test Case 3: Financial Advisor Access")
    role = Role.FINANCIAL_ADVISOR
    print(f"Role: {role.value}")
    print(f"  - View private consumer: {acm.has_permission(role, Permission.VIEW_PRIVATE_CONSUMER)}")
    print(f"  - View money market: {acm.has_permission(role, Permission.VIEW_MONEY_MARKET)}")
    print(f"  - Modify portfolio: {acm.has_permission(role, Permission.MODIFY_INVESTMENT_PORTFOLIO)}")
    print()

    # Test Case 4: Financial Planner permissions
    print("Test Case 4: Financial Planner Access")
    role = Role.FINANCIAL_PLANNER
    print(f"Role: {role.value}")
    print(f"  - View money market: {acm.has_permission(role, Permission.VIEW_MONEY_MARKET)}")
    print(f"  - View private consumer: {acm.has_permission(role, Permission.VIEW_PRIVATE_CONSUMER)}")
    print()

    # Test Case 5: Teller time restrictions
    print("Test Case 5: Teller Time Restrictions")
    role = Role.TELLER
    print(f"Role: {role.value}")
    time_check, msg = acm.check_time_restriction(role)
    print(f"  - Current time access: {time_check}")
    print(f"  - Message: {msg}")
    print()

    # Test Case 6: All permissions for each role
    print("Test Case 6: Complete Permission Sets")
    for role in Role:
        permissions = acm.get_permissions(role)
        print(f"{role.value}:")
        for perm in permissions:
            print(f"  - {perm.value}")
        print()


if __name__ == "__main__":
    test_access_control()
