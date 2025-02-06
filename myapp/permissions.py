from rest_framework.permissions import BasePermission

class IsAdminUser(BasePermission):
    """
    Custom permission to allow only admins to access certain endpoints.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and hasattr(request.user, 'userprofile') and request.user.userprofile.is_admin

class IsRegularUser(BasePermission):
    """
    Custom permission to allow only regular users to access certain endpoints.
    """
    def has_permission(self, request, view):
        return request.user.is_authenticated and hasattr(request.user, 'userprofile') and not request.user.userprofile.is_admin
