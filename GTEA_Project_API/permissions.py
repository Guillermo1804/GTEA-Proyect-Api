from rest_framework import permissions


class IsAdminOrReadOnly(permissions.BasePermission):
    """Allow safe methods for everyone; unsafe methods only for admins.
    Admin = is_staff or is_superuser or group 'administrador'."""
    def has_permission(self, request, view):
        if request.method in permissions.SAFE_METHODS:
            return True
        user = request.user
        if not user or not user.is_authenticated:
            return False
        return user.groups.filter(name__iexact='administrador').exists()


class IsAdminOrAuthenticated(permissions.BasePermission):
    """Allow access to authenticated users; admins naturally are allowed too."""
    def has_permission(self, request, view):
        return bool(request.user and request.user.is_authenticated)
