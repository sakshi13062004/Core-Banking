"""
Custom permissions for Banking API

This module contains essential permission classes for the banking application.
Simplified version to avoid import issues during initial setup.
"""

from rest_framework import permissions


class IsOwnerOrReadOnly(permissions.BasePermission):
    """
    Custom permission to only allow owners of an object to edit it.
    Staff users can access all objects.
    """
    
    def has_object_permission(self, request, view, obj):
        # Read permissions are allowed for any request
        if request.method in permissions.SAFE_METHODS:
            return True
        
        # Staff users have full access
        if request.user.is_staff:
            return True
        
        # Write permissions are only allowed to the owner of the object
        if hasattr(obj, 'account_holder'):
            return obj.account_holder == request.user
        
        if hasattr(obj, 'user'):
            return obj.user == request.user
        
        if hasattr(obj, 'username'):
            return obj == request.user
        
        return False


class IsBankStaff(permissions.BasePermission):
    """
    Custom permission to only allow bank staff access.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        # Superusers and staff always have access
        if request.user.is_superuser or request.user.is_staff:
            return True
        
        # Check if user has any staff role
        try:
            staff_roles = ['TELLER', 'MANAGER', 'ADMIN', 'AUDITOR']
            return request.user.roles.filter(name__in=staff_roles).exists()
        except:
            return False


class IsCustomer(permissions.BasePermission):
    """
    Custom permission to only allow customers access.
    """
    
    def has_permission(self, request, view):
        if not request.user or not request.user.is_authenticated:
            return False
        
        try:
            return request.user.roles.filter(name='CUSTOMER').exists()
        except:
            return True  # Default to customer if no roles system