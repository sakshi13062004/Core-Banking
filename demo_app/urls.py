"""
URL Configuration for Banking API

This module defines all URL patterns for the banking application endpoints
including authentication, account management, transactions, and more.
"""

from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenRefreshView
from . import views

# Create a router for ViewSets
router = DefaultRouter()
router.register(r'accounts', views.AccountViewSet, basename='account')
router.register(r'transactions', views.TransactionViewSet, basename='transaction')
router.register(r'fraud-alerts', views.FraudAlertViewSet, basename='fraudalert')
router.register(r'audit-logs', views.AuditLogViewSet, basename='auditlog')

app_name = 'banking'

urlpatterns = [
    # Authentication endpoints
    path('auth/register/', views.UserRegistrationView.as_view(), name='register'),
    path('auth/login/', views.CustomTokenObtainPairView.as_view(), name='login'),
    path('auth/logout/', views.logout_view, name='logout'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    
    # User profile endpoints
    path('profile/', views.UserProfileView.as_view(), name='profile'),
    
    # Quick access endpoints
    path('balance/', views.balance_inquiry, name='balance_inquiry'),
    path('dashboard/', views.dashboard_stats, name='dashboard'),
    
    # Include router URLs
    path('', include(router.urls)),
]
