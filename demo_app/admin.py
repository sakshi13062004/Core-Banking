"""
Django Admin Configuration for Banking Models

This module provides comprehensive admin interfaces for all banking models
with proper security, filtering, and search capabilities.
"""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.utils.html import format_html
from django.urls import reverse
from django.utils.safestring import mark_safe
from .models import (
    User, UserRole, Account, Transaction, TransactionHistory,
    FraudAlert, AuditLog
)


class UserRoleAdmin(admin.ModelAdmin):
    """Admin interface for User Roles"""
    list_display = ('name', 'description', 'created_at')
    list_filter = ('name', 'created_at')
    search_fields = ('name', 'description')
    filter_horizontal = ('permissions',)


class CustomUserAdmin(BaseUserAdmin):
    """Enhanced User admin with banking-specific fields"""
    list_display = (
        'username', 'email', 'customer_id', 'phone_number', 
        'kyc_status', 'risk_profile', 'is_account_verified', 'date_joined'
    )
    list_filter = (
        'is_staff', 'is_superuser', 'is_active', 'kyc_status', 
        'risk_profile', 'is_account_verified', 'two_factor_enabled'
    )
    search_fields = ('username', 'first_name', 'last_name', 'email', 'customer_id')
    readonly_fields = ('customer_id', 'last_login', 'date_joined', 'created_at', 'updated_at')
    
    fieldsets = BaseUserAdmin.fieldsets + (
        ('Banking Information', {
            'fields': (
                'customer_id', 'phone_number', 'date_of_birth', 
                'kyc_status', 'risk_profile'
            )
        }),
        ('Security', {
            'fields': (
                'is_account_verified', 'two_factor_enabled', 
                'failed_login_attempts', 'account_locked_until'
            )
        }),
        ('Sensitive Data (Encrypted)', {
            'fields': ('ssn', 'address'),
            'classes': ('collapse',)
        }),
        ('RBAC', {
            'fields': ('roles',),
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'last_login_ip'),
            'classes': ('collapse',)
        }),
    )
    
    filter_horizontal = ('groups', 'user_permissions', 'roles')


class AccountAdmin(admin.ModelAdmin):
    """Admin interface for Bank Accounts"""
    list_display = (
        'account_number', 'account_holder', 'account_type', 
        'balance', 'status', 'risk_score', 'created_at'
    )
    list_filter = (
        'account_type', 'status', 'suspicious_activity_flag', 
        'created_at', 'updated_at'
    )
    search_fields = (
        'account_number', 'account_holder__username', 
        'account_holder__customer_id', 'account_holder__email'
    )
    readonly_fields = (
        'account_number', 'available_balance', 'created_at', 
        'updated_at', 'last_transaction_date'
    )
    
    fieldsets = (
        ('Account Information', {
            'fields': (
                'account_number', 'account_holder', 'account_type', 'status'
            )
        }),
        ('Balance & Limits', {
            'fields': (
                'balance', 'available_balance', 'minimum_balance',
                'daily_transaction_limit', 'single_transaction_limit'
            )
        }),
        ('Account Settings', {
            'fields': ('interest_rate',)
        }),
        ('Security & Risk', {
            'fields': ('suspicious_activity_flag', 'risk_score')
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'last_transaction_date'),
            'classes': ('collapse',)
        }),
    )
    
    def get_queryset(self, request):
        qs = super().get_queryset(request)
        return qs.select_related('account_holder')


class TransactionAdmin(admin.ModelAdmin):
    """Admin interface for Transactions"""
    list_display = (
        'transaction_id', 'transaction_type', 'amount', 'fee',
        'status', 'fraud_score_display', 'transaction_date'
    )
    list_filter = (
        'transaction_type', 'status', 'is_suspicious', 
        'transaction_date', 'processed_date'
    )
    search_fields = (
        'transaction_id', 'reference_number', 'description',
        'from_account__account_number', 'to_account__account_number'
    )
    readonly_fields = (
        'transaction_id', 'fraud_score', 'processed_date',
        'transaction_date', 'updated_at'
    )
    
    fieldsets = (
        ('Transaction Information', {
            'fields': (
                'transaction_id', 'transaction_type', 'from_account', 
                'to_account', 'amount', 'fee'
            )
        }),
        ('Transaction Details', {
            'fields': ('description', 'reference_number', 'status')
        }),
        ('Security & Approval', {
            'fields': (
                'initiated_by', 'approved_by', 'fraud_score', 
                'is_suspicious', 'fraud_reason'
            )
        }),
        ('Network Information', {
            'fields': ('ip_address', 'user_agent', 'device_fingerprint'),
            'classes': ('collapse',)
        }),
        ('Timestamps', {
            'fields': ('transaction_date', 'processed_date', 'updated_at'),
            'classes': ('collapse',)
        }),
    )
    
    def fraud_score_display(self, obj):
        """Display fraud score with color coding"""
        if obj.fraud_score >= 80:
            color = 'red'
        elif obj.fraud_score >= 50:
            color = 'orange'
        elif obj.fraud_score >= 25:
            color = 'yellow'
        else:
            color = 'green'
        
        return format_html(
            '<span style="color: {}; font-weight: bold;">{}</span>',
            color, obj.fraud_score
        )
    fraud_score_display.short_description = 'Fraud Score'
    
    actions = ['process_selected_transactions']
    
    def process_selected_transactions(self, request, queryset):
        """Admin action to process selected transactions"""
        processed_count = 0
        for transaction in queryset.filter(status='PENDING'):
            success, message = transaction.process_transaction()
            if success:
                processed_count += 1
        
        self.message_user(
            request, 
            f"Successfully processed {processed_count} transactions."
        )
    
    process_selected_transactions.short_description = "Process selected transactions"


class TransactionHistoryAdmin(admin.ModelAdmin):
    """Admin interface for Transaction History"""
    list_display = (
        'transaction', 'field_name', 'changed_by', 'changed_at'
    )
    list_filter = ('field_name', 'changed_at')
    search_fields = (
        'transaction__transaction_id', 'field_name', 'reason'
    )
    readonly_fields = ('changed_at',)


class FraudAlertAdmin(admin.ModelAdmin):
    """Admin interface for Fraud Alerts"""
    list_display = (
        'alert_id', 'alert_type', 'severity', 'status', 
        'user', 'risk_score', 'created_at'
    )
    list_filter = (
        'alert_type', 'severity', 'status', 'created_at'
    )
    search_fields = (
        'alert_id', 'title', 'description', 'user__username'
    )
    readonly_fields = (
        'alert_id', 'created_at', 'updated_at', 'resolved_at'
    )
    
    fieldsets = (
        ('Alert Information', {
            'fields': (
                'alert_id', 'alert_type', 'severity', 'status', 'title'
            )
        }),
        ('Related Objects', {
            'fields': ('user', 'account', 'transaction')
        }),
        ('Alert Details', {
            'fields': ('description', 'risk_score')
        }),
        ('Resolution', {
            'fields': (
                'assigned_to', 'resolved_by', 'resolution_notes'
            )
        }),
        ('Timestamps', {
            'fields': ('created_at', 'updated_at', 'resolved_at'),
            'classes': ('collapse',)
        }),
    )


class AuditLogAdmin(admin.ModelAdmin):
    """Admin interface for Audit Logs"""
    list_display = (
        'log_id', 'user', 'action_type', 'target_model', 
        'ip_address', 'timestamp'
    )
    list_filter = ('action_type', 'target_model', 'timestamp')
    search_fields = (
        'log_id', 'user__username', 'target_id', 'description'
    )
    readonly_fields = ('log_id', 'timestamp')
    
    def has_delete_permission(self, request, obj=None):
        """Prevent deletion of audit logs"""
        return False
    
    def has_change_permission(self, request, obj=None):
        """Prevent modification of audit logs"""
        return False


# Register models with admin
admin.site.register(User, CustomUserAdmin)
admin.site.register(UserRole, UserRoleAdmin)
admin.site.register(Account, AccountAdmin)
admin.site.register(Transaction, TransactionAdmin)
admin.site.register(TransactionHistory, TransactionHistoryAdmin)
admin.site.register(FraudAlert, FraudAlertAdmin)
admin.site.register(AuditLog, AuditLogAdmin)

# Customize admin site
admin.site.site_header = "Core Banking Administration"
admin.site.site_title = "Banking Admin"
admin.site.index_title = "Welcome to Core Banking Administration"
