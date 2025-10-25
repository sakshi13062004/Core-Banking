"""
Django REST Framework Serializers for Banking API

This module contains all serializers for the banking application with
proper validation, security, and data transformation.
"""

from rest_framework import serializers
from rest_framework_simplejwt.serializers import TokenObtainPairSerializer
from django.contrib.auth.password_validation import validate_password
from django.contrib.auth import authenticate
from django.core.validators import RegexValidator
from decimal import Decimal
from django.utils import timezone
from .models import (
    User, UserRole, Account, Transaction, TransactionHistory,
    FraudAlert, AuditLog
)
import logging

logger = logging.getLogger(__name__)


class UserRoleSerializer(serializers.ModelSerializer):
    """Serializer for UserRole model"""
    
    class Meta:
        model = UserRole
        fields = ['id', 'name', 'description', 'created_at']
        read_only_fields = ['created_at']


class UserRegistrationSerializer(serializers.ModelSerializer):
    """Serializer for user registration with comprehensive validation"""
    
    password = serializers.CharField(
        write_only=True,
        validators=[validate_password],
        style={'input_type': 'password'}
    )
    confirm_password = serializers.CharField(
        write_only=True,
        style={'input_type': 'password'}
    )
    phone_number = serializers.CharField(
        validators=[RegexValidator(
            regex=r'^\+?1?\d{9,15}$',
            message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
        )]
    )
    
    class Meta:
        model = User
        fields = [
            'username', 'email', 'password', 'confirm_password',
            'first_name', 'last_name', 'phone_number', 'date_of_birth',
            'ssn', 'address'
        ]
        extra_kwargs = {
            'email': {'required': True},
            'first_name': {'required': True},
            'last_name': {'required': True},
            'ssn': {'write_only': True},
            'address': {'write_only': True},
        }
    
    def validate(self, attrs):
        """Custom validation for user registration"""
        if attrs['password'] != attrs['confirm_password']:
            raise serializers.ValidationError({
                'confirm_password': "Password fields didn't match."
            })
        
        # Remove confirm_password from validated data
        attrs.pop('confirm_password')
        
        # Check if user is at least 18 years old
        if attrs.get('date_of_birth'):
            today = timezone.now().date()
            age = today.year - attrs['date_of_birth'].year
            if today.month < attrs['date_of_birth'].month or \
               (today.month == attrs['date_of_birth'].month and today.day < attrs['date_of_birth'].day):
                age -= 1
            
            if age < 18:
                raise serializers.ValidationError({
                    'date_of_birth': 'User must be at least 18 years old.'
                })
        
        return attrs
    
    def create(self, validated_data):
        """Create user with encrypted sensitive data"""
        user = User.objects.create_user(
            username=validated_data['username'],
            email=validated_data['email'],
            password=validated_data['password'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name'],
            phone_number=validated_data['phone_number'],
            date_of_birth=validated_data.get('date_of_birth'),
            ssn=validated_data.get('ssn'),
            address=validated_data.get('address'),
        )
        
        # Assign default customer role
        customer_role, created = UserRole.objects.get_or_create(
            name='CUSTOMER',
            defaults={'description': 'Bank Customer'}
        )
        user.roles.add(customer_role)
        
        return user


class UserSerializer(serializers.ModelSerializer):
    """Serializer for User model with security considerations"""
    
    roles = UserRoleSerializer(many=True, read_only=True)
    
    class Meta:
        model = User
        fields = [
            'id', 'username', 'email', 'first_name', 'last_name',
            'phone_number', 'date_of_birth', 'customer_id',
            'kyc_status', 'risk_profile', 'is_account_verified',
            'two_factor_enabled', 'roles', 'date_joined', 'last_login'
        ]
        read_only_fields = [
            'customer_id', 'kyc_status', 'risk_profile', 
            'is_account_verified', 'date_joined', 'last_login'
        ]
    
    def to_representation(self, instance):
        """Custom representation to hide sensitive data"""
        data = super().to_representation(instance)
        request = self.context.get('request')
        
        # Only show full data to the user themselves or staff
        if request and (request.user == instance or request.user.is_staff):
            return data
        
        # Hide sensitive information for other users
        sensitive_fields = ['email', 'phone_number', 'date_of_birth']
        for field in sensitive_fields:
            if field in data:
                data[field] = "***HIDDEN***"
        
        return data


class CustomTokenObtainPairSerializer(TokenObtainPairSerializer):
    """Custom JWT token serializer with enhanced security"""
    
    def validate(self, attrs):
        """Enhanced validation with security checks"""
        username = attrs.get('username')
        password = attrs.get('password')
        
        try:
            user = User.objects.get(username=username)
            
            # Check if account is locked
            if user.is_account_locked():
                raise serializers.ValidationError({
                    'non_field_errors': [
                        f'Account is locked until {user.account_locked_until}. '
                        'Please try again later or contact support.'
                    ]
                })
            
            # Authenticate user
            user = authenticate(username=username, password=password)
            if not user:
                # Increment failed login attempts
                try:
                    user_obj = User.objects.get(username=username)
                    user_obj.failed_login_attempts += 1
                    if user_obj.failed_login_attempts >= 5:
                        user_obj.lock_account(duration_minutes=30)
                    user_obj.save()
                except User.DoesNotExist:
                    pass
                
                raise serializers.ValidationError({
                    'non_field_errors': ['Invalid credentials.']
                })
            
            # Reset failed login attempts on successful login
            if user.failed_login_attempts > 0:
                user.failed_login_attempts = 0
                user.save()
            
            # Get IP address from request
            request = self.context.get('request')
            if request:
                user.last_login_ip = self.get_client_ip(request)
                user.save()
            
            attrs['user'] = user
            
        except User.DoesNotExist:
            raise serializers.ValidationError({
                'non_field_errors': ['Invalid credentials.']
            })
        
        return super().validate(attrs)
    
    def get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip
    
    @classmethod
    def get_token(cls, user):
        """Add custom claims to JWT token"""
        token = super().get_token(user)
        
        # Add custom claims
        token['customer_id'] = user.customer_id
        token['kyc_status'] = user.kyc_status
        token['risk_profile'] = user.risk_profile
        token['roles'] = list(user.roles.values_list('name', flat=True))
        
        return token


class AccountSerializer(serializers.ModelSerializer):
    """Serializer for Account model with proper validation"""
    
    account_holder = UserSerializer(read_only=True)
    
    class Meta:
        model = Account
        fields = [
            'id', 'account_number', 'account_type', 'account_holder',
            'balance', 'available_balance', 'status', 'interest_rate',
            'minimum_balance', 'daily_transaction_limit', 
            'single_transaction_limit', 'created_at', 'updated_at',
            'last_transaction_date', 'suspicious_activity_flag', 'risk_score'
        ]
        read_only_fields = [
            'account_number', 'balance', 'available_balance', 
            'created_at', 'updated_at', 'last_transaction_date'
        ]
    
    def validate_account_type(self, value):
        """Validate account type"""
        valid_types = ['SAVINGS', 'CURRENT', 'FIXED_DEPOSIT']
        if value not in valid_types:
            raise serializers.ValidationError(f"Account type must be one of: {valid_types}")
        return value
    
    def create(self, validated_data):
        """Create account with proper user assignment"""
        request = self.context.get('request')
        if request and request.user:
            validated_data['account_holder'] = request.user
        return super().create(validated_data)


class TransactionSerializer(serializers.ModelSerializer):
    """Serializer for Transaction model with comprehensive validation"""
    
    from_account_number = serializers.CharField(write_only=True, required=False)
    to_account_number = serializers.CharField(write_only=True, required=False)
    from_account = AccountSerializer(read_only=True)
    to_account = AccountSerializer(read_only=True)
    initiated_by = UserSerializer(read_only=True)
    
    class Meta:
        model = Transaction
        fields = [
            'id', 'transaction_id', 'transaction_type', 'from_account',
            'to_account', 'from_account_number', 'to_account_number',
            'amount', 'fee', 'description', 'reference_number',
            'status', 'fraud_score', 'is_suspicious', 'initiated_by',
            'transaction_date', 'processed_date'
        ]
        read_only_fields = [
            'transaction_id', 'fee', 'fraud_score', 'is_suspicious',
            'status', 'transaction_date', 'processed_date'
        ]
    
    def validate_amount(self, value):
        """Validate transaction amount"""
        if value <= 0:
            raise serializers.ValidationError("Amount must be positive.")
        
        if value > Decimal('1000000'):
            raise serializers.ValidationError("Amount exceeds maximum limit.")
        
        return value
    
    def validate(self, attrs):
        """Comprehensive transaction validation"""
        transaction_type = attrs.get('transaction_type')
        from_account_number = attrs.get('from_account_number')
        to_account_number = attrs.get('to_account_number')
        amount = attrs.get('amount')
        
        # Validate based on transaction type
        if transaction_type == 'DEPOSIT':
            if not to_account_number:
                raise serializers.ValidationError({
                    'to_account_number': 'Destination account required for deposits.'
                })
            
            try:
                to_account = Account.objects.get(account_number=to_account_number)
                attrs['to_account'] = to_account
            except Account.DoesNotExist:
                raise serializers.ValidationError({
                    'to_account_number': 'Destination account not found.'
                })
        
        elif transaction_type == 'WITHDRAWAL':
            if not from_account_number:
                raise serializers.ValidationError({
                    'from_account_number': 'Source account required for withdrawals.'
                })
            
            try:
                from_account = Account.objects.get(account_number=from_account_number)
                attrs['from_account'] = from_account
                
                # Validate withdrawal permissions
                request = self.context.get('request')
                if request and request.user != from_account.account_holder:
                    raise serializers.ValidationError({
                        'from_account_number': 'You can only withdraw from your own accounts.'
                    })
                
                # Check if withdrawal is possible
                if not from_account.can_withdraw(amount):
                    raise serializers.ValidationError({
                        'amount': 'Insufficient funds or transaction limit exceeded.'
                    })
                
            except Account.DoesNotExist:
                raise serializers.ValidationError({
                    'from_account_number': 'Source account not found.'
                })
        
        elif transaction_type == 'TRANSFER':
            if not from_account_number or not to_account_number:
                raise serializers.ValidationError({
                    'non_field_errors': ['Both source and destination accounts required for transfers.']
                })
            
            if from_account_number == to_account_number:
                raise serializers.ValidationError({
                    'non_field_errors': ['Source and destination accounts cannot be the same.']
                })
            
            try:
                from_account = Account.objects.get(account_number=from_account_number)
                to_account = Account.objects.get(account_number=to_account_number)
                attrs['from_account'] = from_account
                attrs['to_account'] = to_account
                
                # Validate transfer permissions
                request = self.context.get('request')
                if request and request.user != from_account.account_holder:
                    raise serializers.ValidationError({
                        'from_account_number': 'You can only transfer from your own accounts.'
                    })
                
                # Check if transfer is possible (including fee)
                fee_percentage = 0.01  # 1% fee
                total_amount = amount + (amount * Decimal(str(fee_percentage)))
                
                if not from_account.can_withdraw(total_amount):
                    raise serializers.ValidationError({
                        'amount': 'Insufficient funds or transaction limit exceeded (including fee).'
                    })
                
            except Account.DoesNotExist:
                raise serializers.ValidationError({
                    'non_field_errors': ['One or both accounts not found.']
                })
        
        return attrs
    
    def create(self, validated_data):
        """Create transaction with proper user assignment"""
        request = self.context.get('request')
        if request and request.user:
            validated_data['initiated_by'] = request.user
            
            # Set IP address and user agent for fraud detection
            validated_data['ip_address'] = self.get_client_ip(request)
            validated_data['user_agent'] = request.META.get('HTTP_USER_AGENT', '')
        
        # Remove account number fields from validated data
        validated_data.pop('from_account_number', None)
        validated_data.pop('to_account_number', None)
        
        return super().create(validated_data)
    
    def get_client_ip(self, request):
        """Get client IP address from request"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class TransactionHistorySerializer(serializers.ModelSerializer):
    """Serializer for TransactionHistory model"""
    
    transaction = TransactionSerializer(read_only=True)
    changed_by = UserSerializer(read_only=True)
    
    class Meta:
        model = TransactionHistory
        fields = [
            'id', 'transaction', 'field_name', 'old_value', 
            'new_value', 'changed_by', 'changed_at', 'reason'
        ]
        read_only_fields = ['changed_at']


class FraudAlertSerializer(serializers.ModelSerializer):
    """Serializer for FraudAlert model"""
    
    user = UserSerializer(read_only=True)
    account = AccountSerializer(read_only=True)
    transaction = TransactionSerializer(read_only=True)
    
    class Meta:
        model = FraudAlert
        fields = [
            'id', 'alert_id', 'alert_type', 'severity', 'status',
            'user', 'account', 'transaction', 'title', 'description',
            'risk_score', 'assigned_to', 'resolved_by', 'resolution_notes',
            'created_at', 'updated_at', 'resolved_at'
        ]
        read_only_fields = [
            'alert_id', 'created_at', 'updated_at', 'resolved_at'
        ]


class AuditLogSerializer(serializers.ModelSerializer):
    """Serializer for AuditLog model"""
    
    user = UserSerializer(read_only=True)
    
    class Meta:
        model = AuditLog
        fields = [
            'id', 'log_id', 'action_type', 'user', 'target_model',
            'target_id', 'description', 'changes', 'ip_address',
            'user_agent', 'timestamp'
        ]
        read_only_fields = ['log_id', 'timestamp']


class BalanceInquirySerializer(serializers.Serializer):
    """Serializer for balance inquiry requests"""
    
    account_number = serializers.CharField(max_length=20)
    
    def validate_account_number(self, value):
        """Validate account exists and user has access"""
        try:
            account = Account.objects.get(account_number=value)
            request = self.context.get('request')
            
            if request and request.user != account.account_holder:
                raise serializers.ValidationError("You can only check your own account balance.")
            
            return value
        except Account.DoesNotExist:
            raise serializers.ValidationError("Account not found.")


class AccountStatementSerializer(serializers.Serializer):
    """Serializer for account statement requests"""
    
    account_number = serializers.CharField(max_length=20)
    start_date = serializers.DateField(required=False)
    end_date = serializers.DateField(required=False)
    transaction_type = serializers.ChoiceField(
        choices=Transaction.TRANSACTION_TYPES,
        required=False
    )
    
    def validate(self, attrs):
        """Validate statement request parameters"""
        start_date = attrs.get('start_date')
        end_date = attrs.get('end_date')
        
        if start_date and end_date:
            if start_date > end_date:
                raise serializers.ValidationError({
                    'start_date': 'Start date cannot be after end date.'
                })
            
            # Limit statement period to 1 year
            if (end_date - start_date).days > 365:
                raise serializers.ValidationError({
                    'non_field_errors': ['Statement period cannot exceed 1 year.']
                })
        
        # Validate account access
        account_number = attrs.get('account_number')
        try:
            account = Account.objects.get(account_number=account_number)
            request = self.context.get('request')
            
            if request and request.user != account.account_holder:
                raise serializers.ValidationError({
                    'account_number': 'You can only access your own account statements.'
                })
            
        except Account.DoesNotExist:
            raise serializers.ValidationError({
                'account_number': 'Account not found.'
            })
        
        return attrs
