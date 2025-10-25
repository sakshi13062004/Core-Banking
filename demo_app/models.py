"""
Banking Models with Enhanced Security Features

This module contains all the database models for the banking application including:
- User profiles with encrypted sensitive data
- Bank accounts with different types
- Secure transactions with fraud detection
- Transaction history and audit trails
- Role-based access control (RBAC)
"""

import uuid
import hashlib
from decimal import Decimal
from django.db import models
from django.contrib.auth.models import AbstractUser, Group, Permission
from django.core.validators import MinValueValidator, MaxValueValidator, RegexValidator
from django.utils import timezone
from cryptography.fernet import Fernet
from django.conf import settings
import logging

logger = logging.getLogger(__name__)


class EncryptedField(models.TextField):
    """Custom field for encrypting sensitive data"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._cipher_suite = None
    
    @property
    def cipher_suite(self):
        """Lazy initialization of cipher suite"""
        if self._cipher_suite is None:
            try:
                # Get encryption key or generate one
                encryption_key = settings.BANKING_SETTINGS.get('ENCRYPTION_KEY')
                if not encryption_key or encryption_key == 'your-32-byte-encryption-key-here!!':
                    # Generate a proper Fernet key
                    encryption_key = Fernet.generate_key()
                    logger.warning("Using generated encryption key. For production, set a proper ENCRYPTION_KEY in settings.")
                elif isinstance(encryption_key, str):
                    # If it's a string, try to encode it properly
                    if len(encryption_key) < 32:
                        # Pad the key to 32 bytes
                        encryption_key = encryption_key.ljust(32)[:32]
                    # Generate a proper Fernet key from the string
                    from base64 import urlsafe_b64encode
                    import os
                    encryption_key = urlsafe_b64encode(encryption_key.encode()[:32])
                
                self._cipher_suite = Fernet(encryption_key)
            except Exception as e:
                logger.error(f"Failed to initialize encryption: {e}")
                # Fallback: generate a new key
                self._cipher_suite = Fernet(Fernet.generate_key())
        
        return self._cipher_suite
    
    def from_db_value(self, value, expression, connection):
        if value is None:
            return value
        try:
            # Check if value is already decrypted (for backwards compatibility)
            if not value.startswith('gAAAAA'):  # Fernet tokens start with this
                return value
            decrypted_value = self.cipher_suite.decrypt(value.encode()).decode()
            return decrypted_value
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            return value  # Return original value if decryption fails
    
    def to_python(self, value):
        if isinstance(value, str) or value is None:
            return value
        return str(value)
    
    def get_prep_value(self, value):
        if value is None:
            return value
        try:
            # Don't encrypt empty strings
            if not str(value).strip():
                return value
            encrypted_value = self.cipher_suite.encrypt(str(value).encode()).decode()
            return encrypted_value
        except Exception as e:
            logger.error(f"Encryption failed: {e}")
            return value  # Return original value if encryption fails


class UserRole(models.Model):
    """User roles for RBAC system"""
    ROLE_CHOICES = [
        ('CUSTOMER', 'Customer'),
        ('TELLER', 'Bank Teller'),
        ('MANAGER', 'Bank Manager'),
        ('ADMIN', 'System Administrator'),
        ('AUDITOR', 'Auditor'),
    ]
    
    name = models.CharField(max_length=20, choices=ROLE_CHOICES, unique=True)
    description = models.TextField(blank=True)
    permissions = models.ManyToManyField(Permission, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def __str__(self):
        return self.get_name_display()
    
    class Meta:
        verbose_name = "User Role"
        verbose_name_plural = "User Roles"


class User(AbstractUser):
    """Extended User model with banking-specific fields"""
    
    # Personal Information
    phone_regex = RegexValidator(
        regex=r'^\+?1?\d{9,15}$',
        message="Phone number must be entered in the format: '+999999999'. Up to 15 digits allowed."
    )
    
    phone_number = models.CharField(validators=[phone_regex], max_length=17, unique=True)
    date_of_birth = models.DateField(null=True, blank=True)
    
    # Encrypted sensitive data
    ssn = EncryptedField(help_text="Social Security Number (encrypted)")
    address = EncryptedField(help_text="Home address (encrypted)")
    
    # Account settings
    is_account_verified = models.BooleanField(default=False)
    failed_login_attempts = models.IntegerField(default=0)
    account_locked_until = models.DateTimeField(null=True, blank=True)
    two_factor_enabled = models.BooleanField(default=False)
    
    # Banking specific
    customer_id = models.CharField(max_length=20, unique=True, editable=False)
    kyc_status = models.CharField(
        max_length=10,
        choices=[('PENDING', 'Pending'), ('APPROVED', 'Approved'), ('REJECTED', 'Rejected')],
        default='PENDING'
    )
    risk_profile = models.CharField(
        max_length=10,
        choices=[('LOW', 'Low Risk'), ('MEDIUM', 'Medium Risk'), ('HIGH', 'High Risk')],
        default='LOW'
    )
    
    # RBAC
    roles = models.ManyToManyField(UserRole, blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_login_ip = models.GenericIPAddressField(null=True, blank=True)
    
    def save(self, *args, **kwargs):
        if not self.customer_id:
            self.customer_id = f"CUST{str(uuid.uuid4().int)[:10]}"
        super().save(*args, **kwargs)
    
    def is_account_locked(self):
        """Check if account is currently locked"""
        if self.account_locked_until:
            return timezone.now() < self.account_locked_until
        return False
    
    def lock_account(self, duration_minutes=30):
        """Lock account for specified duration"""
        self.account_locked_until = timezone.now() + timezone.timedelta(minutes=duration_minutes)
        self.save()
    
    def unlock_account(self):
        """Unlock user account"""
        self.failed_login_attempts = 0
        self.account_locked_until = None
        self.save()
    
    def has_role(self, role_name):
        """Check if user has specific role"""
        return self.roles.filter(name=role_name).exists()
    
    def __str__(self):
        return f"{self.username} ({self.customer_id})"
    
    class Meta:
        verbose_name = "Bank User"
        verbose_name_plural = "Bank Users"


class Account(models.Model):
    """Bank Account model with different account types"""
    
    ACCOUNT_TYPES = [
        ('SAVINGS', 'Savings Account'),
        ('CURRENT', 'Current Account'),
        ('FIXED_DEPOSIT', 'Fixed Deposit'),
        ('LOAN', 'Loan Account'),
    ]
    
    STATUS_CHOICES = [
        ('ACTIVE', 'Active'),
        ('INACTIVE', 'Inactive'),
        ('SUSPENDED', 'Suspended'),
        ('CLOSED', 'Closed'),
    ]
    
    # Account identification
    account_number = models.CharField(max_length=20, unique=True, editable=False)
    account_type = models.CharField(max_length=15, choices=ACCOUNT_TYPES)
    account_holder = models.ForeignKey(User, on_delete=models.CASCADE, related_name='accounts')
    
    # Account details
    balance = models.DecimalField(
        max_digits=15, 
        decimal_places=2, 
        default=Decimal('0.00'),
        validators=[MinValueValidator(Decimal('0.00'))]
    )
    available_balance = models.DecimalField(
        max_digits=15, 
        decimal_places=2, 
        default=Decimal('0.00'),
        validators=[MinValueValidator(Decimal('0.00'))]
    )
    
    # Account settings
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default='ACTIVE')
    interest_rate = models.DecimalField(
        max_digits=5, 
        decimal_places=2, 
        default=Decimal('0.00'),
        validators=[MinValueValidator(Decimal('0.00')), MaxValueValidator(Decimal('100.00'))]
    )
    minimum_balance = models.DecimalField(
        max_digits=10, 
        decimal_places=2, 
        default=Decimal('0.00')
    )
    
    # Security and limits
    daily_transaction_limit = models.DecimalField(
        max_digits=10, 
        decimal_places=2, 
        default=Decimal('50000.00')
    )
    single_transaction_limit = models.DecimalField(
        max_digits=10, 
        decimal_places=2, 
        default=Decimal('10000.00')
    )
    
    # Metadata
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    last_transaction_date = models.DateTimeField(null=True, blank=True)
    
    # Fraud detection
    suspicious_activity_flag = models.BooleanField(default=False)
    risk_score = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    
    def save(self, *args, **kwargs):
        if not self.account_number:
            # Generate unique account number
            timestamp = str(int(timezone.now().timestamp()))
            account_hash = hashlib.md5(f"{self.account_holder.id}{timestamp}".encode()).hexdigest()[:6]
            self.account_number = f"{self.account_type[:2]}{account_hash.upper()}{timestamp[-4:]}"
        
        # Update available balance based on account status
        if self.status in ['SUSPENDED', 'CLOSED']:
            self.available_balance = Decimal('0.00')
        else:
            self.available_balance = max(self.balance - self.minimum_balance, Decimal('0.00'))
        
        super().save(*args, **kwargs)
    
    def can_withdraw(self, amount):
        """Check if withdrawal is possible"""
        return (
            self.status == 'ACTIVE' and
            self.available_balance >= amount and
            amount <= self.single_transaction_limit
        )
    
    def get_daily_transaction_total(self):
        """Get total transaction amount for today"""
        today = timezone.now().date()
        total = self.transactions_from.filter(
            transaction_date__date=today,
            status='COMPLETED'
        ).aggregate(
            total=models.Sum('amount')
        )['total'] or Decimal('0.00')
        return total
    
    def __str__(self):
        return f"{self.account_number} - {self.account_holder.username}"
    
    class Meta:
        verbose_name = "Bank Account"
        verbose_name_plural = "Bank Accounts"
        indexes = [
            models.Index(fields=['account_number']),
            models.Index(fields=['account_holder']),
            models.Index(fields=['status']),
        ]


class Transaction(models.Model):
    """Secure transaction model with fraud detection"""
    
    TRANSACTION_TYPES = [
        ('DEPOSIT', 'Deposit'),
        ('WITHDRAWAL', 'Withdrawal'),
        ('TRANSFER', 'Transfer'),
        ('PAYMENT', 'Payment'),
        ('FEE', 'Fee'),
        ('INTEREST', 'Interest'),
        ('REFUND', 'Refund'),
    ]
    
    STATUS_CHOICES = [
        ('PENDING', 'Pending'),
        ('PROCESSING', 'Processing'),
        ('COMPLETED', 'Completed'),
        ('FAILED', 'Failed'),
        ('CANCELLED', 'Cancelled'),
        ('REJECTED', 'Rejected'),
    ]
    
    # Transaction identification
    transaction_id = models.CharField(max_length=50, unique=True, editable=False)
    transaction_type = models.CharField(max_length=15, choices=TRANSACTION_TYPES)
    
    # Transaction details
    from_account = models.ForeignKey(
        Account, 
        on_delete=models.CASCADE, 
        related_name='transactions_from',
        null=True, 
        blank=True
    )
    to_account = models.ForeignKey(
        Account, 
        on_delete=models.CASCADE, 
        related_name='transactions_to',
        null=True, 
        blank=True
    )
    
    amount = models.DecimalField(
        max_digits=15, 
        decimal_places=2,
        validators=[MinValueValidator(Decimal('0.01'))]
    )
    fee = models.DecimalField(
        max_digits=10, 
        decimal_places=2, 
        default=Decimal('0.00')
    )
    
    # Transaction metadata
    description = models.TextField(blank=True)
    reference_number = models.CharField(max_length=100, blank=True)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='PENDING')
    
    # Security and tracking
    initiated_by = models.ForeignKey(User, on_delete=models.CASCADE, related_name='initiated_transactions')
    approved_by = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='approved_transactions',
        null=True, 
        blank=True
    )
    
    # Fraud detection
    fraud_score = models.IntegerField(
        default=0,
        validators=[MinValueValidator(0), MaxValueValidator(100)]
    )
    is_suspicious = models.BooleanField(default=False)
    fraud_reason = models.TextField(blank=True)
    
    # Network information
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    user_agent = models.TextField(blank=True)
    device_fingerprint = models.CharField(max_length=100, blank=True)
    
    # Timestamps
    transaction_date = models.DateTimeField(auto_now_add=True)
    processed_date = models.DateTimeField(null=True, blank=True)
    updated_at = models.DateTimeField(auto_now=True)
    
    def save(self, *args, **kwargs):
        if not self.transaction_id:
            # Generate unique transaction ID
            timestamp = str(int(timezone.now().timestamp()))
            trans_hash = hashlib.md5(f"{self.amount}{timestamp}".encode()).hexdigest()[:8]
            self.transaction_id = f"TXN{trans_hash.upper()}{timestamp[-6:]}"
        
        # Calculate fee if not set
        if not self.fee and self.transaction_type in ['TRANSFER', 'PAYMENT']:
            fee_percentage = settings.BANKING_SETTINGS.get('TRANSACTION_FEE_PERCENTAGE', 0.01)
            self.fee = self.amount * Decimal(str(fee_percentage))
        
        # Set processed date when status changes to completed
        if self.status == 'COMPLETED' and not self.processed_date:
            self.processed_date = timezone.now()
        
        super().save(*args, **kwargs)
    
    def calculate_fraud_score(self):
        """Calculate fraud score based on various factors"""
        score = 0
        
        # Large amount transactions
        if self.amount > Decimal('10000'):
            score += 20
        elif self.amount > Decimal('5000'):
            score += 10
        
        # Unusual timing (late night transactions)
        hour = self.transaction_date.hour
        if hour < 6 or hour > 23:
            score += 15
        
        # Multiple transactions in short time
        recent_transactions = Transaction.objects.filter(
            from_account=self.from_account,
            transaction_date__gte=timezone.now() - timezone.timedelta(hours=1)
        ).count()
        
        if recent_transactions > 5:
            score += 25
        elif recent_transactions > 3:
            score += 15
        
        # Unknown device/IP
        if self.from_account:
            user_recent_ips = Transaction.objects.filter(
                from_account__account_holder=self.from_account.account_holder,
                ip_address=self.ip_address,
                transaction_date__gte=timezone.now() - timezone.timedelta(days=30)
            ).exists()
            
            if not user_recent_ips and self.ip_address:
                score += 20
        
        self.fraud_score = min(score, 100)
        self.is_suspicious = score >= 50
        
        if self.is_suspicious:
            fraud_reasons = []
            if self.amount > Decimal('10000'):
                fraud_reasons.append("Large transaction amount")
            if hour < 6 or hour > 23:
                fraud_reasons.append("Unusual transaction time")
            if recent_transactions > 5:
                fraud_reasons.append("Multiple rapid transactions")
            
            self.fraud_reason = "; ".join(fraud_reasons)
    
    def process_transaction(self):
        """Process the transaction and update account balances"""
        if self.status != 'PENDING':
            return False, "Transaction already processed"
        
        try:
            self.status = 'PROCESSING'
            self.save()
            
            # Calculate fraud score
            self.calculate_fraud_score()
            
            # Reject high-risk transactions
            if self.fraud_score >= 80:
                self.status = 'REJECTED'
                self.save()
                return False, "Transaction rejected due to high fraud risk"
            
            # Process based on transaction type
            if self.transaction_type == 'DEPOSIT':
                self.to_account.balance += self.amount
                self.to_account.save()
            
            elif self.transaction_type == 'WITHDRAWAL':
                if not self.from_account.can_withdraw(self.amount):
                    self.status = 'FAILED'
                    self.save()
                    return False, "Insufficient funds or transaction limit exceeded"
                
                self.from_account.balance -= self.amount
                self.from_account.save()
            
            elif self.transaction_type == 'TRANSFER':
                total_amount = self.amount + self.fee
                
                if not self.from_account.can_withdraw(total_amount):
                    self.status = 'FAILED'
                    self.save()
                    return False, "Insufficient funds or transaction limit exceeded"
                
                # Check daily limit
                daily_total = self.from_account.get_daily_transaction_total()
                if daily_total + total_amount > self.from_account.daily_transaction_limit:
                    self.status = 'FAILED'
                    self.save()
                    return False, "Daily transaction limit exceeded"
                
                self.from_account.balance -= total_amount
                self.to_account.balance += self.amount
                self.from_account.save()
                self.to_account.save()
            
            self.status = 'COMPLETED'
            self.processed_date = timezone.now()
            self.save()
            
            # Update last transaction date for accounts
            if self.from_account:
                self.from_account.last_transaction_date = timezone.now()
                self.from_account.save()
            if self.to_account:
                self.to_account.last_transaction_date = timezone.now()
                self.to_account.save()
            
            return True, "Transaction completed successfully"
        
        except Exception as e:
            self.status = 'FAILED'
            self.save()
            logger.error(f"Transaction processing failed: {e}")
            return False, f"Transaction failed: {str(e)}"
    
    def __str__(self):
        return f"{self.transaction_id} - {self.transaction_type} - {self.amount}"
    
    class Meta:
        verbose_name = "Transaction"
        verbose_name_plural = "Transactions"
        ordering = ['-transaction_date']
        indexes = [
            models.Index(fields=['transaction_id']),
            models.Index(fields=['from_account', 'transaction_date']),
            models.Index(fields=['to_account', 'transaction_date']),
            models.Index(fields=['status']),
            models.Index(fields=['is_suspicious']),
        ]


class TransactionHistory(models.Model):
    """Audit trail for all transaction changes"""
    
    transaction = models.ForeignKey(Transaction, on_delete=models.CASCADE, related_name='history')
    field_name = models.CharField(max_length=50)
    old_value = models.TextField(blank=True)
    new_value = models.TextField(blank=True)
    changed_by = models.ForeignKey(User, on_delete=models.CASCADE)
    changed_at = models.DateTimeField(auto_now_add=True)
    reason = models.TextField(blank=True)
    
    def __str__(self):
        return f"{self.transaction.transaction_id} - {self.field_name} changed"
    
    class Meta:
        verbose_name = "Transaction History"
        verbose_name_plural = "Transaction Histories"
        ordering = ['-changed_at']


class FraudAlert(models.Model):
    """Fraud detection alerts"""
    
    ALERT_TYPES = [
        ('SUSPICIOUS_TRANSACTION', 'Suspicious Transaction'),
        ('MULTIPLE_FAILED_LOGINS', 'Multiple Failed Logins'),
        ('UNUSUAL_PATTERN', 'Unusual Pattern'),
        ('HIGH_RISK_TRANSACTION', 'High Risk Transaction'),
        ('ACCOUNT_BREACH', 'Potential Account Breach'),
    ]
    
    SEVERITY_LEVELS = [
        ('LOW', 'Low'),
        ('MEDIUM', 'Medium'),
        ('HIGH', 'High'),
        ('CRITICAL', 'Critical'),
    ]
    
    STATUS_CHOICES = [
        ('OPEN', 'Open'),
        ('INVESTIGATING', 'Under Investigation'),
        ('RESOLVED', 'Resolved'),
        ('FALSE_POSITIVE', 'False Positive'),
    ]
    
    alert_id = models.CharField(max_length=50, unique=True, editable=False)
    alert_type = models.CharField(max_length=30, choices=ALERT_TYPES)
    severity = models.CharField(max_length=10, choices=SEVERITY_LEVELS)
    status = models.CharField(max_length=15, choices=STATUS_CHOICES, default='OPEN')
    
    # Related objects
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='fraud_alerts')
    account = models.ForeignKey(Account, on_delete=models.CASCADE, null=True, blank=True)
    transaction = models.ForeignKey(Transaction, on_delete=models.CASCADE, null=True, blank=True)
    
    # Alert details
    title = models.CharField(max_length=200)
    description = models.TextField()
    risk_score = models.IntegerField(validators=[MinValueValidator(0), MaxValueValidator(100)])
    
    # Resolution
    assigned_to = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='assigned_alerts',
        null=True, 
        blank=True
    )
    resolved_by = models.ForeignKey(
        User, 
        on_delete=models.CASCADE, 
        related_name='resolved_alerts',
        null=True, 
        blank=True
    )
    resolution_notes = models.TextField(blank=True)
    
    # Timestamps
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)
    resolved_at = models.DateTimeField(null=True, blank=True)
    
    def save(self, *args, **kwargs):
        if not self.alert_id:
            timestamp = str(int(timezone.now().timestamp()))
            alert_hash = hashlib.md5(f"{self.user.id}{timestamp}".encode()).hexdigest()[:6]
            self.alert_id = f"ALERT{alert_hash.upper()}{timestamp[-4:]}"
        
        if self.status == 'RESOLVED' and not self.resolved_at:
            self.resolved_at = timezone.now()
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.alert_id} - {self.title}"
    
    class Meta:
        verbose_name = "Fraud Alert"
        verbose_name_plural = "Fraud Alerts"
        ordering = ['-created_at']


class AuditLog(models.Model):
    """System audit logs for compliance"""
    
    ACTION_TYPES = [
        ('CREATE', 'Create'),
        ('UPDATE', 'Update'),
        ('DELETE', 'Delete'),
        ('LOGIN', 'Login'),
        ('LOGOUT', 'Logout'),
        ('VIEW', 'View'),
        ('EXPORT', 'Export'),
        ('IMPORT', 'Import'),
    ]
    
    # Log identification
    log_id = models.CharField(max_length=50, unique=True, editable=False)
    action_type = models.CharField(max_length=10, choices=ACTION_TYPES)
    
    # User and target information
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name='audit_logs')
    target_model = models.CharField(max_length=50)
    target_id = models.CharField(max_length=50)
    
    # Action details
    description = models.TextField()
    changes = models.JSONField(default=dict, blank=True)
    
    # Request information
    ip_address = models.GenericIPAddressField()
    user_agent = models.TextField(blank=True)
    
    # Timestamps
    timestamp = models.DateTimeField(auto_now_add=True)
    
    def save(self, *args, **kwargs):
        if not self.log_id:
            timestamp = str(int(timezone.now().timestamp()))
            log_hash = hashlib.md5(f"{self.user.id}{timestamp}".encode()).hexdigest()[:8]
            self.log_id = f"LOG{log_hash.upper()}{timestamp[-6:]}"
        
        super().save(*args, **kwargs)
    
    def __str__(self):
        return f"{self.log_id} - {self.user.username} - {self.action_type}"
    
    class Meta:
        verbose_name = "Audit Log"
        verbose_name_plural = "Audit Logs"
        ordering = ['-timestamp']
        indexes = [
            models.Index(fields=['user', 'timestamp']),
            models.Index(fields=['action_type']),
            models.Index(fields=['target_model']),
        ]