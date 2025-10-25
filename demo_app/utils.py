"""
Essential utility functions for Banking Application

Simplified version to avoid import issues during setup.
More advanced features can be added after initial setup is complete.
"""

import logging
from decimal import Decimal
from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings

logger = logging.getLogger(__name__)


def create_audit_log(user, action_type, description, target_model, target_id, 
                    ip_address=None, user_agent=None, changes=None):
    """
    Create an audit log entry for tracking user actions.
    """
    try:
        from .models import AuditLog
        audit_log = AuditLog.objects.create(
            user=user,
            action_type=action_type,
            description=description,
            target_model=target_model,
            target_id=str(target_id),
            ip_address=ip_address or '127.0.0.1',
            user_agent=user_agent or '',
            changes=changes or {}
        )
        logger.info(f"Audit log created: {audit_log.log_id}")
        return audit_log
    except Exception as e:
        logger.error(f"Failed to create audit log: {e}")
        return None


def detect_fraud(transaction, request=None):
    """
    Basic fraud detection for transactions.
    """
    fraud_score = 0
    fraud_reasons = []
    
    try:
        # Basic amount-based detection
        if transaction.amount > Decimal('50000'):
            fraud_score += 30
            fraud_reasons.append("Very high transaction amount")
        elif transaction.amount > Decimal('10000'):
            fraud_score += 15
            fraud_reasons.append("High transaction amount")
        
        # Time-based detection
        hour = transaction.transaction_date.hour
        if hour < 6 or hour > 23:
            fraud_score += 20
            fraud_reasons.append("Unusual transaction time")
        
        # Update transaction fraud score
        transaction.fraud_score = min(fraud_score, 100)
        transaction.save()
        
        # Determine if transaction is fraudulent
        is_fraudulent = fraud_score >= 50
        reason = "; ".join(fraud_reasons) if fraud_reasons else "No fraud indicators"
        
        return is_fraudulent, reason
    
    except Exception as e:
        logger.error(f"Fraud detection error: {e}")
        return False, "Fraud detection system error"


def send_fraud_alert(transaction, reason):
    """
    Create fraud alert for suspicious transaction.
    """
    try:
        from .models import FraudAlert
        
        # Determine severity based on fraud score
        if transaction.fraud_score >= 80:
            severity = 'CRITICAL'
        elif transaction.fraud_score >= 60:
            severity = 'HIGH'
        elif transaction.fraud_score >= 40:
            severity = 'MEDIUM'
        else:
            severity = 'LOW'
        
        # Create fraud alert
        alert = FraudAlert.objects.create(
            alert_type='SUSPICIOUS_TRANSACTION',
            severity=severity,
            user=transaction.initiated_by,
            account=transaction.from_account,
            transaction=transaction,
            title=f"Suspicious Transaction: {transaction.transaction_id}",
            description=f"Transaction flagged for review. Amount: ${transaction.amount}. Reason: {reason}",
            risk_score=transaction.fraud_score
        )
        
        logger.warning(f"Fraud alert created: {alert.alert_id}")
        return alert
    
    except Exception as e:
        logger.error(f"Failed to create fraud alert: {e}")
        return None


def get_client_ip(request):
    """
    Extract client IP address from request.
    """
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0].strip()
    else:
        ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
    return ip


def calculate_transaction_fee(amount, transaction_type):
    """
    Calculate transaction fee based on amount and type.
    """
    fee_rates = {
        'TRANSFER': Decimal('0.01'),  # 1%
        'PAYMENT': Decimal('0.005'),  # 0.5%
        'WITHDRAWAL': Decimal('0.002'),  # 0.2%
        'DEPOSIT': Decimal('0.0'),  # Free
    }
    
    rate = fee_rates.get(transaction_type, Decimal('0.0'))
    fee = amount * rate
    
    # Minimum fee of $1 for paid transactions
    if rate > 0 and fee < Decimal('1.00'):
        fee = Decimal('1.00')
    
    # Maximum fee cap
    max_fee = Decimal('50.00')
    if fee > max_fee:
        fee = max_fee
    
    return fee