"""
Django REST Framework Views for Banking API

This module contains all API views for the banking application with
comprehensive security, validation, and business logic implementation.
"""

from rest_framework import generics, status, permissions, filters
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet, ReadOnlyModelViewSet
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from rest_framework_simplejwt.tokens import RefreshToken
from django_filters.rest_framework import DjangoFilterBackend
from django.contrib.auth import logout
from django.utils import timezone
from django.db.models import Q, Sum
from django.core.cache import cache
from django_ratelimit.decorators import ratelimit
from django.utils.decorators import method_decorator
from decimal import Decimal
from datetime import datetime, timedelta
import logging

from .models import (
    User, UserRole, Account, Transaction, TransactionHistory,
    FraudAlert, AuditLog
)
from .serializers import (
    UserRegistrationSerializer, UserSerializer, CustomTokenObtainPairSerializer,
    AccountSerializer, TransactionSerializer, TransactionHistorySerializer,
    FraudAlertSerializer, AuditLogSerializer, BalanceInquirySerializer,
    AccountStatementSerializer
)
from .permissions import IsOwnerOrReadOnly, IsBankStaff, IsCustomer
from .utils import create_audit_log, detect_fraud, send_fraud_alert

logger = logging.getLogger(__name__)


class CustomTokenObtainPairView(TokenObtainPairView):
    """Enhanced JWT token view with security features"""
    serializer_class = CustomTokenObtainPairSerializer
    
    @method_decorator(ratelimit(key='ip', rate='5/m', method='POST'))
    def post(self, request, *args, **kwargs):
        """Rate-limited login endpoint"""
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == 200:
            # Log successful login
            username = request.data.get('username')
            try:
                user = User.objects.get(username=username)
                create_audit_log(
                    user=user,
                    action_type='LOGIN',
                    description=f'User {username} logged in successfully',
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    target_model='User',
                    target_id=str(user.id)
                )
            except User.DoesNotExist:
                pass
        
        return response
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


class UserRegistrationView(generics.CreateAPIView):
    """User registration endpoint with comprehensive validation"""
    queryset = User.objects.all()
    serializer_class = UserRegistrationSerializer
    permission_classes = [permissions.AllowAny]
    
    @method_decorator(ratelimit(key='ip', rate='3/m', method='POST'))
    def post(self, request, *args, **kwargs):
        """Rate-limited registration endpoint"""
        response = super().post(request, *args, **kwargs)
        
        if response.status_code == 201:
            user_data = response.data
            logger.info(f"New user registered: {user_data.get('username')}")
            
            # Create audit log
            try:
                user = User.objects.get(username=user_data.get('username'))
                create_audit_log(
                    user=user,
                    action_type='CREATE',
                    description=f'New user account created: {user.username}',
                    ip_address=self.get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    target_model='User',
                    target_id=str(user.id)
                )
            except User.DoesNotExist:
                pass
        
        return response
    
    def get_client_ip(self, request):
        """Get client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
        return ip


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@ratelimit(key='user', rate='10/m', method='POST')
def logout_view(request):
    """Logout endpoint that blacklists refresh token"""
    try:
        refresh_token = request.data.get('refresh_token')
        if refresh_token:
            token = RefreshToken(refresh_token)
            token.blacklist()
        
        # Create audit log
        create_audit_log(
            user=request.user,
            action_type='LOGOUT',
            description=f'User {request.user.username} logged out',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            target_model='User',
            target_id=str(request.user.id)
        )
        
        return Response({
            'message': 'Successfully logged out'
        }, status=status.HTTP_200_OK)
    
    except Exception as e:
        logger.error(f"Logout error: {e}")
        return Response({
            'error': 'Invalid token or logout failed'
        }, status=status.HTTP_400_BAD_REQUEST)


class UserProfileView(generics.RetrieveUpdateAPIView):
    """User profile management endpoint"""
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]
    
    def get_object(self):
        """Return the current user"""
        return self.request.user
    
    def update(self, request, *args, **kwargs):
        """Track profile updates in audit log"""
        old_data = UserSerializer(self.get_object()).data
        response = super().update(request, *args, **kwargs)
        
        if response.status_code == 200:
            new_data = response.data
            changes = {}
            for key, new_value in new_data.items():
                old_value = old_data.get(key)
                if old_value != new_value:
                    changes[key] = {'old': old_value, 'new': new_value}
            
            if changes:
                create_audit_log(
                    user=request.user,
                    action_type='UPDATE',
                    description=f'User profile updated',
                    changes=changes,
                    ip_address=get_client_ip(request),
                    user_agent=request.META.get('HTTP_USER_AGENT', ''),
                    target_model='User',
                    target_id=str(request.user.id)
                )
        
        return response


class AccountViewSet(ModelViewSet):
    """ViewSet for bank account management"""
    serializer_class = AccountSerializer
    permission_classes = [permissions.IsAuthenticated, IsOwnerOrReadOnly]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['account_type', 'status']
    search_fields = ['account_number']
    ordering_fields = ['created_at', 'balance']
    
    def get_queryset(self):
        """Return accounts owned by current user or all if staff"""
        if self.request.user.is_staff or (hasattr(self.request.user, 'has_role') and self.request.user.has_role('MANAGER')):
            return Account.objects.all().select_related('account_holder')
        return Account.objects.filter(
            account_holder=self.request.user
        ).select_related('account_holder')
    
    def create(self, request, *args, **kwargs):
        """Create new account with audit logging"""
        response = super().create(request, *args, **kwargs)
        
        if response.status_code == 201:
            account_data = response.data
            create_audit_log(
                user=request.user,
                action_type='CREATE',
                description=f'New account created: {account_data.get("account_number")}',
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                target_model='Account',
                target_id=str(account_data.get('id'))
            )
        
        return response
    
    @action(detail=True, methods=['get'])
    def balance(self, request, pk=None):
        """Get account balance"""
        account = self.get_object()
        
        # Check cache first
        cache_key = f"balance_{account.account_number}"
        cached_balance = cache.get(cache_key)
        
        if cached_balance is None:
            balance_data = {
                'account_number': account.account_number,
                'balance': account.balance,
                'available_balance': account.available_balance,
                'last_updated': account.updated_at
            }
            cache.set(cache_key, balance_data, timeout=300)  # 5 minutes
        else:
            balance_data = cached_balance
        
        # Log balance inquiry
        create_audit_log(
            user=request.user,
            action_type='VIEW',
            description=f'Balance inquiry for account {account.account_number}',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            target_model='Account',
            target_id=str(account.id)
        )
        
        return Response(balance_data)
    
    @action(detail=True, methods=['get'])
    def statement(self, request, pk=None):
        """Get account statement"""
        account = self.get_object()
        serializer = AccountStatementSerializer(
            data=request.query_params,
            context={'request': request}
        )
        serializer.is_valid(raise_exception=True)
        
        # Build query filters
        filters = Q(from_account=account) | Q(to_account=account)
        
        start_date = serializer.validated_data.get('start_date')
        end_date = serializer.validated_data.get('end_date')
        transaction_type = serializer.validated_data.get('transaction_type')
        
        if start_date:
            filters &= Q(transaction_date__date__gte=start_date)
        if end_date:
            filters &= Q(transaction_date__date__lte=end_date)
        if transaction_type:
            filters &= Q(transaction_type=transaction_type)
        
        transactions = Transaction.objects.filter(filters).order_by('-transaction_date')
        
        # Paginate results
        page = self.paginate_queryset(transactions)
        if page is not None:
            transaction_serializer = TransactionSerializer(page, many=True)
            return self.get_paginated_response(transaction_serializer.data)
        
        transaction_serializer = TransactionSerializer(transactions, many=True)
        
        # Log statement access
        create_audit_log(
            user=request.user,
            action_type='VIEW',
            description=f'Account statement accessed for {account.account_number}',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            target_model='Account',
            target_id=str(account.id)
        )
        
        return Response({
            'account': AccountSerializer(account).data,
            'transactions': transaction_serializer.data,
            'summary': {
                'total_transactions': transactions.count(),
                'total_debits': transactions.filter(
                    from_account=account, status='COMPLETED'
                ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00'),
                'total_credits': transactions.filter(
                    to_account=account, status='COMPLETED'
                ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
            }
        })


class TransactionViewSet(ModelViewSet):
    """ViewSet for transaction management"""
    serializer_class = TransactionSerializer
    permission_classes = [permissions.IsAuthenticated]
    filter_backends = [DjangoFilterBackend, filters.SearchFilter, filters.OrderingFilter]
    filterset_fields = ['transaction_type', 'status', 'is_suspicious']
    search_fields = ['transaction_id', 'description', 'reference_number']
    ordering_fields = ['transaction_date', 'amount']
    
    def get_queryset(self):
        """Return transactions for current user or all if staff"""
        if self.request.user.is_staff or (hasattr(self.request.user, 'has_role') and self.request.user.has_role('MANAGER')):
            return Transaction.objects.all().select_related(
                'from_account', 'to_account', 'initiated_by'
            )
        
        user_accounts = Account.objects.filter(account_holder=self.request.user)
        return Transaction.objects.filter(
            Q(from_account__in=user_accounts) | Q(to_account__in=user_accounts)
        ).select_related('from_account', 'to_account', 'initiated_by')
    
    @method_decorator(ratelimit(key='user', rate='20/m', method='POST'))
    def create(self, request, *args, **kwargs):
        """Create new transaction with fraud detection"""
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        
        # Create transaction
        transaction = serializer.save()
        
        # Run fraud detection
        fraud_detected, fraud_reason = detect_fraud(transaction, request)
        if fraud_detected:
            transaction.is_suspicious = True
            transaction.fraud_reason = fraud_reason
            transaction.status = 'PENDING'  # Hold for manual review
            transaction.save()
            
            # Send fraud alert
            send_fraud_alert(transaction, fraud_reason)
            
            logger.warning(f"Suspicious transaction detected: {transaction.transaction_id}")
        
        # Process transaction if not suspicious
        if not transaction.is_suspicious:
            success, message = transaction.process_transaction()
            if not success:
                return Response({
                    'error': message,
                    'transaction_id': transaction.transaction_id
                }, status=status.HTTP_400_BAD_REQUEST)
        
        # Create audit log
        create_audit_log(
            user=request.user,
            action_type='CREATE',
            description=f'Transaction created: {transaction.transaction_id}',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            target_model='Transaction',
            target_id=str(transaction.id)
        )
        
        headers = self.get_success_headers(serializer.data)
        return Response(
            TransactionSerializer(transaction).data,
            status=status.HTTP_201_CREATED,
            headers=headers
        )
    
    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAuthenticated, IsBankStaff])
    def approve(self, request, pk=None):
        """Approve pending transaction (staff only)"""
        transaction = self.get_object()
        
        if transaction.status != 'PENDING':
            return Response({
                'error': 'Transaction is not pending approval'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        transaction.approved_by = request.user
        success, message = transaction.process_transaction()
        
        if success:
            create_audit_log(
                user=request.user,
                action_type='UPDATE',
                description=f'Transaction approved: {transaction.transaction_id}',
                changes={'status': {'old': 'PENDING', 'new': transaction.status}},
                ip_address=get_client_ip(request),
                user_agent=request.META.get('HTTP_USER_AGENT', ''),
                target_model='Transaction',
                target_id=str(transaction.id)
            )
            
            return Response({
                'message': 'Transaction approved and processed successfully',
                'transaction': TransactionSerializer(transaction).data
            })
        else:
            return Response({
                'error': message
            }, status=status.HTTP_400_BAD_REQUEST)
    
    @action(detail=True, methods=['post'], permission_classes=[permissions.IsAuthenticated, IsBankStaff])
    def reject(self, request, pk=None):
        """Reject pending transaction (staff only)"""
        transaction = self.get_object()
        
        if transaction.status != 'PENDING':
            return Response({
                'error': 'Transaction is not pending approval'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        reason = request.data.get('reason', 'No reason provided')
        transaction.status = 'REJECTED'
        transaction.approved_by = request.user
        transaction.save()
        
        # Create audit log
        create_audit_log(
            user=request.user,
            action_type='UPDATE',
            description=f'Transaction rejected: {transaction.transaction_id} - Reason: {reason}',
            changes={'status': {'old': 'PENDING', 'new': 'REJECTED'}},
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            target_model='Transaction',
            target_id=str(transaction.id)
        )
        
        return Response({
            'message': 'Transaction rejected successfully',
            'transaction': TransactionSerializer(transaction).data
        })


@api_view(['POST'])
@permission_classes([permissions.IsAuthenticated])
@ratelimit(key='user', rate='30/m', method='POST')
def balance_inquiry(request):
    """Quick balance inquiry endpoint"""
    serializer = BalanceInquirySerializer(
        data=request.data,
        context={'request': request}
    )
    serializer.is_valid(raise_exception=True)
    
    account_number = serializer.validated_data['account_number']
    
    try:
        account = Account.objects.get(account_number=account_number)
        
        # Check permissions
        if request.user != account.account_holder and not request.user.is_staff:
            return Response({
                'error': 'You can only check your own account balance'
            }, status=status.HTTP_403_FORBIDDEN)
        
        balance_data = {
            'account_number': account.account_number,
            'account_type': account.account_type,
            'balance': account.balance,
            'available_balance': account.available_balance,
            'currency': 'USD',
            'last_updated': account.updated_at
        }
        
        # Log balance inquiry
        create_audit_log(
            user=request.user,
            action_type='VIEW',
            description=f'Balance inquiry for account {account_number}',
            ip_address=get_client_ip(request),
            user_agent=request.META.get('HTTP_USER_AGENT', ''),
            target_model='Account',
            target_id=str(account.id)
        )
        
        return Response(balance_data)
    
    except Account.DoesNotExist:
        return Response({
            'error': 'Account not found'
        }, status=status.HTTP_404_NOT_FOUND)


class FraudAlertViewSet(ReadOnlyModelViewSet):
    """ViewSet for fraud alert management (read-only for most users)"""
    serializer_class = FraudAlertSerializer
    permission_classes = [permissions.IsAuthenticated, IsBankStaff]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['alert_type', 'severity', 'status']
    ordering_fields = ['created_at', 'risk_score']
    
    def get_queryset(self):
        """Return fraud alerts based on user role"""
        if (hasattr(self.request.user, 'has_role') and self.request.user.has_role('ADMIN')) or self.request.user.is_superuser:
            return FraudAlert.objects.all()
        elif hasattr(self.request.user, 'has_role') and self.request.user.has_role('MANAGER'):
            return FraudAlert.objects.filter(severity__in=['HIGH', 'CRITICAL'])
        else:
            return FraudAlert.objects.filter(assigned_to=self.request.user)


class AuditLogViewSet(ReadOnlyModelViewSet):
    """ViewSet for audit log management (read-only)"""
    serializer_class = AuditLogSerializer
    permission_classes = [permissions.IsAuthenticated, IsBankStaff]
    filter_backends = [DjangoFilterBackend, filters.OrderingFilter]
    filterset_fields = ['action_type', 'target_model']
    ordering_fields = ['timestamp']
    
    def get_queryset(self):
        """Return audit logs based on user role"""
        if (hasattr(self.request.user, 'has_role') and self.request.user.has_role('ADMIN')) or self.request.user.is_superuser:
            return AuditLog.objects.all()
        elif hasattr(self.request.user, 'has_role') and self.request.user.has_role('AUDITOR'):
            return AuditLog.objects.all()
        else:
            # Regular staff can only see their own actions
            return AuditLog.objects.filter(user=self.request.user)


@api_view(['GET'])
@permission_classes([permissions.IsAuthenticated])
def dashboard_stats(request):
    """Dashboard statistics for authenticated users"""
    user = request.user
    
    if hasattr(user, 'has_role') and user.has_role('CUSTOMER'):
        # Customer dashboard
        user_accounts = Account.objects.filter(account_holder=user)
        user_transactions = Transaction.objects.filter(
            Q(from_account__in=user_accounts) | Q(to_account__in=user_accounts)
        )
        
        stats = {
            'total_accounts': user_accounts.count(),
            'total_balance': user_accounts.aggregate(
                total=Sum('balance')
            )['total'] or Decimal('0.00'),
            'recent_transactions': user_transactions.order_by('-transaction_date')[:5].count(),
            'pending_transactions': user_transactions.filter(status='PENDING').count(),
            'monthly_spending': user_transactions.filter(
                from_account__in=user_accounts,
                transaction_date__gte=timezone.now().replace(day=1),
                status='COMPLETED'
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00')
        }
    
    elif (hasattr(user, 'has_role') and user.has_role('MANAGER')) or user.is_staff:
        # Manager/Staff dashboard
        stats = {
            'total_accounts': Account.objects.count(),
            'total_users': User.objects.count(),
            'pending_transactions': Transaction.objects.filter(status='PENDING').count(),
            'fraud_alerts': FraudAlert.objects.filter(status='OPEN').count(),
            'daily_transaction_volume': Transaction.objects.filter(
                transaction_date__date=timezone.now().date(),
                status='COMPLETED'
            ).aggregate(total=Sum('amount'))['total'] or Decimal('0.00'),
            'suspicious_transactions': Transaction.objects.filter(
                is_suspicious=True,
                transaction_date__date=timezone.now().date()
            ).count()
        }
    
    else:
        stats = {'message': 'No dashboard data available for your role'}
    
    return Response(stats)


def get_client_ip(request):
    """Utility function to get client IP address"""
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip
