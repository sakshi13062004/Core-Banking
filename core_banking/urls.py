"""
URL configuration for core_banking project.

Main URL configuration for the Core Banking API system.
Includes admin interface, API endpoints, and documentation.
"""

from django.contrib import admin
from django.urls import path, include
from django.http import JsonResponse
from drf_spectacular.views import (
    SpectacularAPIView, 
    SpectacularRedocView, 
    SpectacularSwaggerView
)


def api_root(request):
    """API root endpoint with basic information"""
    return JsonResponse({
        'message': 'Welcome to Core Banking API',
        'version': '1.0.0',
        'documentation': {
            'swagger': '/api/docs/swagger/',
            'redoc': '/api/docs/redoc/',
            'openapi_schema': '/api/schema/'
        },
        'endpoints': {
            'authentication': '/api/auth/',
            'accounts': '/api/accounts/',
            'transactions': '/api/transactions/',
            'profile': '/api/profile/',
            'balance': '/api/balance/',
            'dashboard': '/api/dashboard/'
        },
        'admin': '/admin/',
        'health': '/health/'
    })


def health_check(request):
    """Simple health check endpoint"""
    return JsonResponse({
        'status': 'healthy',
        'service': 'Core Banking API',
        'version': '1.0.0'
    })


urlpatterns = [
    # Admin interface
    path('admin/', admin.site.urls),
    
    # API root and health check
    path('', api_root, name='api_root'),
    path('health/', health_check, name='health_check'),
    
    # API endpoints
    path('api/', include('demo_app.urls', namespace='banking')),
    
    # API Documentation
    path('api/schema/', SpectacularAPIView.as_view(), name='schema'),
    path('api/docs/swagger/', SpectacularSwaggerView.as_view(url_name='schema'), name='swagger-ui'),
    path('api/docs/redoc/', SpectacularRedocView.as_view(url_name='schema'), name='redoc'),
]
