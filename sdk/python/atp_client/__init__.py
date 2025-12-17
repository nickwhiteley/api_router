"""
API Translation Platform Python SDK

A comprehensive Python client library for the API Translation Platform Management API.
"""

from .client import Client
from .models import (
    Organisation,
    APIConfiguration,
    Connector,
    User,
    SystemHealth,
    UsageAnalytics,
    AuthenticationConfig,
)
from .exceptions import ATPError, AuthenticationError, NotFoundError, ValidationError

__version__ = "1.0.0"
__all__ = [
    "Client",
    "Organisation",
    "APIConfiguration", 
    "Connector",
    "User",
    "SystemHealth",
    "UsageAnalytics",
    "AuthenticationConfig",
    "ATPError",
    "AuthenticationError",
    "NotFoundError",
    "ValidationError",
]