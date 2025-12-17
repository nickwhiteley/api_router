"""
Exception classes for the API Translation Platform Python SDK
"""


class ATPError(Exception):
    """Base exception for ATP client errors."""
    
    def __init__(self, message: str, status_code: int = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class AuthenticationError(ATPError):
    """Raised when authentication fails."""
    
    def __init__(self, message: str = "Authentication failed"):
        super().__init__(message, status_code=401)


class NotFoundError(ATPError):
    """Raised when a resource is not found."""
    
    def __init__(self, message: str = "Resource not found"):
        super().__init__(message, status_code=404)


class ValidationError(ATPError):
    """Raised when request validation fails."""
    
    def __init__(self, message: str = "Validation failed"):
        super().__init__(message, status_code=400)


class RateLimitError(ATPError):
    """Raised when rate limit is exceeded."""
    
    def __init__(self, message: str = "Rate limit exceeded"):
        super().__init__(message, status_code=429)


class ServerError(ATPError):
    """Raised when server returns a 5xx error."""
    
    def __init__(self, message: str = "Server error", status_code: int = 500):
        super().__init__(message, status_code=status_code)