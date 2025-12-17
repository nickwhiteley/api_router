"""
API Translation Platform Python Client
"""

import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from urllib.parse import urljoin, urlencode

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from .models import (
    Organisation,
    APIConfiguration,
    Connector,
    User,
    SystemHealth,
    UsageAnalytics,
)
from .exceptions import ATPError, AuthenticationError, NotFoundError, ValidationError


class Client:
    """API Translation Platform client for Python."""
    
    def __init__(
        self,
        base_url: str,
        token: Optional[str] = None,
        version: str = "v1",
        timeout: int = 30,
        max_retries: int = 3,
        session: Optional[requests.Session] = None,
    ):
        """
        Initialize the ATP client.
        
        Args:
            base_url: Base URL of the API Translation Platform
            token: Authentication token (JWT)
            version: API version to use (default: v1)
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries for failed requests
            session: Optional custom requests session
        """
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.version = version
        self.timeout = timeout
        
        # Set up session with retry strategy
        self.session = session or requests.Session()
        retry_strategy = Retry(
            total=max_retries,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)
        
        # Set default headers
        self.session.headers.update({
            "Content-Type": "application/json",
            "Accept": "application/json",
        })
        
        if self.token:
            self.session.headers["Authorization"] = f"Bearer {self.token}"
    
    def set_token(self, token: str) -> None:
        """Set the authentication token."""
        self.token = token
        self.session.headers["Authorization"] = f"Bearer {token}"
    
    def _make_request(
        self,
        method: str,
        path: str,
        data: Optional[Dict[str, Any]] = None,
        params: Optional[Dict[str, Any]] = None,
    ) -> Any:
        """Make an HTTP request to the API."""
        url = urljoin(f"{self.base_url}/api/{self.version}/", path.lstrip("/"))
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                json=data,
                params=params,
                timeout=self.timeout,
            )
            
            # Handle different response status codes
            if response.status_code == 401:
                raise AuthenticationError("Authentication failed")
            elif response.status_code == 404:
                raise NotFoundError("Resource not found")
            elif response.status_code == 400:
                error_data = response.json() if response.content else {}
                raise ValidationError(error_data.get("error", "Validation failed"))
            elif response.status_code >= 400:
                error_data = response.json() if response.content else {}
                raise ATPError(
                    error_data.get("error", f"HTTP {response.status_code}"),
                    status_code=response.status_code,
                )
            
            # Return parsed JSON for successful responses with content
            if response.content:
                return response.json()
            return None
            
        except requests.exceptions.RequestException as e:
            raise ATPError(f"Request failed: {str(e)}")
    
    # Organisation Management
    
    def create_organisation(self, name: str, is_active: bool = True) -> Organisation:
        """Create a new organisation."""
        data = {"name": name, "is_active": is_active}
        result = self._make_request("POST", "/organisations", data=data)
        return Organisation.from_dict(result)
    
    def get_organisations(self) -> List[Organisation]:
        """Get all organisations."""
        result = self._make_request("GET", "/organisations")
        return [Organisation.from_dict(org) for org in result]
    
    def get_organisation(self, org_id: str) -> Organisation:
        """Get a specific organisation."""
        result = self._make_request("GET", f"/organisations/{org_id}")
        return Organisation.from_dict(result)
    
    def update_organisation(
        self, org_id: str, name: Optional[str] = None, is_active: Optional[bool] = None
    ) -> Organisation:
        """Update an organisation."""
        data = {}
        if name is not None:
            data["name"] = name
        if is_active is not None:
            data["is_active"] = is_active
        
        result = self._make_request("PUT", f"/organisations/{org_id}", data=data)
        return Organisation.from_dict(result)
    
    def delete_organisation(self, org_id: str) -> None:
        """Delete an organisation."""
        self._make_request("DELETE", f"/organisations/{org_id}")
    
    # API Configuration Management
    
    def create_api_configuration(
        self, org_id: str, config: APIConfiguration
    ) -> APIConfiguration:
        """Create a new API configuration."""
        result = self._make_request(
            "POST", f"/organisations/{org_id}/api-configurations", data=config.to_dict()
        )
        return APIConfiguration.from_dict(result)
    
    def get_api_configurations(self, org_id: str) -> List[APIConfiguration]:
        """Get all API configurations for an organisation."""
        result = self._make_request("GET", f"/organisations/{org_id}/api-configurations")
        return [APIConfiguration.from_dict(config) for config in result]
    
    def get_api_configuration(self, config_id: str) -> APIConfiguration:
        """Get a specific API configuration."""
        result = self._make_request("GET", f"/api-configurations/{config_id}")
        return APIConfiguration.from_dict(result)
    
    def update_api_configuration(
        self, config_id: str, config: APIConfiguration
    ) -> APIConfiguration:
        """Update an API configuration."""
        result = self._make_request(
            "PUT", f"/api-configurations/{config_id}", data=config.to_dict()
        )
        return APIConfiguration.from_dict(result)
    
    def delete_api_configuration(self, config_id: str) -> None:
        """Delete an API configuration."""
        self._make_request("DELETE", f"/api-configurations/{config_id}")
    
    def test_api_configuration(
        self, config_id: str, test_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Test an API configuration."""
        return self._make_request(
            "POST", f"/api-configurations/{config_id}/test", data=test_data
        )
    
    # Connector Management
    
    def create_connector(self, org_id: str, connector: Connector) -> Connector:
        """Create a new connector."""
        result = self._make_request(
            "POST", f"/organisations/{org_id}/connectors", data=connector.to_dict()
        )
        return Connector.from_dict(result)
    
    def get_connectors(self, org_id: str) -> List[Connector]:
        """Get all connectors for an organisation."""
        result = self._make_request("GET", f"/organisations/{org_id}/connectors")
        return [Connector.from_dict(connector) for connector in result]
    
    def get_connector(self, connector_id: str) -> Connector:
        """Get a specific connector."""
        result = self._make_request("GET", f"/connectors/{connector_id}")
        return Connector.from_dict(result)
    
    def update_connector(self, connector_id: str, connector: Connector) -> Connector:
        """Update a connector."""
        result = self._make_request(
            "PUT", f"/connectors/{connector_id}", data=connector.to_dict()
        )
        return Connector.from_dict(result)
    
    def delete_connector(self, connector_id: str) -> None:
        """Delete a connector."""
        self._make_request("DELETE", f"/connectors/{connector_id}")
    
    def update_connector_script(self, connector_id: str, script: str) -> None:
        """Update a connector's Python script."""
        self._make_request(
            "PUT", f"/connectors/{connector_id}/script", data={"script": script}
        )
    
    # User Management
    
    def create_user(
        self, org_id: str, username: str, email: str, password: str, role: str = "org_admin"
    ) -> User:
        """Create a new user."""
        user_data = {
            "username": username,
            "email": email,
            "role": role,
            "is_active": True,
        }
        data = {"user": user_data, "password": password}
        result = self._make_request("POST", f"/organisations/{org_id}/users", data=data)
        return User.from_dict(result)
    
    def get_users(self, org_id: str) -> List[User]:
        """Get all users for an organisation."""
        result = self._make_request("GET", f"/organisations/{org_id}/users")
        return [User.from_dict(user) for user in result]
    
    def get_user(self, user_id: str) -> User:
        """Get a specific user."""
        result = self._make_request("GET", f"/users/{user_id}")
        return User.from_dict(result)
    
    def update_user(self, user_id: str, user: User) -> User:
        """Update a user."""
        result = self._make_request("PUT", f"/users/{user_id}", data=user.to_dict())
        return User.from_dict(result)
    
    def delete_user(self, user_id: str) -> None:
        """Delete a user."""
        self._make_request("DELETE", f"/users/{user_id}")
    
    def change_user_role(self, user_id: str, role: str) -> None:
        """Change a user's role."""
        self._make_request("PUT", f"/users/{user_id}/role", data={"role": role})
    
    def change_user_password(self, user_id: str, password: str) -> None:
        """Change a user's password."""
        self._make_request("PUT", f"/users/{user_id}/password", data={"password": password})
    
    def activate_user(self, user_id: str) -> None:
        """Activate a user."""
        self._make_request("POST", f"/users/{user_id}/activate")
    
    def deactivate_user(self, user_id: str) -> None:
        """Deactivate a user."""
        self._make_request("POST", f"/users/{user_id}/deactivate")
    
    # Monitoring and Analytics
    
    def get_system_health(self) -> SystemHealth:
        """Get system health status."""
        result = self._make_request("GET", "/system/health")
        return SystemHealth.from_dict(result)
    
    def get_organisation_metrics(self, org_id: str) -> Dict[str, Any]:
        """Get metrics for an organisation."""
        return self._make_request("GET", f"/organisations/{org_id}/metrics")
    
    def get_usage_analytics(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> UsageAnalytics:
        """Get API usage analytics."""
        params = {}
        if start_time:
            params["start"] = start_time.isoformat()
        if end_time:
            params["end"] = end_time.isoformat()
        
        result = self._make_request("GET", "/analytics/usage", params=params)
        return UsageAnalytics.from_dict(result)
    
    def get_rate_limit_analytics(
        self, start_time: Optional[datetime] = None, end_time: Optional[datetime] = None
    ) -> Dict[str, Any]:
        """Get rate limit analytics."""
        params = {}
        if start_time:
            params["start"] = start_time.isoformat()
        if end_time:
            params["end"] = end_time.isoformat()
        
        return self._make_request("GET", "/analytics/rate-limits", params=params)
    
    def get_organisation_logs(
        self, org_id: str, limit: int = 50, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get logs for an organisation."""
        params = {"limit": limit, "offset": offset}
        return self._make_request("GET", f"/organisations/{org_id}/logs", params=params)
    
    def get_organisation_errors(
        self, org_id: str, limit: int = 50, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get error logs for an organisation."""
        params = {"limit": limit, "offset": offset}
        return self._make_request("GET", f"/organisations/{org_id}/errors", params=params)
    
    def get_system_metrics(self) -> Dict[str, Any]:
        """Get system-wide metrics."""
        return self._make_request("GET", "/system/metrics")
    
    def get_system_logs(self, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Get system logs."""
        params = {"limit": limit, "offset": offset}
        return self._make_request("GET", "/system/logs", params=params)
    
    # Audit Logs
    
    def get_audit_logs(
        self, org_id: str, limit: int = 50, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get audit logs for an organisation."""
        params = {"limit": limit, "offset": offset}
        return self._make_request("GET", f"/organisations/{org_id}/audit-logs", params=params)
    
    def get_resource_audit_logs(
        self, resource_id: str, limit: int = 50, offset: int = 0
    ) -> List[Dict[str, Any]]:
        """Get audit logs for a specific resource."""
        params = {"limit": limit, "offset": offset}
        return self._make_request("GET", f"/configurations/{resource_id}/audit-logs", params=params)
    
    # Configuration Management
    
    def get_configuration_versions(self, config_id: str) -> List[Dict[str, Any]]:
        """Get all versions for a configuration."""
        return self._make_request("GET", f"/configurations/{config_id}/versions")
    
    def get_configuration_version(self, version_id: str) -> Dict[str, Any]:
        """Get a specific configuration version."""
        return self._make_request("GET", f"/configurations/versions/{version_id}")
    
    def rollback_to_version(self, version_id: str) -> None:
        """Rollback to a specific configuration version."""
        self._make_request("POST", f"/configurations/versions/{version_id}/rollback")
    
    def synchronize_configuration(self, instance_id: str) -> None:
        """Synchronize configuration across instances."""
        self._make_request("POST", f"/system/sync/{instance_id}")
    
    def get_configuration_checksum(self, org_id: str) -> str:
        """Get configuration checksum for an organisation."""
        result = self._make_request("GET", f"/organisations/{org_id}/checksum")
        return result["checksum"]
    
    def validate_configuration_consistency(self) -> None:
        """Validate configuration consistency."""
        self._make_request("POST", "/system/validate-consistency")
    
    # Utility Methods
    
    def ping(self) -> bool:
        """Test connectivity to the API."""
        try:
            self.get_system_health()
            return True
        except Exception:
            return False