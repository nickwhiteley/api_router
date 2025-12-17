"""
Data models for the API Translation Platform Python SDK
"""

from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from dataclasses_json import dataclass_json


@dataclass_json
@dataclass
class AuthenticationConfig:
    """Authentication configuration for API endpoints."""
    type: str
    parameters: Optional[Dict[str, str]] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AuthenticationConfig":
        return cls(
            type=data["type"],
            parameters=data.get("parameters", {}),
        )


@dataclass_json
@dataclass
class Organisation:
    """Organisation model."""
    id: str
    name: str
    is_active: bool
    created_at: datetime
    updated_at: datetime
    
    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["created_at"] = self.created_at.isoformat()
        data["updated_at"] = self.updated_at.isoformat()
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Organisation":
        return cls(
            id=data["id"],
            name=data["name"],
            is_active=data["is_active"],
            created_at=datetime.fromisoformat(data["created_at"].replace("Z", "+00:00")),
            updated_at=datetime.fromisoformat(data["updated_at"].replace("Z", "+00:00")),
        )


@dataclass_json
@dataclass
class APIConfiguration:
    """API Configuration model."""
    name: str
    type: str
    direction: str
    endpoint: str
    authentication: AuthenticationConfig
    id: Optional[str] = None
    organisation_id: Optional[str] = None
    headers: Optional[Dict[str, str]] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        data = {
            "name": self.name,
            "type": self.type,
            "direction": self.direction,
            "endpoint": self.endpoint,
            "authentication": self.authentication.to_dict(),
        }
        
        if self.id:
            data["id"] = self.id
        if self.organisation_id:
            data["organisation_id"] = self.organisation_id
        if self.headers:
            data["headers"] = self.headers
        if self.created_at:
            data["created_at"] = self.created_at.isoformat()
        if self.updated_at:
            data["updated_at"] = self.updated_at.isoformat()
            
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "APIConfiguration":
        created_at = None
        updated_at = None
        
        if data.get("created_at"):
            created_at = datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
        if data.get("updated_at"):
            updated_at = datetime.fromisoformat(data["updated_at"].replace("Z", "+00:00"))
        
        return cls(
            id=data.get("id"),
            organisation_id=data.get("organisation_id"),
            name=data["name"],
            type=data["type"],
            direction=data["direction"],
            endpoint=data["endpoint"],
            authentication=AuthenticationConfig.from_dict(data["authentication"]),
            headers=data.get("headers", {}),
            created_at=created_at,
            updated_at=updated_at,
        )


@dataclass_json
@dataclass
class Connector:
    """Connector model."""
    name: str
    inbound_api_id: str
    outbound_api_id: str
    python_script: str
    id: Optional[str] = None
    organisation_id: Optional[str] = None
    is_active: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        data = {
            "name": self.name,
            "inbound_api_id": self.inbound_api_id,
            "outbound_api_id": self.outbound_api_id,
            "python_script": self.python_script,
            "is_active": self.is_active,
        }
        
        if self.id:
            data["id"] = self.id
        if self.organisation_id:
            data["organisation_id"] = self.organisation_id
        if self.created_at:
            data["created_at"] = self.created_at.isoformat()
        if self.updated_at:
            data["updated_at"] = self.updated_at.isoformat()
            
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Connector":
        created_at = None
        updated_at = None
        
        if data.get("created_at"):
            created_at = datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
        if data.get("updated_at"):
            updated_at = datetime.fromisoformat(data["updated_at"].replace("Z", "+00:00"))
        
        return cls(
            id=data.get("id"),
            organisation_id=data.get("organisation_id"),
            name=data["name"],
            inbound_api_id=data["inbound_api_id"],
            outbound_api_id=data["outbound_api_id"],
            python_script=data["python_script"],
            is_active=data.get("is_active", True),
            created_at=created_at,
            updated_at=updated_at,
        )


@dataclass_json
@dataclass
class User:
    """User model."""
    username: str
    email: str
    role: str
    id: Optional[str] = None
    organisation_id: Optional[str] = None
    is_active: bool = True
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    
    def to_dict(self) -> Dict[str, Any]:
        data = {
            "username": self.username,
            "email": self.email,
            "role": self.role,
            "is_active": self.is_active,
        }
        
        if self.id:
            data["id"] = self.id
        if self.organisation_id:
            data["organisation_id"] = self.organisation_id
        if self.created_at:
            data["created_at"] = self.created_at.isoformat()
        if self.updated_at:
            data["updated_at"] = self.updated_at.isoformat()
            
        return data
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "User":
        created_at = None
        updated_at = None
        
        if data.get("created_at"):
            created_at = datetime.fromisoformat(data["created_at"].replace("Z", "+00:00"))
        if data.get("updated_at"):
            updated_at = datetime.fromisoformat(data["updated_at"].replace("Z", "+00:00"))
        
        return cls(
            id=data.get("id"),
            organisation_id=data.get("organisation_id"),
            username=data["username"],
            email=data["email"],
            role=data["role"],
            is_active=data.get("is_active", True),
            created_at=created_at,
            updated_at=updated_at,
        )


@dataclass_json
@dataclass
class ComponentHealth:
    """Component health status."""
    status: str
    message: str
    timestamp: datetime
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ComponentHealth":
        return cls(
            status=data["status"],
            message=data["message"],
            timestamp=datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00")),
        )


@dataclass_json
@dataclass
class SystemHealth:
    """System health status."""
    status: str
    components: Dict[str, ComponentHealth]
    timestamp: datetime
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SystemHealth":
        components = {}
        for name, component_data in data["components"].items():
            components[name] = ComponentHealth.from_dict(component_data)
        
        return cls(
            status=data["status"],
            components=components,
            timestamp=datetime.fromisoformat(data["timestamp"].replace("Z", "+00:00")),
        )


@dataclass_json
@dataclass
class UsageAnalytics:
    """API usage analytics."""
    total_requests: int
    success_rate: float
    avg_response_time: float
    start_time: datetime
    end_time: datetime
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UsageAnalytics":
        return cls(
            total_requests=data["total_requests"],
            success_rate=data["success_rate"],
            avg_response_time=data["avg_response_time"],
            start_time=datetime.fromisoformat(data["start_time"].replace("Z", "+00:00")),
            end_time=datetime.fromisoformat(data["end_time"].replace("Z", "+00:00")),
        )