from pydantic import BaseModel, EmailStr, Field, ConfigDict
from datetime import datetime
from typing import Optional, Any, Literal

class Token(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    role: str
    username: str

class UserCreate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=50, pattern=r"^[A-Za-z0-9_.-]+$")
    email: EmailStr
    # bcrypt only uses the first 72 bytes; cap length to avoid silent truncation.
    password: str = Field(min_length=12, max_length=72)


class UserAdminCreate(UserCreate):
    role: Literal["Admin", "Analyst", "User"] = "User"


class UserAdminUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    role: Optional[Literal["Admin", "Analyst", "User"]] = None
    is_active: Optional[bool] = None

class UserOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id: int
    username: str
    # Plain str on output: stored addresses were validated on input, and
    # re-validating here made reserved demo domains (e.g. *.local) crash with 500.
    email: str
    role: str
    is_active: bool
    created_at: datetime

class ActivityCreate(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False, extra="forbid")
    action_type: Literal["LOGIN", "LOGOUT", "FILE_ACCESS", "FILE_READ", "DATA_TRANSFER",
                         "PRIVILEGE_USE", "DOCUMENT_QUERY", "EMAIL_SEND", "DEVICE_CONNECT"]
    bytes_transferred: float = Field(default=0.0, ge=0, le=1e9)
    is_sensitive_file: bool = False
    failed_attempts: int = Field(default=0, ge=0, le=1000)
    privilege_level: int = Field(default=0, ge=0, le=2)
    session_duration_sec: float = Field(default=0.0, ge=0, le=86400)

class ActivityOut(BaseModel):
    id: int
    user_id: int
    timestamp: datetime
    action_type: str
    bytes_transferred: float
    is_sensitive_file: bool
    failed_attempts: int
    model_config = ConfigDict(from_attributes=True)

class TelemetryVector(BaseModel):
    model_config = ConfigDict(allow_inf_nan=False, extra="forbid")
    login_hour: float = Field(ge=0, lt=24)
    files_accessed: float = Field(ge=0, le=1e6)
    sensitive_files_accessed: float = Field(ge=0, le=1e6)
    bytes_transferred_mb: float = Field(ge=0, le=1e9)
    failed_logins: float = Field(ge=0, le=1e6)
    privilege_level: float = Field(ge=0, le=2)
    session_duration_min: float = Field(ge=0, le=1440)

class SimulationTrigger(BaseModel):
    user_id: int = Field(ge=1)
    scenario: Literal["NORMAL", "DATA_EXFILTRATION", "ABNORMAL_HOURS", "ADAPTIVE_EVASION"]
    iterations: int = Field(default=8, ge=1, le=50)
    seed: int = Field(default=0, ge=0, le=2147483647)

class AnalysisResponse(BaseModel):
    user_id: int
    risk_score: float
    iforest_anomaly: bool
    ocsvm_anomaly: bool
    game_action: str
    top_explanations: dict[str, float]
    details: dict[str, Any]
    adaptive_metrics: dict[str, Any]
