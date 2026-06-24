"""
Sentinel AI - SQLAlchemy ORM Models
"""
from sqlalchemy import (
    Column, BigInteger, String, Text, SmallInteger, Integer,
    DECIMAL, TIMESTAMP, Enum, JSON, ForeignKey, func
)
from sqlalchemy.dialects.mysql import TINYINT
from sqlalchemy.orm import relationship
from app.core.database import Base


class Role(Base):
    __tablename__ = "roles"
    id          = Column(BigInteger, primary_key=True, autoincrement=True)
    name        = Column(String(50), nullable=False, unique=True)
    description = Column(String(255))
    created_at  = Column(TIMESTAMP, server_default=func.now())
    updated_at  = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
    users       = relationship("User", back_populates="role")


class User(Base):
    __tablename__ = "users"
    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    role_id    = Column(BigInteger, ForeignKey("roles.id"), nullable=False)
    name       = Column(String(150), nullable=False)
    email      = Column(String(255), nullable=False, unique=True)
    password   = Column(String(255), nullable=False)
    avatar     = Column(String(500))
    is_active  = Column(TINYINT(1), nullable=False, default=1)
    last_login = Column(TIMESTAMP)
    deleted_at = Column(TIMESTAMP)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
    role       = relationship("Role", back_populates="users")
    websites   = relationship("Website", back_populates="user")
    scans      = relationship("Scan", back_populates="user")


class Website(Base):
    __tablename__ = "websites"
    id           = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id      = Column(BigInteger, ForeignKey("users.id"), nullable=False)
    name         = Column(String(150), nullable=False)
    url          = Column(String(500), nullable=False)
    domain       = Column(String(255))
    category     = Column(String(100))
    description  = Column(Text)
    status       = Column(Enum("active","inactive","suspended"), default="active")
    last_scan_at = Column(TIMESTAMP)
    deleted_at   = Column(TIMESTAMP)
    created_at   = Column(TIMESTAMP, server_default=func.now())
    updated_at   = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
    user         = relationship("User", back_populates="websites")
    scans        = relationship("Scan", back_populates="website")


class Scan(Base):
    __tablename__ = "scans"
    id               = Column(BigInteger, primary_key=True, autoincrement=True)
    website_id       = Column(BigInteger, ForeignKey("websites.id"), nullable=False)
    user_id          = Column(BigInteger, ForeignKey("users.id"), nullable=False)
    mode             = Column(Enum("quick","standard","full"), default="standard")
    status           = Column(Enum("pending","running","paused","completed","cancelled","failed"), default="pending")
    max_depth        = Column(Integer, default=5)
    max_pages        = Column(Integer, default=1000)
    timeout_ms       = Column(Integer, default=10000)
    security_score   = Column(DECIMAL(5,2))
    grade            = Column(String(1))
    risk_level       = Column(Enum("critical","high","medium","low","safe"))
    total_pages      = Column(Integer, default=0)
    total_endpoints  = Column(Integer, default=0)
    total_findings   = Column(Integer, default=0)
    critical_count   = Column(Integer, default=0)
    high_count       = Column(Integer, default=0)
    medium_count     = Column(Integer, default=0)
    low_count        = Column(Integer, default=0)
    started_at       = Column(TIMESTAMP)
    completed_at     = Column(TIMESTAMP)
    duration_seconds = Column(Integer)
    error_message    = Column(Text)
    created_at       = Column(TIMESTAMP, server_default=func.now())
    updated_at       = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
    website          = relationship("Website", back_populates="scans")
    user             = relationship("User", back_populates="scans")
    logs             = relationship("ScanLog", back_populates="scan", cascade="all, delete-orphan")
    pages            = relationship("Page", back_populates="scan", cascade="all, delete-orphan")
    endpoints        = relationship("Endpoint", back_populates="scan", cascade="all, delete-orphan")
    technologies     = relationship("Technology", back_populates="scan", cascade="all, delete-orphan")
    predictions      = relationship("AIPrediction", back_populates="scan", cascade="all, delete-orphan")
    recommendations  = relationship("Recommendation", back_populates="scan", cascade="all, delete-orphan")
    progress         = relationship("ScanProgress", back_populates="scan", uselist=False, cascade="all, delete-orphan")


class ScanLog(Base):
    __tablename__ = "scan_logs"
    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id    = Column(BigInteger, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    level      = Column(Enum("info","warning","error","debug"), default="info")
    agent      = Column(String(100))
    message    = Column(Text, nullable=False)
    meta_data  = Column("metadata", JSON)
    created_at = Column(TIMESTAMP, server_default=func.now())
    scan       = relationship("Scan", back_populates="logs")


class Page(Base):
    __tablename__ = "pages"
    id              = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id         = Column(BigInteger, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    url             = Column(String(2000), nullable=False)
    title           = Column(String(500))
    status_code     = Column(SmallInteger)
    response_time   = Column(Integer)
    content_length  = Column(Integer)
    content_type    = Column(String(200))
    depth           = Column(Integer, default=0)
    has_form        = Column(TINYINT(1), default=0)
    has_login       = Column(TINYINT(1), default=0)
    has_upload      = Column(TINYINT(1), default=0)
    screenshot_path = Column(String(500))
    created_at      = Column(TIMESTAMP, server_default=func.now())
    scan            = relationship("Scan", back_populates="pages")
    forms           = relationship("Form", back_populates="page", cascade="all, delete-orphan")


class Form(Base):
    __tablename__ = "forms"
    id           = Column(BigInteger, primary_key=True, autoincrement=True)
    page_id      = Column(BigInteger, ForeignKey("pages.id", ondelete="CASCADE"), nullable=False)
    scan_id      = Column(BigInteger, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    action       = Column(String(1000))
    method       = Column(Enum("GET","POST","PUT","PATCH","DELETE"), default="POST")
    has_password = Column(TINYINT(1), default=0)
    has_file     = Column(TINYINT(1), default=0)
    has_hidden   = Column(TINYINT(1), default=0)
    input_count  = Column(Integer, default=0)
    form_type    = Column(String(100))
    raw_html     = Column(Text)
    created_at   = Column(TIMESTAMP, server_default=func.now())
    page         = relationship("Page", back_populates="forms")


class Endpoint(Base):
    __tablename__ = "endpoints"
    id             = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id        = Column(BigInteger, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    url            = Column(String(2000), nullable=False)
    method         = Column(Enum("GET","POST","PUT","PATCH","DELETE","HEAD","OPTIONS"), default="GET")
    endpoint_type  = Column(Enum("page","api","static","form","redirect"), default="page")
    priority_score = Column(SmallInteger, default=0)
    has_auth       = Column(TINYINT(1), default=0)
    has_params     = Column(TINYINT(1), default=0)
    param_count    = Column(Integer, default=0)
    status_code    = Column(SmallInteger)
    response_time  = Column(Integer)
    created_at     = Column(TIMESTAMP, server_default=func.now())
    scan           = relationship("Scan", back_populates="endpoints")
    predictions    = relationship("AIPrediction", back_populates="endpoint")


class Technology(Base):
    __tablename__ = "technologies"
    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id    = Column(BigInteger, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    name       = Column(String(150), nullable=False)
    version    = Column(String(100))
    category   = Column(String(100))
    confidence = Column(SmallInteger, default=0)
    source     = Column(String(100))
    created_at = Column(TIMESTAMP, server_default=func.now())
    scan       = relationship("Scan", back_populates="technologies")


class MLModel(Base):
    __tablename__ = "ml_models"
    id              = Column(BigInteger, primary_key=True, autoincrement=True)
    name            = Column(String(150), nullable=False)
    algorithm       = Column(Enum("random_forest","xgboost","decision_tree","svm"), nullable=False)
    version         = Column(String(50), default="1.0")
    file_path       = Column(String(500))
    accuracy        = Column(DECIMAL(6,4))
    precision_score = Column(DECIMAL(6,4))
    recall_score    = Column(DECIMAL(6,4))
    f1_score        = Column(DECIMAL(6,4))
    roc_auc         = Column(DECIMAL(6,4))
    training_time   = Column(DECIMAL(10,3))
    sample_count    = Column(Integer)
    feature_count   = Column(Integer)
    is_active       = Column(TINYINT(1), default=0)
    status          = Column(Enum("training","ready","failed","archived"), default="ready")
    trained_at      = Column(TIMESTAMP)
    created_at      = Column(TIMESTAMP, server_default=func.now())
    updated_at      = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())


class Dataset(Base):
    __tablename__ = "datasets"
    id           = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id      = Column(BigInteger, ForeignKey("users.id"), nullable=False)
    name         = Column(String(255), nullable=False)
    description  = Column(Text)
    file_path    = Column(String(500))
    file_size    = Column(BigInteger)
    sample_count = Column(Integer)
    version      = Column(String(50), default="1.0")
    status       = Column(Enum("pending","processing","ready","failed"), default="pending")
    deleted_at   = Column(TIMESTAMP)
    created_at   = Column(TIMESTAMP, server_default=func.now())
    updated_at   = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())


class AIPrediction(Base):
    __tablename__ = "ai_predictions"
    id               = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id          = Column(BigInteger, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    endpoint_id      = Column(BigInteger, ForeignKey("endpoints.id", ondelete="SET NULL"))
    ml_model_id      = Column(BigInteger, ForeignKey("ml_models.id", ondelete="SET NULL"))
    prediction       = Column(String(150), nullable=False)
    confidence       = Column(DECIMAL(5,2), default=0)
    probability      = Column(JSON)
    severity         = Column(Enum("critical","high","medium","low","info"), default="info")
    owasp_category   = Column(String(100))
    cwe_id           = Column(String(50))
    is_verified      = Column(TINYINT(1), default=0)
    is_false_positive = Column(TINYINT(1), default=0)
    evidence         = Column(JSON)
    created_at       = Column(TIMESTAMP, server_default=func.now())
    scan             = relationship("Scan", back_populates="predictions")
    endpoint         = relationship("Endpoint", back_populates="predictions")


class Recommendation(Base):
    __tablename__ = "recommendations"
    id            = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id       = Column(BigInteger, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    prediction_id = Column(BigInteger, ForeignKey("ai_predictions.id", ondelete="SET NULL"))
    title         = Column(String(500), nullable=False)
    summary       = Column(Text)
    cause         = Column(Text)
    impact        = Column(Text)
    solution      = Column(Text)
    priority      = Column(Enum("critical","high","medium","low"), default="medium")
    owasp_ref     = Column(String(100))
    cwe_ref       = Column(String(100))
    cvss_score    = Column(DECIMAL(4,2))
    affected_url  = Column(String(2000))
    checklist     = Column(JSON)
    created_at    = Column(TIMESTAMP, server_default=func.now())
    scan          = relationship("Scan", back_populates="recommendations")


class Report(Base):
    __tablename__ = "reports"
    id                = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id           = Column(BigInteger, ForeignKey("scans.id"), nullable=False)
    user_id           = Column(BigInteger, ForeignKey("users.id"), nullable=False)
    title             = Column(String(500))
    pdf_path          = Column(String(500))
    json_path         = Column(String(500))
    csv_path          = Column(String(500))
    executive_summary = Column(Text)
    security_score    = Column(DECIMAL(5,2))
    grade             = Column(String(1))
    risk_level        = Column(Enum("critical","high","medium","low","safe"))
    generated_at      = Column(TIMESTAMP)
    deleted_at        = Column(TIMESTAMP)
    created_at        = Column(TIMESTAMP, server_default=func.now())
    updated_at        = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())


class AIChatSession(Base):
    __tablename__ = "ai_chat_sessions"
    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id    = Column(BigInteger, ForeignKey("users.id"), nullable=False)
    scan_id    = Column(BigInteger, ForeignKey("scans.id", ondelete="SET NULL"))
    title      = Column(String(255), default="Sesi Baru")
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
    messages   = relationship("AIChatMessage", back_populates="session", cascade="all, delete-orphan")


class AIChatMessage(Base):
    __tablename__ = "ai_chat_messages"
    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    session_id = Column(BigInteger, ForeignKey("ai_chat_sessions.id", ondelete="CASCADE"), nullable=False)
    role       = Column(Enum("user","assistant"), nullable=False)
    content    = Column(Text, nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())
    session    = relationship("AIChatSession", back_populates="messages")


class AIMemory(Base):
    __tablename__ = "ai_memory"
    id             = Column(BigInteger, primary_key=True, autoincrement=True)
    website_id     = Column(BigInteger, ForeignKey("websites.id"), nullable=False)
    scan_id        = Column(BigInteger, ForeignKey("scans.id"), nullable=False)
    security_score = Column(DECIMAL(5,2))
    grade          = Column(String(1))
    risk_level     = Column(String(20))
    total_findings = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count     = Column(Integer, default=0)
    medium_count   = Column(Integer, default=0)
    low_count      = Column(Integer, default=0)
    technologies   = Column(JSON)
    top_risks      = Column(JSON)
    created_at     = Column(TIMESTAMP, server_default=func.now())


class ActivityLog(Base):
    __tablename__ = "activity_logs"
    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id    = Column(BigInteger, ForeignKey("users.id", ondelete="SET NULL"))
    action     = Column(String(150), nullable=False)
    entity     = Column(String(100))
    entity_id  = Column(BigInteger)
    ip_address = Column(String(50))
    user_agent = Column(Text)
    meta_data  = Column("metadata", JSON)
    created_at = Column(TIMESTAMP, server_default=func.now())


class Notification(Base):
    __tablename__ = "notifications"
    id         = Column(BigInteger, primary_key=True, autoincrement=True)
    user_id    = Column(BigInteger, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    type       = Column(String(100), nullable=False)
    title      = Column(String(255), nullable=False)
    body       = Column(Text)
    data       = Column(JSON)
    is_read    = Column(TINYINT(1), default=0)
    read_at    = Column(TIMESTAMP)
    created_at = Column(TIMESTAMP, server_default=func.now())


class Setting(Base):
    __tablename__ = "settings"
    id          = Column(BigInteger, primary_key=True, autoincrement=True)
    key_name    = Column(String(150), nullable=False, unique=True)
    value       = Column(Text)
    type        = Column(Enum("string","integer","boolean","json"), default="string")
    group_name  = Column(String(100))
    description = Column(String(500))
    created_at  = Column(TIMESTAMP, server_default=func.now())
    updated_at  = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())


class ScanProgress(Base):
    __tablename__ = "scan_progress"
    id               = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id          = Column(BigInteger, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False, unique=True)
    current_agent    = Column(String(100))
    percentage       = Column(SmallInteger, default=0)
    discovery_pct    = Column(SmallInteger, default=0)
    technology_pct   = Column(SmallInteger, default=0)
    endpoint_pct     = Column(SmallInteger, default=0)
    scanner_pct      = Column(SmallInteger, default=0)
    verification_pct = Column(SmallInteger, default=0)
    report_pct       = Column(SmallInteger, default=0)
    pages_found      = Column(Integer, default=0)
    endpoints_found  = Column(Integer, default=0)
    requests_sent    = Column(Integer, default=0)
    updated_at       = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
    scan             = relationship("Scan", back_populates="progress")
    

class ScanQueue(Base):
    __tablename__ = "scan_queue"
    id           = Column(BigInteger, primary_key=True, autoincrement=True)
    scan_id      = Column(BigInteger, ForeignKey("scans.id", ondelete="CASCADE"), nullable=False)
    status       = Column(Enum("pending","running","waiting","completed","failed","cancelled"), default="pending")
    priority     = Column(SmallInteger, default=5)
    attempts     = Column(SmallInteger, default=0)
    max_attempts = Column(SmallInteger, default=3)
    payload      = Column(JSON)
    error        = Column(Text)
    started_at   = Column(TIMESTAMP)
    completed_at = Column(TIMESTAMP)
    created_at   = Column(TIMESTAMP, server_default=func.now())
    updated_at   = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())
    scan         = relationship("Scan")
