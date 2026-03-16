"""
SQLAlchemy ORM Models for CyberGuard
"""
import enum
from datetime import datetime
from typing import List, Optional
from sqlalchemy import (
    String, Boolean, DateTime, Float, Integer, Text, JSON,
    ForeignKey, Enum, ARRAY, func
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    CLIENT = "CLIENT"


class ScanStatus(str, enum.Enum):
    PENDING = "PENDING"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class ScanType(str, enum.Enum):
    QUICK = "QUICK"
    FULL = "FULL"
    CUSTOM = "CUSTOM"


class Severity(str, enum.Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class SubscriptionPlan(str, enum.Enum):
    FREE = "FREE"
    MONTHLY = "MONTHLY"
    PREMIUM = "PREMIUM"


class SubscriptionStatus(str, enum.Enum):
    ACTIVE = "ACTIVE"
    INACTIVE = "INACTIVE"
    TRIAL = "TRIAL"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"


class AlertType(str, enum.Enum):
    SSL_EXPIRY = "SSL_EXPIRY"
    DOMAIN_EXPIRY = "DOMAIN_EXPIRY"
    PORT_CHANGE = "PORT_CHANGE"
    UPTIME = "UPTIME"
    VULNERABILITY = "VULNERABILITY"
    SECURITY = "SECURITY"


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    email: Mapped[str] = mapped_column(String, unique=True, index=True)
    name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    password: Mapped[str] = mapped_column(String)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.CLIENT)
    email_verified: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    phone: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    company: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    last_login_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())

    targets: Mapped[List["Target"]] = relationship("Target", back_populates="user")
    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="user")
    reports: Mapped[List["Report"]] = relationship("Report", back_populates="user")
    subscription: Mapped[Optional["Subscription"]] = relationship("Subscription", back_populates="user", uselist=False)
    alerts: Mapped[List["Alert"]] = relationship("Alert", back_populates="user")
    audit_logs: Mapped[List["AuditLog"]] = relationship("AuditLog", back_populates="user")
    notifications: Mapped[List["Notification"]] = relationship("Notification", back_populates="user")


class Target(Base):
    __tablename__ = "targets"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id", ondelete="CASCADE"))
    name: Mapped[str] = mapped_column(String)
    domain: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    url: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())

    user: Mapped["User"] = relationship("User", back_populates="targets")
    scans: Mapped[List["Scan"]] = relationship("Scan", back_populates="target")
    monitors: Mapped[List["Monitor"]] = relationship("Monitor", back_populates="target")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"))
    target_id: Mapped[str] = mapped_column(String, ForeignKey("targets.id"))
    type: Mapped[ScanType] = mapped_column(Enum(ScanType), default=ScanType.QUICK)
    status: Mapped[ScanStatus] = mapped_column(Enum(ScanStatus), default=ScanStatus.PENDING)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    queued_by: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())

    user: Mapped["User"] = relationship("User", back_populates="scans")
    target: Mapped["Target"] = relationship("Target", back_populates="scans")
    findings: Mapped[List["ScanFinding"]] = relationship("ScanFinding", back_populates="scan")
    report: Mapped[Optional["Report"]] = relationship("Report", back_populates="scan", uselist=False)


class ScanFinding(Base):
    __tablename__ = "scan_findings"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id", ondelete="CASCADE"))
    category: Mapped[str] = mapped_column(String)
    title: Mapped[str] = mapped_column(String)
    description: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    is_fixed: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    scan_id: Mapped[str] = mapped_column(String, ForeignKey("scans.id"), unique=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id"))
    title: Mapped[str] = mapped_column(String)
    executive_summary: Mapped[str] = mapped_column(Text)
    technical_findings: Mapped[dict] = mapped_column(JSON)
    recommendations: Mapped[dict] = mapped_column(JSON)
    risk_score: Mapped[float] = mapped_column(Float)
    critical_count: Mapped[int] = mapped_column(Integer, default=0)
    high_count: Mapped[int] = mapped_column(Integer, default=0)
    medium_count: Mapped[int] = mapped_column(Integer, default=0)
    low_count: Mapped[int] = mapped_column(Integer, default=0)
    info_count: Mapped[int] = mapped_column(Integer, default=0)
    pdf_path: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    generated_by_ai: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())

    scan: Mapped["Scan"] = relationship("Scan", back_populates="report")
    user: Mapped["User"] = relationship("User", back_populates="reports")


class Monitor(Base):
    __tablename__ = "monitors"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    target_id: Mapped[str] = mapped_column(String, ForeignKey("targets.id", ondelete="CASCADE"))
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    check_interval: Mapped[int] = mapped_column(Integer, default=86400)
    last_checked_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    next_check_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    ssl_expiry_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    domain_expiry_days: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    uptime_status: Mapped[Optional[bool]] = mapped_column(Boolean, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())

    target: Mapped["Target"] = relationship("Target", back_populates="monitors")
    check_logs: Mapped[List["MonitorLog"]] = relationship("MonitorLog", back_populates="monitor")


class MonitorLog(Base):
    __tablename__ = "monitor_logs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    monitor_id: Mapped[str] = mapped_column(String, ForeignKey("monitors.id", ondelete="CASCADE"))
    check_type: Mapped[str] = mapped_column(String)
    status: Mapped[str] = mapped_column(String)
    message: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    checked_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    monitor: Mapped["Monitor"] = relationship("Monitor", back_populates="check_logs")


class Alert(Base):
    __tablename__ = "alerts"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id", ondelete="CASCADE"))
    type: Mapped[AlertType] = mapped_column(Enum(AlertType))
    title: Mapped[str] = mapped_column(String)
    message: Mapped[str] = mapped_column(Text)
    severity: Mapped[Severity] = mapped_column(Enum(Severity))
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    sent_email: Mapped[bool] = mapped_column(Boolean, default=False)
    sent_telegram: Mapped[bool] = mapped_column(Boolean, default=False)
    metadata: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    user: Mapped["User"] = relationship("User", back_populates="alerts")


class Subscription(Base):
    __tablename__ = "subscriptions"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id", ondelete="CASCADE"), unique=True)
    plan: Mapped[SubscriptionPlan] = mapped_column(Enum(SubscriptionPlan), default=SubscriptionPlan.FREE)
    status: Mapped[SubscriptionStatus] = mapped_column(Enum(SubscriptionStatus), default=SubscriptionStatus.ACTIVE)
    current_period_start: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    current_period_end: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    cancel_at_period_end: Mapped[bool] = mapped_column(Boolean, default=False)
    payment_provider: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    payment_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    scans_used: Mapped[int] = mapped_column(Integer, default=0)
    scans_limit: Mapped[int] = mapped_column(Integer, default=3)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())

    user: Mapped["User"] = relationship("User", back_populates="subscription")


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[str] = mapped_column(String, ForeignKey("users.id", ondelete="CASCADE"))
    title: Mapped[str] = mapped_column(String)
    message: Mapped[str] = mapped_column(String)
    type: Mapped[str] = mapped_column(String)
    is_read: Mapped[bool] = mapped_column(Boolean, default=False)
    link: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    user: Mapped["User"] = relationship("User", back_populates="notifications")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String, primary_key=True)
    user_id: Mapped[Optional[str]] = mapped_column(String, ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String)
    resource: Mapped[str] = mapped_column(String)
    resource_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    details: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    ip_address: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=func.now())

    user: Mapped[Optional["User"]] = relationship("User", back_populates="audit_logs")
