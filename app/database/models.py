from datetime import datetime
from typing import Optional
from sqlalchemy import String, Integer, DateTime, Text, ForeignKey, Float
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

class Base(DeclarativeBase):
    pass

class ScanModel(Base):
    __tablename__ = "scans"

    scan_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    target: Mapped[str] = mapped_column(String(255), nullable=False)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    status: Mapped[str] = mapped_column(String(50), default="IN_PROGRESS")
    
    pages_discovered: Mapped[int] = mapped_column(Integer, default=0)
    requests_made: Mapped[int] = mapped_column(Integer, default=0)
    findings_count: Mapped[int] = mapped_column(Integer, default=0)
    
    findings = relationship("FindingModel", back_populates="scan", cascade="all, delete-orphan")
    pages = relationship("PageModel", back_populates="scan", cascade="all, delete-orphan")

class FindingModel(Base):
    __tablename__ = "findings"

    finding_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.scan_id"))
    
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    category: Mapped[str] = mapped_column(String(100), nullable=False)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    method: Mapped[str] = mapped_column(String(10), nullable=False)
    parameter: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    
    severity: Mapped[str] = mapped_column(String(50), nullable=False)
    confidence: Mapped[str] = mapped_column(String(50), nullable=False)
    
    evidence: Mapped[str] = mapped_column(Text, nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    remediation: Mapped[str] = mapped_column(Text, nullable=False)
    scanner_source: Mapped[str] = mapped_column(String(100), nullable=False)
    
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    # Deduplication hash could be added here in the future
    
    scan = relationship("ScanModel", back_populates="findings")

class PageModel(Base):
    __tablename__ = "pages"

    page_id: Mapped[str] = mapped_column(String(36), primary_key=True)
    scan_id: Mapped[str] = mapped_column(String(36), ForeignKey("scans.scan_id"))
    
    url: Mapped[str] = mapped_column(Text, nullable=False)
    status_code: Mapped[int] = mapped_column(Integer, nullable=False)
    content_type: Mapped[str] = mapped_column(String(255), nullable=False)
    depth: Mapped[int] = mapped_column(Integer, nullable=False)
    
    discovered_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    
    scan = relationship("ScanModel", back_populates="pages")
