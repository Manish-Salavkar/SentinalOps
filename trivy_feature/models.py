from sqlalchemy import Column, Integer, String, DateTime, ForeignKey, Boolean
from sqlalchemy.orm import declarative_base, relationship
from datetime import datetime

Base = declarative_base()

class ScanRun(Base):
    """
    Represents a single execution of a Trivy scan.
    """
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True, index=True)
    report_id = Column(String, unique=True, index=True, nullable=False)
    trivy_version = Column(String, nullable=False)
    artifact_name = Column(String, nullable=False)  # e.g., "vuln_app:latest"
    artifact_type = Column(String)                  # e.g., "container_image"
    os_family = Column(String)                      # e.g., "debian"
    os_name = Column(String)                        # e.g., "13.3"
    created_at = Column(DateTime, default=datetime.utcnow)

    # One-to-Many relationship: One scan run has many vulnerabilities
    vulnerabilities = relationship("VulnerabilityRecord", back_populates="scan", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<ScanRun(artifact={self.artifact_name}, date={self.created_at})>"


class VulnerabilityRecord(Base):
    """
    Represents an individual vulnerability found during a specific scan.
    """
    __tablename__ = "vulnerabilities"

    id = Column(Integer, primary_key=True, index=True)
    scan_id = Column(Integer, ForeignKey("scan_runs.id"), nullable=False)
    
    # Core Vulnerability Data
    vulnerability_id = Column(String, index=True, nullable=False)  # e.g., CVE-2026-24049
    pkg_name = Column(String, nullable=False)
    installed_version = Column(String, nullable=False)
    fixed_version = Column(String)
    severity = Column(String, index=True, nullable=False)          # e.g., HIGH, CRITICAL
    
    # Optional tracking flag for your diffing logic
    is_remediated = Column(Boolean, default=False) 

    # Relationship back to the parent scan
    scan = relationship("ScanRun", back_populates="vulnerabilities")

    def __repr__(self):
        return f"<Vulnerability(id={self.vulnerability_id}, pkg={self.pkg_name}, severity={self.severity})>"