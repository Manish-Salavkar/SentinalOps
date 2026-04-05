from pydantic import BaseModel, Field
from typing import List, Optional, Any
from datetime import datetime

class TrivyInfo(BaseModel):
    Version: str

class OSInfo(BaseModel):
    Family: str
    Name: str

class Metadata(BaseModel):
    Size: Optional[int] = None
    OS: Optional[OSInfo] = None
    ImageID: Optional[str] = None
    RepoTags: Optional[List[str]] = []

class Vulnerability(BaseModel):
    VulnerabilityID: str
    PkgName: str
    InstalledVersion: str
    FixedVersion: Optional[str] = None
    Title: Optional[str] = None
    Description: Optional[str] = None
    Severity: str
    # You can add CVSS or References here if you want to expand later

class Result(BaseModel):
    Target: str
    Class: str
    Type: Optional[str] = None
    Vulnerabilities: Optional[List[Vulnerability]] = []

class TrivyReport(BaseModel):
    SchemaVersion: int
    Trivy: TrivyInfo
    ReportID: str
    CreatedAt: datetime
    ArtifactID: str
    ArtifactName: str
    ArtifactType: str
    Metadata: Optional[Metadata] = None
    Results: List[Result] = []