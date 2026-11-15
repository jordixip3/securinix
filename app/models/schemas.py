"""
Securinix Data Schemas & Models
Pydantic schemas for Network Events, Detection Rules, Incidents, SOAR Playbooks, and Telemetry.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
import time

class NetworkEvent(BaseModel):
    id: str
    timestamp: float = Field(default_factory=time.time)
    timestamp_iso: str = ""
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str  # TCP, UDP, ICMP, DNS, HTTP, TLS, SSH, SMB, RDP
    length: int
    flags: str = ""
    service: str = "Unknown"
    payload_preview: str = ""
    geo_src: str = "Unknown"
    geo_dst: str = "Internal"
    anomaly_score: float = 0.0
    matched_rules: List[str] = []

class DetectionRule(BaseModel):
    id: str
    name: str
    description: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # Reconnaissance, Credential Access, Defense Evasion, Exfiltration, Lateral Movement, DoS, Malware/C2, Policy Violation
    mitre_tactic: str  # e.g., TA0001, TA0006, TA0010
    mitre_technique: str  # e.g., T1046, T1110, T1048
    protocol: Optional[str] = "ANY"  # ANY, TCP, UDP, ICMP, DNS, HTTP, SSH, etc.
    dst_port: Optional[int] = None  # None = any port
    threshold: int = 5  # Occurrences required within window
    window_seconds: int = 15  # Sliding window duration
    condition_type: str = "rate"  # rate, signature, payload_match, port_scan, ueba_anomaly
    pattern: Optional[str] = None  # Optional payload/signature regex
    enabled: bool = True
    action: str = "create_incident"  # alert_only, create_incident, auto_isolate, auto_block
    created_at: float = Field(default_factory=time.time)

class IncidentNote(BaseModel):
    id: str
    timestamp: float = Field(default_factory=time.time)
    author: str
    content: str

class IncidentAudit(BaseModel):
    timestamp: float = Field(default_factory=time.time)
    action: str
    details: str
    status: str = "Success"

class Incident(BaseModel):
    id: str
    title: str
    description: str
    rule_id: str
    rule_name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    risk_score: int = Field(ge=0, le=100)  # 0 to 100
    status: str = "New"  # New, Investigating, Contained, Resolved, False_Positive
    src_ip: str
    dst_ip: str
    affected_asset: str = ""
    event_count: int = 1
    first_seen: float = Field(default_factory=time.time)
    last_seen: float = Field(default_factory=time.time)
    mitre_tactic: str = ""
    mitre_technique: str = ""
    recommended_playbook: str = "isolate_host"
    playbook_executed: bool = False
    playbook_results: List[Dict[str, Any]] = []
    notes: List[IncidentNote] = []
    audit_trail: List[IncidentAudit] = []
    sample_events: List[Dict[str, Any]] = []

class PlaybookExecutionRequest(BaseModel):
    incident_id: str
    playbook_id: str  # isolate_host, block_ip, revoke_session, capture_forensics, generate_report
    parameters: Optional[Dict[str, Any]] = None

class RuleToggleRequest(BaseModel):
    enabled: bool

class RuleUpdateRequest(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[str] = None
    category: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    protocol: Optional[str] = None
    dst_port: Optional[int] = None
    threshold: Optional[int] = None
    window_seconds: Optional[int] = None
    action: Optional[str] = None
    enabled: Optional[bool] = None

class SimulationRequest(BaseModel):
    scenario: str  # port_scan, brute_force, c2_beacon, data_exfil, ddos_syn_flood, ransomware_burst, normal_traffic
    intensity: str = "medium"  # low, medium, high, extreme
    duration_seconds: int = 30
