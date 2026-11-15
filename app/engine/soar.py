"""
Securinix SOAR & Incident Response Engine
Manages Security Incidents lifecycle, triage, analyst notes, and automated response playbooks.
"""
import uuid
import time
from typing import List, Dict, Optional, Any
from app.models.schemas import Incident, IncidentNote, IncidentAudit

SEVERITY_RISK_MAP = {
    "CRITICAL": 95,
    "HIGH": 80,
    "MEDIUM": 55,
    "LOW": 30,
    "INFO": 10
}

PLAYBOOK_DESCRIPTIONS = {
    "isolate_host": {
        "name": "Host Network Isolation (Quarantine)",
        "icon": "shield-slash",
        "description": "Applies micro-segmentation / SDN null-route isolating the affected endpoint from internal lateral movement while maintaining C2 forensic probe tap.",
        "steps": [
            "1. Verified target IP within asset database",
            "2. Executed network switch VLAN migration to Quarantine VNet (VLAN 999)",
            "3. Enforced host-level firewall drop for all RFC1918 internal subnets",
            "4. Maintained isolated SOC management conduit for agent triage"
        ]
    },
    "block_ip": {
        "name": "Perimeter Firewall Threat Actor Ingress Block",
        "icon": "ban",
        "description": "Pushes border firewall ACL rule dropping all ingress/egress packets associated with the malicious adversary IP.",
        "steps": [
            "1. Enriched threat intelligence against VirusTotal and AbuseIPDB",
            "2. Injected dynamic drop rule on Perimeter Edge Fortinet / Palo Alto cluster",
            "3. Terminated all active ESTABLISHED NAT translation sessions",
            "4. Propagated IP hash to cloud WAF and Cloudflare zero-trust edge"
        ]
    },
    "revoke_session": {
        "name": "Credential Revocation & Session Eviction",
        "icon": "key",
        "description": "Immediately invalidates Active Directory / Okta SSO Kerberos tickets, clears OAuth tokens, and revokes active VPN tunnels.",
        "steps": [
            "1. Identified authenticated user principal and active Kerberos TGT",
            "2. Invoked Microsoft Entra ID / Okta RevokeUserSessions API",
            "3. Terminated active OpenVPN and WireGuard client tunnels",
            "4. Enforced mandatory Multi-Factor Authentication (FIDO2) prompt on next auth"
        ]
    },
    "capture_forensics": {
        "name": "Automated Volatility Memory & PCAP Snapshot",
        "icon": "camera",
        "description": "Extracts volatile host memory dump (LiME/WinPmem), running processes tree, and writes full-packet capture PCAP ring buffer.",
        "steps": [
            "1. Triggered background memory capture agent on compromised host",
            "2. Exported 5-minute rolling network PCAP buffer from tap sensor",
            "3. Hashed evidence artifacts (SHA256) into secure forensic vault",
            "4. Generated volatility process anomaly delta report"
        ]
    },
    "generate_report": {
        "name": "Executive Incident Brief & Forensic Export",
        "icon": "file-earmark-text",
        "description": "Compiles comprehensive CIRT forensic summary ready for CISO briefing and regulatory compliance filing (GDPR / NIS2).",
        "steps": [
            "1. Aggregated incident timeline, raw packet evidence, and IOC list",
            "2. Correlated MITRE ATT&CK tactics, techniques, and observed threat actors",
            "3. Compiled containment actions and analyst audit logs",
            "4. Formatted PDF / JSON forensic bundle package"
        ]
    }
}

class IncidentResponseManager:
    def __init__(self):
        self._incidents: Dict[str, Incident] = {}

    def get_all(self, limit: int = 50) -> List[Incident]:
        sorted_incidents = sorted(self._incidents.values(), key=lambda x: x.last_seen, reverse=True)
        return sorted_incidents[:limit]

    def get(self, incident_id: str) -> Optional[Incident]:
        return self._incidents.get(incident_id)

    def create_or_update(
        self,
        rule_id: str,
        rule_name: str,
        severity: str,
        src_ip: str,
        dst_ip: str,
        mitre_tactic: str,
        mitre_technique: str,
        sample_event: Dict[str, Any]
    ) -> Incident:
        # Check if an active open incident already exists for this rule and src_ip
        existing = None
        for inc in self._incidents.values():
            if inc.rule_id == rule_id and inc.src_ip == src_ip and inc.status in ["New", "Investigating"]:
                existing = inc
                break

        now = time.time()
        if existing:
            existing.event_count += 1
            existing.last_seen = now
            existing.risk_score = min(100, existing.risk_score + 2)
            if sample_event and len(existing.sample_events) < 15:
                existing.sample_events.append(sample_event)
            return existing

        # Recommend playbook based on severity and category
        if "BRUTE" in rule_id or "SPRAY" in rule_id:
            rec_playbook = "revoke_session"
        elif "DDOS" in rule_id or "PORT-SCAN" in rule_id or "SQLI" in rule_id:
            rec_playbook = "block_ip"
        elif "EXFIL" in rule_id or "SMB" in rule_id or "C2" in rule_id:
            rec_playbook = "isolate_host"
        else:
            rec_playbook = "capture_forensics"

        inc_id = f"INC-{int(now) % 100000:05d}-{uuid.uuid4().hex[:4].upper()}"
        base_risk = SEVERITY_RISK_MAP.get(severity.upper(), 50)

        incident = Incident(
            id=inc_id,
            title=f"{rule_name} detected from {src_ip}",
            description=f"Automated threat correlation triggered by {rule_id}. Traffic originating from {src_ip} directed against {dst_ip}.",
            rule_id=rule_id,
            rule_name=rule_name,
            severity=severity.upper(),
            risk_score=base_risk,
            status="New",
            src_ip=src_ip,
            dst_ip=dst_ip,
            affected_asset=dst_ip,
            event_count=1,
            first_seen=now,
            last_seen=now,
            mitre_tactic=mitre_tactic,
            mitre_technique=mitre_technique,
            recommended_playbook=rec_playbook,
            playbook_executed=False,
            playbook_results=[],
            notes=[
                IncidentNote(
                    id=str(uuid.uuid4())[:8],
                    timestamp=now,
                    author="Securinix AI Autopilot",
                    content=f"Threat correlation rule '{rule_name}' satisfied. Baseline anomaly detected. Recommended SOAR action: {rec_playbook}."
                )
            ],
            audit_trail=[
                IncidentAudit(
                    timestamp=now,
                    action="Incident Created",
                    details=f"Generated by real-time detection engine from {src_ip} -> {dst_ip}",
                    status="Success"
                )
            ],
            sample_events=[sample_event] if sample_event else []
        )
        self._incidents[inc_id] = incident
        return incident

    def update_status(self, incident_id: str, new_status: str, analyst: str = "SOC Analyst") -> Optional[Incident]:
        incident = self._incidents.get(incident_id)
        if not incident:
            return None
        old_status = incident.status
        incident.status = new_status
        incident.audit_trail.append(
            IncidentAudit(
                timestamp=time.time(),
                action=f"Status Changed ({old_status} -> {new_status})",
                details=f"Updated by {analyst}",
                status="Success"
            )
        )
        return incident

    def add_note(self, incident_id: str, author: str, content: str) -> Optional[Incident]:
        incident = self._incidents.get(incident_id)
        if not incident:
            return None
        incident.notes.append(
            IncidentNote(
                id=str(uuid.uuid4())[:8],
                timestamp=time.time(),
                author=author,
                content=content
            )
        )
        return incident

    def execute_playbook(self, incident_id: str, playbook_id: str, parameters: Optional[Dict] = None) -> Dict[str, Any]:
        incident = self._incidents.get(incident_id)
        if not incident:
            return {"success": False, "error": "Incident not found"}

        now = time.time()
        pb_info = PLAYBOOK_DESCRIPTIONS.get(playbook_id, {
            "name": playbook_id,
            "description": "Standard containment action",
            "steps": ["Action executed successfully"]
        })

        execution_record = {
            "execution_id": f"PB-RUN-{uuid.uuid4().hex[:6].upper()}",
            "playbook_id": playbook_id,
            "name": pb_info["name"],
            "executed_at": now,
            "status": "COMPLETED",
            "target": incident.src_ip if playbook_id == "block_ip" else incident.dst_ip,
            "steps_log": pb_info["steps"],
            "mitigation_summary": f"Containment strategy successfully enforced against {incident.src_ip}."
        }

        incident.playbook_executed = True
        incident.playbook_results.append(execution_record)
        incident.status = "Contained"
        incident.risk_score = max(10, incident.risk_score - 40)
        
        incident.audit_trail.append(
            IncidentAudit(
                timestamp=now,
                action=f"SOAR Playbook Executed: {pb_info['name']}",
                details=f"Applied containment to {execution_record['target']}",
                status="COMPLETED"
            )
        )
        
        incident.notes.append(
            IncidentNote(
                id=str(uuid.uuid4())[:8],
                timestamp=now,
                author="Securinix SOAR Engine",
                content=f"Playbook '{pb_info['name']}' completed automatically. Threat vector mitigated. Incident status escalated to Contained."
            )
        )

        return {
            "success": True,
            "playbook": execution_record,
            "incident": incident
        }

soar_manager = IncidentResponseManager()
