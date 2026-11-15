"""
Securinix Detection Rules Store & Manager
Configurable detection rules engine with real-time editing, persistence, and MITRE ATT&CK mapping.
"""
import json
import os
import uuid
import time
from typing import List, Optional, Dict
from app.models.schemas import DetectionRule, RuleUpdateRequest

RULES_FILE = os.path.join(os.path.dirname(os.path.dirname(__file__)), "rules_config.json")

DEFAULT_RULES: List[Dict] = [
    {
        "id": "RULE-PORT-SCAN",
        "name": "Horizontal / Vertical Network Port Sweep",
        "description": "Rapid scanning of multiple destination ports from a single external IP indicating network reconnaissance.",
        "severity": "HIGH",
        "category": "Reconnaissance",
        "mitre_tactic": "TA0043 - Reconnaissance",
        "mitre_technique": "T1046 - Network Service Scanning",
        "protocol": "TCP",
        "dst_port": None,
        "threshold": 12,
        "window_seconds": 10,
        "condition_type": "port_scan",
        "pattern": None,
        "enabled": True,
        "action": "create_incident",
        "created_at": time.time()
    },
    {
        "id": "RULE-SSH-BRUTE",
        "name": "Rapid SSH Credential Brute-Force",
        "description": "High frequency of SSH connection attempts and handshake terminations on port 22 within a narrow window.",
        "severity": "CRITICAL",
        "category": "Credential Access",
        "mitre_tactic": "TA0006 - Credential Access",
        "mitre_technique": "T1110.001 - Password Guessing",
        "protocol": "TCP",
        "dst_port": 22,
        "threshold": 6,
        "window_seconds": 15,
        "condition_type": "rate",
        "pattern": None,
        "enabled": True,
        "action": "auto_block",
        "created_at": time.time()
    },
    {
        "id": "RULE-RDP-SPRAY",
        "name": "RDP / Terminal Services Password Spray",
        "description": "Multiple authentication attempts directed at internal Windows Workstations/Servers via RDP (Port 3389).",
        "severity": "HIGH",
        "category": "Credential Access",
        "mitre_tactic": "TA0006 - Credential Access",
        "mitre_technique": "T1110.003 - Password Spraying",
        "protocol": "TCP",
        "dst_port": 3389,
        "threshold": 5,
        "window_seconds": 20,
        "condition_type": "rate",
        "pattern": None,
        "enabled": True,
        "action": "create_incident",
        "created_at": time.time()
    },
    {
        "id": "RULE-DNS-TUNNEL",
        "name": "Suspicious High-Entropy DNS C2 Exfiltration",
        "description": "Repetitive burst of high-entropy TXT/NULL DNS queries directed to unknown dynamic external nameservers.",
        "severity": "CRITICAL",
        "category": "Exfiltration",
        "mitre_tactic": "TA0010 - Exfiltration",
        "mitre_technique": "T1071.004 - DNS Command & Control",
        "protocol": "UDP",
        "dst_port": 53,
        "threshold": 8,
        "window_seconds": 12,
        "condition_type": "rate",
        "pattern": r"(?i)(\.xyz|\.top|\.ru|base64|tunnel)",
        "enabled": True,
        "action": "auto_isolate",
        "created_at": time.time()
    },
    {
        "id": "RULE-DDOS-SYN",
        "name": "Volumetric TCP SYN Flood Anomaly",
        "description": "Abnormal volume of half-open TCP SYN packets without ACK responses exceeding normal ingress capacity.",
        "severity": "CRITICAL",
        "category": "Denial of Service",
        "mitre_tactic": "TA0040 - Impact",
        "mitre_technique": "T1498 - Network Denial of Service",
        "protocol": "TCP",
        "dst_port": None,
        "threshold": 25,
        "window_seconds": 8,
        "condition_type": "rate",
        "pattern": None,
        "enabled": True,
        "action": "auto_block",
        "created_at": time.time()
    },
    {
        "id": "RULE-SMB-LATERAL",
        "name": "Lateral SMB / EternalBlue Staging Sweep",
        "description": "Unauthorized SMB session establishment and pipe negotiation across private subnet ranges on port 445.",
        "severity": "HIGH",
        "category": "Lateral Movement",
        "mitre_tactic": "TA0008 - Lateral Movement",
        "mitre_technique": "T1021.002 - SMB/Windows Admin Shares",
        "protocol": "TCP",
        "dst_port": 445,
        "threshold": 4,
        "window_seconds": 15,
        "condition_type": "rate",
        "pattern": None,
        "enabled": True,
        "action": "create_incident",
        "created_at": time.time()
    },
    {
        "id": "RULE-C2-BEACON",
        "name": "Cobalt Strike / C2 Periodic Jitter Beacon",
        "description": "Consistent periodic heartbeat outbound connection to suspected adversary Command & Control infrastructure.",
        "severity": "HIGH",
        "category": "Command and Control",
        "mitre_tactic": "TA0011 - Command and Control",
        "mitre_technique": "T1071.001 - Web Protocols (C2)",
        "protocol": "TCP",
        "dst_port": 8443,
        "threshold": 6,
        "window_seconds": 25,
        "condition_type": "rate",
        "pattern": None,
        "enabled": True,
        "action": "create_incident",
        "created_at": time.time()
    },
    {
        "id": "RULE-SQLI-INGRESS",
        "name": "Web Ingress SQL Injection / Path Traversal",
        "description": "Malicious SQL syntax or directory traversal patterns detected in HTTP request URI or payload parameters.",
        "severity": "MEDIUM",
        "category": "Initial Access",
        "mitre_tactic": "TA0001 - Initial Access",
        "mitre_technique": "T1190 - Exploit Public-Facing Application",
        "protocol": "TCP",
        "dst_port": 80,
        "threshold": 3,
        "window_seconds": 15,
        "condition_type": "payload_match",
        "pattern": r"(?i)(UNION\s+SELECT|OR\s+1=1|\.\./\.\./|--|DROP\s+TABLE)",
        "enabled": True,
        "action": "create_incident",
        "created_at": time.time()
    },
    {
        "id": "RULE-EXFIL-OUTBOUND",
        "name": "Anomalous High-Volume Outbound Data Transfer",
        "description": "Excessive egress bytes transmitted to an unclassified external destination within a single session.",
        "severity": "HIGH",
        "category": "Exfiltration",
        "mitre_tactic": "TA0010 - Exfiltration",
        "mitre_technique": "T1048 - Exfiltration Over Alternative Protocol",
        "protocol": "TCP",
        "dst_port": None,
        "threshold": 10,
        "window_seconds": 15,
        "condition_type": "rate",
        "pattern": None,
        "enabled": True,
        "action": "create_incident",
        "created_at": time.time()
    }
]

class RulesManager:
    def __init__(self):
        self._rules: Dict[str, DetectionRule] = {}
        self.load_rules()

    def load_rules(self):
        if os.path.exists(RULES_FILE):
            try:
                with open(RULES_FILE, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    self._rules = {item["id"]: DetectionRule(**item) for item in data}
                    return
            except Exception as e:
                print(f"[RulesManager] Error loading rules file: {e}. Falling back to default rules.")
        
        # Load defaults
        self._rules = {item["id"]: DetectionRule(**item) for item in DEFAULT_RULES}
        self.save_rules()

    def save_rules(self):
        try:
            data = [rule.model_dump() for rule in self._rules.values()]
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
        except Exception as e:
            print(f"[RulesManager] Error saving rules: {e}")

    def get_all(self) -> List[DetectionRule]:
        return list(self._rules.values())

    def get(self, rule_id: str) -> Optional[DetectionRule]:
        return self._rules.get(rule_id)

    def toggle_rule(self, rule_id: str, enabled: bool) -> Optional[DetectionRule]:
        if rule_id in self._rules:
            self._rules[rule_id].enabled = enabled
            self.save_rules()
            return self._rules[rule_id]
        return None

    def update_rule(self, rule_id: str, updates: RuleUpdateRequest) -> Optional[DetectionRule]:
        if rule_id not in self._rules:
            return None
        rule = self._rules[rule_id]
        update_dict = updates.model_dump(exclude_unset=True)
        for k, v in update_dict.items():
            setattr(rule, k, v)
        self.save_rules()
        return rule

    def create_rule(self, rule_data: Dict) -> DetectionRule:
        rule_id = rule_data.get("id") or f"RULE-{uuid.uuid4().hex[:6].upper()}"
        rule_data["id"] = rule_id
        rule_data["created_at"] = time.time()
        new_rule = DetectionRule(**rule_data)
        self._rules[rule_id] = new_rule
        self.save_rules()
        return new_rule

    def delete_rule(self, rule_id: str) -> bool:
        if rule_id in self._rules:
            del self._rules[rule_id]
            self.save_rules()
            return True
        return False

rules_manager = RulesManager()
