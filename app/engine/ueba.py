"""
Securinix UEBA (User & Entity Behavior Analytics) Engine
Tracks entity baseline behaviors, peer grouping anomalies, and dynamic risk scoring.
"""
import time
from typing import List, Dict

class UEBAEngine:
    def __init__(self):
        self._entities: Dict[str, Dict] = {
            "USR-JMAICAS": {
                "id": "USR-JMAICAS",
                "type": "USER",
                "name": "Jordi Maicas (SecOps Lead)",
                "department": "Cybersecurity & Platform",
                "risk_score": 18,
                "status": "NORMAL",
                "anomalies_detected": ["Occasional off-hours SSH to Gateway"],
                "last_active": "2 minutes ago",
                "risk_trend": [12, 14, 15, 18, 18]
            },
            "USR-GUEST-VPN": {
                "id": "USR-GUEST-VPN",
                "type": "USER",
                "name": "Vendor Contractor (VPN-EXT)",
                "department": "External Partner",
                "risk_score": 78,
                "status": "WATCHLIST",
                "anomalies_detected": [
                    "Impossible Geolocation Travel (Madrid -> Singapore in 15m)",
                    "Unauthorized attempts to access Finance CIFS share"
                ],
                "last_active": "Just now",
                "risk_trend": [20, 35, 60, 75, 78]
            },
            "ASSET-DC-CORP": {
                "id": "ASSET-DC-CORP",
                "type": "HOST",
                "name": "DC-WIN2022-CORP (10.0.1.10)",
                "department": "Core Active Directory",
                "risk_score": 42,
                "status": "ELEVATED",
                "anomalies_detected": ["SMB lateral sweep requests from DEV subnet"],
                "last_active": "Continuous",
                "risk_trend": [10, 10, 25, 38, 42]
            },
            "ASSET-DEV-WS08": {
                "id": "ASSET-DEV-WS08",
                "type": "HOST",
                "name": "DEV-WORKSTATION-08 (10.0.4.15)",
                "department": "Engineering Lab",
                "risk_score": 88,
                "status": "HIGH_RISK",
                "anomalies_detected": [
                    "High-entropy DNS exfiltration tunnel burst",
                    "Unapproved outbound connections to TOR exit relay"
                ],
                "last_active": "10 seconds ago",
                "risk_trend": [15, 22, 55, 74, 88]
            },
            "SVC-BACKUP-AUTO": {
                "id": "SVC-BACKUP-AUTO",
                "type": "SERVICE",
                "name": "svc_veeam_backup (Service Account)",
                "department": "Infrastructure Services",
                "risk_score": 12,
                "status": "NORMAL",
                "anomalies_detected": [],
                "last_active": "1 hour ago",
                "risk_trend": [10, 10, 12, 12, 12]
            }
        }

    def get_all_entities(self) -> List[Dict]:
        return sorted(self._entities.values(), key=lambda x: x["risk_score"], reverse=True)

    def record_anomaly(self, entity_id: str, anomaly_desc: str, risk_bump: int = 15):
        if entity_id in self._entities:
            ent = self._entities[entity_id]
            ent["risk_score"] = min(100, ent["risk_score"] + risk_bump)
            if anomaly_desc not in ent["anomalies_detected"]:
                ent["anomalies_detected"].append(anomaly_desc)
            if ent["risk_score"] >= 80:
                ent["status"] = "HIGH_RISK"
            elif ent["risk_score"] >= 50:
                ent["status"] = "WATCHLIST"
            ent["risk_trend"].append(ent["risk_score"])
            if len(ent["risk_trend"]) > 10:
                ent["risk_trend"].pop(0)

ueba_engine = UEBAEngine()
