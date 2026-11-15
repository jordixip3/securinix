"""
Securinix Network Sniffer & Telemetry Generator
Combines real system network metrics (psutil) with synthetic enterprise traffic and attack scenario simulators.
"""
import asyncio
import random
import time
import uuid
import psutil
from datetime import datetime
from typing import List, Dict, Optional, Callable
from collections import deque
from app.models.schemas import NetworkEvent
from app.engine.detector import detector

INTERNAL_IPS = [
    "10.0.1.10", "10.0.1.25", "10.0.2.14", "10.0.2.80",
    "10.0.3.50", "10.0.4.15", "10.0.4.22", "192.168.1.105"
]

SERVER_ROLES = {
    "10.0.1.10": {"name": "DC-WIN2022-CORP", "services": [53, 88, 389, 445, 3389]},
    "10.0.1.25": {"name": "SRV-APP-PROD01", "services": [80, 443, 8080, 8443, 22]},
    "10.0.2.14": {"name": "SRV-POSTGRES-DB", "services": [5432, 22]},
    "10.0.2.80": {"name": "SRV-REDIS-CACHE", "services": [6379]},
    "10.0.3.50": {"name": "GATEWAY-VPN-EDGE", "services": [1194, 51820, 443]},
    "10.0.4.15": {"name": "DEV-WORKSTATION-08", "services": [22, 3389, 445]},
    "10.0.4.22": {"name": "FINANCE-PC-12", "services": [445, 3389]}
}

EXTERNAL_ADVERSARIES = [
    {"ip": "185.220.101.5", "geo": "NL - Amsterdam (Tor Exit)"},
    {"ip": "45.154.255.88", "geo": "RU - Moscow (Bulletproof VPS)"},
    {"ip": "103.149.28.19", "geo": "CN - Beijing (Scanned Range)"},
    {"ip": "194.26.29.112", "geo": "RO - Bucharest (Botnet C2)"},
    {"ip": "91.240.118.17", "geo": "UA - Kyiv (Darknet Proxy)"},
    {"ip": "198.51.100.42", "geo": "US - DigitalOcean VPS"}
]

EXTERNAL_LEGIT = [
    {"ip": "1.1.1.1", "geo": "Cloudflare DNS"},
    {"ip": "8.8.8.8", "geo": "Google DNS"},
    {"ip": "142.250.180.206", "geo": "Google Services"},
    {"ip": "13.107.4.52", "geo": "Microsoft Azure / Office 365"},
    {"ip": "151.101.65.140", "geo": "Fastly CDN"}
]

class NetworkSniffer:
    def __init__(self):
        self._running = False
        self._event_history: deque = deque(maxlen=200)
        self._event_callbacks: List[Callable] = []
        self._events_processed = 0
        self._last_net_io = None
        self._current_eps = 0.0
        self._scenario_task = None

    def register_event_callback(self, callback: Callable):
        self._event_callbacks.append(callback)

    def get_recent_events(self, limit: int = 100) -> List[NetworkEvent]:
        return list(self._event_history)[-limit:]

    def get_stats(self) -> Dict:
        # Calculate real system I/O
        io = psutil.net_io_counters()
        active_sockets = 18
        try:
            active_sockets = len(psutil.Process().net_connections())
        except Exception:
            try:
                active_sockets = len(psutil.net_connections(kind="inet"))
            except Exception:
                active_sockets = 18

        return {
            "total_events_processed": self._events_processed,
            "current_eps": round(self._current_eps, 1),
            "bytes_sent": io.bytes_sent,
            "bytes_recv": io.bytes_recv,
            "packets_sent": io.packets_sent,
            "packets_recv": io.packets_recv,
            "active_sockets": active_sockets
        }

    def ingest_custom_event(self, event_data: Dict) -> NetworkEvent:
        now = time.time()
        evt = NetworkEvent(
            id=f"EVT-{uuid.uuid4().hex[:8]}",
            timestamp=now,
            timestamp_iso=datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            src_ip=event_data.get("src_ip", "192.168.1.50"),
            src_port=event_data.get("src_port", random.randint(40000, 65000)),
            dst_ip=event_data.get("dst_ip", "10.0.1.25"),
            dst_port=event_data.get("dst_port", 80),
            protocol=event_data.get("protocol", "TCP"),
            length=event_data.get("length", random.randint(64, 1500)),
            flags=event_data.get("flags", "ACK, PSH"),
            service=event_data.get("service", "HTTP"),
            payload_preview=event_data.get("payload_preview", ""),
            geo_src=event_data.get("geo_src", "External"),
            geo_dst=event_data.get("geo_dst", "Internal Corp"),
            anomaly_score=event_data.get("anomaly_score", 0.1)
        )
        self._process_and_broadcast(evt)
        return evt

    def _process_and_broadcast(self, evt: NetworkEvent):
        self._events_processed += 1
        self._event_history.append(evt)
        # Correlate through detector
        detector.process_event(evt)

        # Broadcast via callbacks
        for cb in self._event_callbacks:
            try:
                cb(evt.model_dump())
            except Exception:
                pass

    async def start(self):
        self._running = True
        print("[NetworkSniffer] Telemetry engine started.")
        sec_counter = 0
        events_this_sec = 0
        last_calc = time.time()

        while self._running:
            # Generate 1 to 4 normal enterprise background packets per loop tick
            await asyncio.sleep(0.35)
            
            # Synthesize normal background traffic
            evt = self._generate_normal_packet()
            self._process_and_broadcast(evt)
            events_this_sec += 1

            now = time.time()
            if now - last_calc >= 1.0:
                self._current_eps = events_this_sec / (now - last_calc)
                events_this_sec = 0
                last_calc = now

    def stop(self):
        self._running = False

    def _generate_normal_packet(self) -> NetworkEvent:
        now = time.time()
        protocols = ["TCP", "TCP", "UDP", "TLS", "HTTP", "DNS"]
        proto = random.choice(protocols)
        
        # 70% internal-to-internal or internal-to-cloud, 30% external-to-internal
        is_inbound = random.random() < 0.3
        
        if is_inbound:
            ext = random.choice(EXTERNAL_LEGIT)
            src_ip = ext["ip"]
            geo_src = ext["geo"]
            dst_ip = "10.0.1.25"
            dst_port = random.choice([80, 443])
            service = "HTTPS" if dst_port == 443 else "HTTP"
            payload = f"GET /api/v1/health HTTP/1.1\r\nHost: portal.corp.local"
        else:
            src_ip = random.choice(INTERNAL_IPS)
            geo_src = "HQ Core Network (VLAN 10)"
            if proto == "DNS":
                dst_ip = "1.1.1.1"
                dst_port = 53
                service = "DNS"
                payload = f"Standard query 0x{random.randint(1000, 9999):x} A update.corp.internal"
            else:
                target_server = random.choice(list(SERVER_ROLES.keys()))
                dst_ip = target_server
                dst_port = random.choice(SERVER_ROLES[target_server]["services"])
                service = "HTTPS" if dst_port in [443, 8443] else ("SSH" if dst_port == 22 else "SMB" if dst_port == 445 else "TCP")
                payload = f"TLSv1.3 Application Data Length: {random.randint(128, 1420)}"

        return NetworkEvent(
            id=f"EVT-{uuid.uuid4().hex[:8]}",
            timestamp=now,
            timestamp_iso=datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            src_ip=src_ip,
            src_port=random.randint(40000, 65000),
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=proto,
            length=random.randint(64, 1500),
            flags="ACK, PSH",
            service=service,
            payload_preview=payload,
            geo_src=geo_src,
            geo_dst="Corp DMZ / LAN",
            anomaly_score=random.uniform(0.01, 0.12)
        )

    async def trigger_scenario(self, scenario: str, intensity: str = "medium", duration_seconds: int = 20):
        """
        Executes a targeted attack simulation scenario that immediately exercises Securinix rules.
        """
        adv = random.choice(EXTERNAL_ADVERSARIES)
        src_ip = adv["ip"]
        geo_src = adv["geo"]
        target_ip = "10.0.1.25"

        print(f"[AttackSimulator] Executing scenario '{scenario}' from {src_ip} -> {target_ip}")
        start_time = time.time()
        
        burst_count = 15 if intensity == "low" else (30 if intensity == "medium" else 60)
        interval = 0.15 if intensity == "low" else (0.05 if intensity == "medium" else 0.02)

        for _ in range(burst_count):
            if time.time() - start_time > duration_seconds:
                break

            now = time.time()
            if scenario == "port_scan":
                # Scans sequentially across high-value ports
                scanned_port = random.choice([21, 22, 23, 25, 53, 80, 110, 135, 139, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443, 9200])
                evt = NetworkEvent(
                    id=f"EVT-SCAN-{uuid.uuid4().hex[:6]}",
                    timestamp=now,
                    timestamp_iso=datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    src_ip=src_ip,
                    src_port=random.randint(49152, 65535),
                    dst_ip=target_ip,
                    dst_port=scanned_port,
                    protocol="TCP",
                    length=44,
                    flags="SYN",
                    service="Recon/Probe",
                    payload_preview=f"Nmap stealth probe 0x{scanned_port:04x} window size 1024",
                    geo_src=geo_src,
                    geo_dst="SRV-APP-PROD01 (DMZ)",
                    anomaly_score=0.88
                )

            elif scenario == "brute_force":
                # High frequency SSH login failures
                user_attempted = random.choice(["root", "admin", "deploy", "ubuntu", "administrator", "service_account"])
                evt = NetworkEvent(
                    id=f"EVT-BRUTE-{uuid.uuid4().hex[:6]}",
                    timestamp=now,
                    timestamp_iso=datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    src_ip=src_ip,
                    src_port=random.randint(50000, 60000),
                    dst_ip=target_ip,
                    dst_port=22,
                    protocol="TCP",
                    length=98,
                    flags="ACK, PSH",
                    service="SSH",
                    payload_preview=f"SSH-2.0-OpenSSH_8.9 Auth Failed: user='{user_attempted}' password='[REDACTED]' (Bad password)",
                    geo_src=geo_src,
                    geo_dst="SRV-APP-PROD01",
                    anomaly_score=0.94
                )

            elif scenario == "dns_tunnel":
                # Malicious DNS exfiltration queries
                encoded_chunk = f"v{random.randint(1000,9999)}.exfil.{uuid.uuid4().hex[:12]}.c2.adversary.xyz"
                evt = NetworkEvent(
                    id=f"EVT-DNS-{uuid.uuid4().hex[:6]}",
                    timestamp=now,
                    timestamp_iso=datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    src_ip="10.0.4.15",
                    src_port=random.randint(50000, 60000),
                    dst_ip=src_ip,
                    dst_port=53,
                    protocol="UDP",
                    length=210,
                    flags="None",
                    service="DNS",
                    payload_preview=f"Query TXT: {encoded_chunk} (Entropy: 4.88)",
                    geo_src="DEV-WORKSTATION-08",
                    geo_dst=geo_src,
                    anomaly_score=0.97
                )

            elif scenario == "ddos_syn_flood":
                # Flood of raw SYN packets
                evt = NetworkEvent(
                    id=f"EVT-DDOS-{uuid.uuid4().hex[:6]}",
                    timestamp=now,
                    timestamp_iso=datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    src_ip=src_ip,
                    src_port=random.randint(1024, 65535),
                    dst_ip=target_ip,
                    dst_port=80,
                    protocol="TCP",
                    length=54,
                    flags="SYN",
                    service="HTTP",
                    payload_preview="Raw SYN flood frame wscale 7 sackOK",
                    geo_src=geo_src,
                    geo_dst="SRV-APP-PROD01",
                    anomaly_score=0.99
                )

            elif scenario == "sqli_probe":
                payloads = [
                    "GET /users?id=1%20UNION%20SELECT%20null,username,password%20FROM%20users--",
                    "POST /login HTTP/1.1 - admin' OR 1=1; DROP TABLE logs; --",
                    "GET /download?file=../../../../etc/passwd HTTP/1.1"
                ]
                evt = NetworkEvent(
                    id=f"EVT-SQLI-{uuid.uuid4().hex[:6]}",
                    timestamp=now,
                    timestamp_iso=datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    src_ip=src_ip,
                    src_port=random.randint(40000, 60000),
                    dst_ip=target_ip,
                    dst_port=80,
                    protocol="TCP",
                    length=420,
                    flags="ACK, PSH",
                    service="HTTP",
                    payload_preview=random.choice(payloads),
                    geo_src=geo_src,
                    geo_dst="SRV-APP-PROD01",
                    anomaly_score=0.91
                )

            elif scenario == "smb_lateral":
                evt = NetworkEvent(
                    id=f"EVT-SMB-{uuid.uuid4().hex[:6]}",
                    timestamp=now,
                    timestamp_iso=datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
                    src_ip="10.0.4.15",
                    src_port=random.randint(40000, 60000),
                    dst_ip="10.0.1.10",
                    dst_port=445,
                    protocol="TCP",
                    length=340,
                    flags="ACK, PSH",
                    service="SMB2",
                    payload_preview="SMB2 TreeConnect IPC$ -> NamedPipe srvsvc (EternalBlue/PsExec lateral staging)",
                    geo_src="DEV-WORKSTATION-08",
                    geo_dst="DC-WIN2022-CORP",
                    anomaly_score=0.93
                )
            else:
                evt = self._generate_normal_packet()

            self._process_and_broadcast(evt)
            await asyncio.sleep(interval)

sniffer = NetworkSniffer()
