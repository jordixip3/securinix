"""
Securinix Real-Time Correlation & Detection Engine
Processes incoming network events against active configurable detection rules using sliding time windows.
"""
import time
import re
from collections import defaultdict, deque
from typing import List, Dict, Optional, Tuple, Callable
from app.models.schemas import NetworkEvent, DetectionRule
from app.engine.rules import rules_manager
from app.engine.soar import soar_manager

class CorrelationEngine:
    def __init__(self):
        # Sliding windows: key -> deque of (timestamp, event)
        # key format: f"{rule_id}:{src_ip}" or f"ports:{src_ip}"
        self._sliding_windows = defaultdict(lambda: deque())
        self._port_scan_windows = defaultdict(lambda: deque()) # deque of (timestamp, dst_port, event)
        self._callbacks: List[Callable] = []

    def register_alert_callback(self, callback: Callable):
        self._callbacks.append(callback)

    def _clean_window(self, window: deque, max_age: float, now: float):
        cutoff = now - max_age
        while window and window[0][0] < cutoff:
            window.popleft()

    def process_event(self, event: NetworkEvent) -> List[str]:
        """
        Evaluates a single network event against all active rules.
        Returns list of matched rule IDs.
        """
        now = time.time()
        matched_rule_ids = []
        active_rules = [r for r in rules_manager.get_all() if r.enabled]

        for rule in active_rules:
            # Protocol check
            if rule.protocol and rule.protocol != "ANY" and rule.protocol.upper() != event.protocol.upper():
                continue

            # Destination Port check
            if rule.dst_port is not None and rule.dst_port != event.dst_port:
                continue

            # Evaluate by condition type
            is_match = False

            if rule.condition_type == "port_scan":
                # Horizontal/Vertical port sweep tracker
                p_win = self._port_scan_windows[event.src_ip]
                self._clean_window(p_win, rule.window_seconds, now)
                p_win.append((now, event.dst_port, event))
                
                # Count distinct ports scanned
                distinct_ports = {item[1] for item in p_win}
                if len(distinct_ports) >= rule.threshold:
                    is_match = True
                    # Reset slightly to avoid flooding repeated alerts every millisecond
                    if len(p_win) > rule.threshold:
                        p_win.clear()

            elif rule.condition_type == "payload_match" and rule.pattern:
                # Regex signature payload inspection
                if event.payload_preview and re.search(rule.pattern, event.payload_preview):
                    win = self._sliding_windows[f"{rule.id}:{event.src_ip}"]
                    self._clean_window(win, rule.window_seconds, now)
                    win.append((now, event))
                    if len(win) >= rule.threshold:
                        is_match = True
                        win.clear()

            elif rule.condition_type == "rate":
                # Rate threshold per source IP within time window
                win = self._sliding_windows[f"{rule.id}:{event.src_ip}"]
                self._clean_window(win, rule.window_seconds, now)
                win.append((now, event))
                if len(win) >= rule.threshold:
                    is_match = True
                    win.clear()

            elif rule.condition_type == "ueba_anomaly":
                # High anomaly score threshold
                if event.anomaly_score >= 0.75:
                    is_match = True

            if is_match:
                matched_rule_ids.append(rule.id)
                event.matched_rules.append(rule.id)

                # Escalate to SOAR Incident Manager
                incident = soar_manager.create_or_update(
                    rule_id=rule.id,
                    rule_name=rule.name,
                    severity=rule.severity,
                    src_ip=event.src_ip,
                    dst_ip=event.dst_ip,
                    mitre_tactic=rule.mitre_tactic,
                    mitre_technique=rule.mitre_technique,
                    sample_event=event.model_dump()
                )

                # Automatic playbook execution if rule requests auto_isolate / auto_block
                if rule.action == "auto_isolate" and not incident.playbook_executed:
                    soar_manager.execute_playbook(incident.id, "isolate_host")
                elif rule.action == "auto_block" and not incident.playbook_executed:
                    soar_manager.execute_playbook(incident.id, "block_ip")

                # Dispatch alert to WebSocket subscribers
                alert_payload = {
                    "type": "ALERT",
                    "rule": rule.model_dump(),
                    "incident_id": incident.id,
                    "event": event.model_dump(),
                    "timestamp": now
                }
                for cb in self._callbacks:
                    try:
                        cb(alert_payload)
                    except Exception:
                        pass

        return matched_rule_ids

detector = CorrelationEngine()
