/**
 * Securinix Master Application Controller
 * Handles WebSocket telemetry stream, metrics calculation, audio cues, tab routing, and attack simulation.
 */

class SecurinixMaster {
    constructor() {
        this.ws = null;
        this.audioEnabled = true;
        this.streamPaused = false;
        this.audioCtx = null;
        this.recentEvents = [];
        this.activeFilter = '';
        this.topology = null;

        this.initDOM();
        this.initTabs();
        this.initWebSocket();
        this.initAudio();
        this.initPeriodicStatus();
        this.loadUEBA();
        this.loadMITRE();
    }

    initDOM() {
        // Topology Canvas
        setTimeout(() => {
            this.topology = new NetworkTopology('networkTopologyCanvas');
        }, 100);

        // Sound Toggle
        const audioBtn = document.getElementById('toggleAudioBtn');
        if (audioBtn) {
            audioBtn.addEventListener('click', () => {
                this.audioEnabled = !this.audioEnabled;
                audioBtn.innerHTML = this.audioEnabled ? '🔊 Sound: ON' : '🔇 Sound: OFF';
                audioBtn.style.color = this.audioEnabled ? 'var(--cyan-neon)' : '#94a3b8';
            });
        }

        // Pause/Resume Stream
        const pauseBtn = document.getElementById('pauseStreamBtn');
        if (pauseBtn) {
            pauseBtn.addEventListener('click', () => {
                this.streamPaused = !this.streamPaused;
                pauseBtn.innerHTML = this.streamPaused ? '▶️ Resume Stream' : '⏸️ Pause Stream';
                pauseBtn.className = this.streamPaused ? 'btn-cyber' : 'btn-cyber-outline';
            });
        }

        // Event Search Filter
        const searchInput = document.getElementById('eventSearchInput');
        if (searchInput) {
            searchInput.addEventListener('input', (e) => {
                this.activeFilter = e.target.value.toLowerCase().trim();
                this.renderEventsTable();
            });
        }
    }

    initTabs() {
        const tabs = document.querySelectorAll('.nav-tab-btn');
        tabs.forEach(tab => {
            tab.addEventListener('click', () => {
                const targetView = tab.getAttribute('data-target');
                tabs.forEach(t => t.classList.remove('active'));
                tab.classList.add('active');

                document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
                const activeView = document.getElementById(targetView);
                if (activeView) activeView.classList.add('active');

                // Trigger subcomponent refresh
                if (targetView === 'rulesView' && window.RulesManagerUI) {
                    window.RulesManagerUI.loadRules();
                } else if (targetView === 'soarView' && window.SoarManagerUI) {
                    window.SoarManagerUI.loadIncidents();
                } else if (targetView === 'uebaView') {
                    this.loadUEBA();
                } else if (targetView === 'dashboardView' && this.topology) {
                    this.topology.resize();
                }
            });
        });
    }

    initAudio() {
        try {
            window.AudioContext = window.AudioContext || window.webkitAudioContext;
            this.audioCtx = new AudioContext();
        } catch (e) {
            console.warn('[Audio] Web Audio API not supported on this browser.');
        }
    }

    playCyberSound(type = 'ping') {
        if (!this.audioEnabled || !this.audioCtx) return;
        if (this.audioCtx.state === 'suspended') {
            this.audioCtx.resume();
        }

        try {
            const osc = this.audioCtx.createOscillator();
            const gain = this.audioCtx.createGain();
            osc.connect(gain);
            gain.connect(this.audioCtx.destination);

            const now = this.audioCtx.currentTime;

            if (type === 'alert') {
                // High-tech red alert tone
                osc.type = 'sawtooth';
                osc.frequency.setValueAtTime(880, now);
                osc.frequency.exponentialRampToValueAtTime(440, now + 0.25);
                gain.gain.setValueAtTime(0.15, now);
                gain.gain.exponentialRampToValueAtTime(0.01, now + 0.25);
                osc.start(now);
                osc.stop(now + 0.25);
            } else if (type === 'playbook') {
                // Harmonic resolution chime
                osc.type = 'sine';
                osc.frequency.setValueAtTime(523.25, now); // C5
                osc.frequency.setValueAtTime(659.25, now + 0.1); // E5
                osc.frequency.setValueAtTime(783.99, now + 0.2); // G5
                gain.gain.setValueAtTime(0.12, now);
                gain.gain.exponentialRampToValueAtTime(0.01, now + 0.4);
                osc.start(now);
                osc.stop(now + 0.4);
            } else {
                // Subtle packet blip
                osc.type = 'sine';
                osc.frequency.setValueAtTime(1200, now);
                gain.gain.setValueAtTime(0.02, now);
                gain.gain.exponentialRampToValueAtTime(0.001, now + 0.05);
                osc.start(now);
                osc.stop(now + 0.05);
            }
        } catch (e) {
            // Audio error silently ignored
        }
    }

    initWebSocket() {
        const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
        const wsUrl = `${protocol}//${window.location.host}/ws/telemetry`;

        const connect = () => {
            this.ws = new WebSocket(wsUrl);

            this.ws.onopen = () => {
                console.log('[Securinix WS] Telemetry stream connected.');
                const badge = document.getElementById('telemetryBadge');
                if (badge) {
                    badge.innerHTML = '<span class="pulse-dot"></span> TELEMETRY ENGINE: LIVE';
                    badge.style.color = 'var(--emerald-safe)';
                }
            };

            this.ws.onmessage = (event) => {
                try {
                    const msg = JSON.parse(event.data);
                    this.handleWsMessage(msg);
                } catch (e) {
                    console.error('[Securinix WS] Error parsing payload:', e);
                }
            };

            this.ws.onclose = () => {
                console.warn('[Securinix WS] Disconnected. Reconnecting in 3s...');
                const badge = document.getElementById('telemetryBadge');
                if (badge) {
                    badge.innerHTML = '<span class="pulse-dot crit"></span> RECONNECTING...';
                    badge.style.color = 'var(--crimson-crit)';
                }
                setTimeout(connect, 3000);
            };

            this.ws.onerror = (err) => {
                console.error('[Securinix WS] Socket error:', err);
                this.ws.close();
            };
        };

        connect();
    }

    handleWsMessage(msg) {
        if (msg.type === 'INIT') {
            this.recentEvents = msg.recent_events || [];
            this.renderEventsTable();
            if (window.SoarManagerUI) {
                window.SoarManagerUI.loadIncidents();
            }
        } else if (msg.type === 'EVENT') {
            const evt = msg.data;
            if (!this.streamPaused) {
                this.recentEvents.unshift(evt);
                if (this.recentEvents.length > 250) this.recentEvents.pop();
                this.renderEventsTable();
            }

            // Animate on canvas
            if (this.topology) {
                this.topology.spawnNormalTraffic(evt.src_ip, evt.dst_ip);
            }
        } else if (msg.type === 'ALERT') {
            this.playCyberSound('alert');
            this.showToast(`🚨 ALERT: ${msg.rule.name} [${msg.rule.severity}] from ${msg.event.src_ip}`, 'crit');

            // Trigger canvas attack shockwave
            if (this.topology) {
                this.topology.triggerAttack(msg.event.src_ip, msg.event.dst_ip, msg.rule.severity);
            }

            // Reload incidents in background
            if (window.SoarManagerUI) {
                window.SoarManagerUI.loadIncidents();
            }
            this.updateThreatGauge();
        } else if (msg.type === 'PLAYBOOK_EXECUTED' || msg.type === 'INCIDENT_UPDATED') {
            if (window.SoarManagerUI) {
                window.SoarManagerUI.loadIncidents();
            }
            this.updateThreatGauge();
        } else if (msg.type === 'RULES_UPDATED') {
            if (window.RulesManagerUI) {
                window.RulesManagerUI.loadRules();
            }
        }
    }

    async initPeriodicStatus() {
        const update = async () => {
            try {
                const res = await fetch('/api/status');
                if (res.ok) {
                    const data = await res.json();
                    this.updateMetricsUI(data);
                }
            } catch (e) {
                // Status poll error
            }
        };
        update();
        setInterval(update, 2000);
    }

    updateMetricsUI(data) {
        const setVal = (id, val) => {
            const el = document.getElementById(id);
            if (el) el.innerText = val;
        };

        setVal('metricEps', data.telemetry.current_eps);
        setVal('metricTotalEvents', data.telemetry.total_events_processed.toLocaleString());
        setVal('metricOpenIncidents', data.incidents_open);
        setVal('metricCritIncidents', data.critical_incidents);
        setVal('metricActiveRules', `${data.rules_enabled} / ${data.rules_total}`);
        setVal('metricThreatIndex', data.threat_index);

        // Update Threat Index Gauge visuals
        const gaugeVal = document.getElementById('threatGaugeValue');
        const gaugeLabel = document.getElementById('threatGaugeLabel');
        if (gaugeVal && gaugeLabel) {
            gaugeVal.innerText = data.threat_index;
            if (data.threat_index >= 75) {
                gaugeVal.style.color = 'var(--crimson-crit)';
                gaugeLabel.innerText = 'CRITICAL RISK';
                gaugeLabel.style.color = 'var(--crimson-crit)';
            } else if (data.threat_index >= 45) {
                gaugeVal.style.color = 'var(--amber-warn)';
                gaugeLabel.innerText = 'ELEVATED RISK';
                gaugeLabel.style.color = 'var(--amber-warn)';
            } else {
                gaugeVal.style.color = 'var(--emerald-safe)';
                gaugeLabel.innerText = 'NORMAL STATE';
                gaugeLabel.style.color = 'var(--emerald-safe)';
            }
        }
    }

    renderEventsTable() {
        const tbody = document.getElementById('eventsStreamBody');
        if (!tbody) return;

        let filtered = this.recentEvents;
        if (this.activeFilter) {
            filtered = this.recentEvents.filter(e => 
                e.src_ip.includes(this.activeFilter) ||
                e.dst_ip.includes(this.activeFilter) ||
                e.protocol.toLowerCase().includes(this.activeFilter) ||
                e.service.toLowerCase().includes(this.activeFilter) ||
                (e.payload_preview && e.payload_preview.toLowerCase().includes(this.activeFilter))
            );
        }

        const rows = filtered.slice(0, 75).map(e => {
            const isAlert = e.matched_rules && e.matched_rules.length > 0;
            const timeFormatted = e.timestamp_iso ? e.timestamp_iso.split(' ')[1] : new Date(e.timestamp * 1000).toLocaleTimeString();
            const protoClass = `proto-${e.protocol.toLowerCase()}`;
            
            return `
                <tr class="${isAlert ? 'alert-row' : ''}" onclick="window.SecurinixApp.inspectEvent('${e.id}')">
                    <td style="color: #64748b;">${timeFormatted}</td>
                    <td><span class="proto-badge ${protoClass}">${e.protocol}</span></td>
                    <td style="font-weight: 600; color: ${isAlert ? 'var(--crimson-crit)' : '#cbd5e1'}">${e.src_ip}:${e.src_port}</td>
                    <td style="color: var(--cyan-neon);">${e.dst_ip}:${e.dst_port}</td>
                    <td><span class="meta-chip" style="font-size: 10px;">${e.service}</span></td>
                    <td style="color: #64748b;">${e.length} B</td>
                    <td style="max-width: 380px; overflow: hidden; text-overflow: ellipsis; color: #94a3b8;">
                        ${isAlert ? `<strong style="color: var(--crimson-crit)">[TRIGGERED ${e.matched_rules.join(', ')}]</strong> ` : ''}
                        ${this.escapeHtml(e.payload_preview || '')}
                    </td>
                </tr>
            `;
        }).join('');

        tbody.innerHTML = rows;
    }

    inspectEvent(eventId) {
        const evt = this.recentEvents.find(e => e.id === eventId);
        if (!evt) return;

        const modal = document.getElementById('packetInspectorModal');
        const modalBody = document.getElementById('packetInspectorBody');
        if (!modal || !modalBody) return;

        modalBody.innerHTML = `
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 14px; margin-bottom: 16px;">
                <div class="glass-panel" style="padding: 12px; background: rgba(10,15,26,0.8);">
                    <div style="font-size: 10px; color: #64748b; font-weight: 700;">SOURCE TELEMETRY</div>
                    <div style="font-family: var(--font-mono); font-size: 14px; color: #fff; margin-top: 4px;">${evt.src_ip}:${evt.src_port}</div>
                    <div style="font-size: 11px; color: #94a3b8;">Geo: ${evt.geo_src}</div>
                </div>
                <div class="glass-panel" style="padding: 12px; background: rgba(10,15,26,0.8);">
                    <div style="font-size: 10px; color: #64748b; font-weight: 700;">DESTINATION TARGET</div>
                    <div style="font-family: var(--font-mono); font-size: 14px; color: var(--cyan-neon); margin-top: 4px;">${evt.dst_ip}:${evt.dst_port}</div>
                    <div style="font-size: 11px; color: #94a3b8;">Geo: ${evt.geo_dst}</div>
                </div>
            </div>

            <div style="background: #090e1a; border: 1px solid var(--border-subtle); border-radius: 8px; padding: 14px; margin-bottom: 14px;">
                <div style="font-size: 11px; color: #64748b; font-weight: 700; margin-bottom: 6px;">PROTOCOL / FLAGS</div>
                <div style="display: flex; gap: 10px; font-family: var(--font-mono); font-size: 12px;">
                    <span>Protocol: <strong>${evt.protocol}</strong></span>
                    <span>Service: <strong>${evt.service}</strong></span>
                    <span>Flags: <strong>${evt.flags || 'None'}</strong></span>
                    <span>Length: <strong>${evt.length} bytes</strong></span>
                </div>
            </div>

            <div style="background: #090e1a; border: 1px solid var(--border-subtle); border-radius: 8px; padding: 14px;">
                <div style="font-size: 11px; color: #64748b; font-weight: 700; margin-bottom: 6px;">RAW PAYLOAD INSPECTION</div>
                <pre style="font-family: var(--font-mono); font-size: 12px; color: var(--cyan-neon); white-space: pre-wrap; word-break: break-all;">${this.escapeHtml(evt.payload_preview || 'No application data attached.')}</pre>
            </div>
        `;

        modal.classList.add('active');
        const closeBtn = document.getElementById('closePacketInspectorBtn');
        if (closeBtn) closeBtn.onclick = () => modal.classList.remove('active');
    }

    showNodeInspector(node) {
        this.showToast(`Inspecting Host: ${node.label} (${node.ip})`, 'safe');
    }

    async triggerSimulation(scenario) {
        try {
            const res = await fetch('/api/simulate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ scenario, intensity: 'medium', duration_seconds: 15 })
            });
            const data = await res.json();
            if (res.ok) {
                this.showToast(`🔥 Simulation triggered: ${scenario.toUpperCase()}`, 'crit');
            }
        } catch (e) {
            console.error('[Securinix] Simulation error:', e);
        }
    }

    async loadUEBA() {
        const container = document.getElementById('uebaLeaderboard');
        if (!container) return;
        try {
            const res = await fetch('/api/ueba');
            if (res.ok) {
                const entities = await res.json();
                container.innerHTML = entities.map(ent => `
                    <div class="glass-panel" style="padding: 16px; margin-bottom: 12px; display: flex; align-items: center; justify-content: space-between; border-left: 4px solid ${ent.risk_score > 70 ? 'var(--crimson-crit)' : ent.risk_score > 40 ? 'var(--amber-warn)' : 'var(--emerald-safe)'}">
                        <div>
                            <div style="display: flex; align-items: center; gap: 8px;">
                                <strong style="font-size: 14px; color: #fff;">${ent.name}</strong>
                                <span class="meta-chip">${ent.type}</span>
                                <span class="severity-pill sev-${ent.status === 'HIGH_RISK' ? 'critical' : ent.status === 'WATCHLIST' ? 'high' : 'low'}">${ent.status}</span>
                            </div>
                            <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">Department: ${ent.department} • Active: ${ent.last_active}</div>
                            <div style="margin-top: 6px;">
                                ${ent.anomalies_detected.map(a => `<span class="meta-chip" style="color: var(--amber-warn); font-size: 10px;">⚠️ ${a}</span>`).join(' ') || '<span style="color: #64748b; font-size: 11px;">Baseline normal. No anomalies.</span>'}
                            </div>
                        </div>
                        <div style="text-align: right;">
                            <div style="font-size: 10px; color: #64748b; font-weight: 700;">UEBA RISK SCORE</div>
                            <div style="font-family: var(--font-mono); font-size: 32px; font-weight: 800; color: ${ent.risk_score > 70 ? 'var(--crimson-crit)' : ent.risk_score > 40 ? 'var(--amber-warn)' : 'var(--emerald-safe)'};">${ent.risk_score}</div>
                        </div>
                    </div>
                `).join('');
            }
        } catch (e) {
            console.error('[Securinix] Error loading UEBA:', e);
        }
    }

    async loadMITRE() {
        const container = document.getElementById('mitreMatrixContainer');
        if (!container) return;
        try {
            const res = await fetch('/api/mitre');
            if (res.ok) {
                const data = await res.json();
                container.innerHTML = Object.entries(data).map(([tactic, count]) => `
                    <div class="glass-panel" style="padding: 14px; text-align: center; background: ${count > 0 ? 'rgba(255, 0, 85, 0.1)' : 'rgba(10, 15, 26, 0.6)'}; border-color: ${count > 0 ? 'rgba(255, 0, 85, 0.4)' : 'var(--border-subtle)'}">
                        <div style="font-size: 11px; font-weight: 700; color: #cbd5e1;">${tactic}</div>
                        <div style="font-family: var(--font-mono); font-size: 24px; font-weight: 800; color: ${count > 0 ? 'var(--crimson-crit)' : '#64748b'}; margin-top: 6px;">
                            ${count}
                        </div>
                        <div style="font-size: 10px; color: #64748b; margin-top: 2px;">Active Detections</div>
                    </div>
                `).join('');
            }
        } catch (e) {
            console.error('[Securinix] Error loading MITRE:', e);
        }
    }

    showToast(msg, type = 'safe') {
        const toast = document.createElement('div');
        toast.style.cssText = `
            position: fixed;
            bottom: 24px;
            right: 24px;
            background: ${type === 'crit' ? '#1f0d14' : '#0c1a24'};
            border: 1px solid ${type === 'crit' ? 'var(--crimson-crit)' : 'var(--cyan-neon)'};
            color: #fff;
            padding: 12px 20px;
            border-radius: 8px;
            box-shadow: 0 0 20px ${type === 'crit' ? 'rgba(255,0,85,0.4)' : 'rgba(0,240,255,0.3)'};
            font-size: 13px;
            font-weight: 600;
            z-index: 9999;
            display: flex;
            align-items: center;
            gap: 10px;
            animation: slideUp 0.25s ease-out;
        `;
        toast.innerHTML = `<span>${type === 'crit' ? '🚨' : '✨'}</span> <span>${this.escapeHtml(msg)}</span>`;
        document.body.appendChild(toast);
        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transition = 'opacity 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, 4000);
    }

    escapeHtml(str) {
        return (str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }
}

// Global initialization
window.addEventListener('DOMContentLoaded', () => {
    window.SecurinixApp = new SecurinixMaster();
});
