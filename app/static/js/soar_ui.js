/**
 * Securinix SOAR Incident Response & Playbooks UI
 * Interactive incident triage, investigation drawer, and 1-click containment execution.
 */

class SoarUI {
    constructor() {
        this.incidents = [];
        this.activeIncident = null;
        this.listContainer = document.getElementById('soarIncidentList');
        this.detailContainer = document.getElementById('soarDetailContainer');
    }

    async loadIncidents() {
        try {
            const res = await fetch('/api/incidents');
            if (res.ok) {
                this.incidents = await res.json();
                this.renderList();
                if (this.incidents.length > 0 && !this.activeIncident) {
                    this.selectIncident(this.incidents[0].id);
                }
            }
        } catch (e) {
            console.error('[SoarUI] Error loading incidents:', e);
        }
    }

    renderList() {
        if (!this.listContainer) return;
        this.listContainer.innerHTML = '';

        if (this.incidents.length === 0) {
            this.listContainer.innerHTML = `
                <div style="padding: 40px; text-align: center; color: #64748b;">
                    <div style="font-size: 32px; margin-bottom: 8px;">🛡️</div>
                    <div>No security incidents detected. System secure.</div>
                </div>
            `;
            return;
        }

        this.incidents.forEach(inc => {
            const card = document.createElement('div');
            const isActive = this.activeIncident && this.activeIncident.id === inc.id;
            const isCrit = inc.severity === 'CRITICAL';
            card.className = `glass-panel incident-card ${isCrit ? 'crit' : ''} ${isActive ? 'active' : ''}`;
            card.onclick = () => this.selectIncident(inc.id);

            const timeStr = new Date(inc.last_seen * 1000).toLocaleTimeString();
            card.innerHTML = `
                <div class="incident-card-header">
                    <span class="incident-id-tag">${inc.id}</span>
                    <span class="severity-pill sev-${inc.severity.toLowerCase()}">${inc.severity}</span>
                </div>
                <div class="incident-card-title">${inc.title}</div>
                <div class="incident-card-meta">
                    <span>${inc.src_ip} ➔ ${inc.dst_ip}</span>
                    <span style="font-family: var(--font-mono); color: ${inc.risk_score > 70 ? 'var(--crimson-crit)' : 'var(--cyan-neon)'}">
                        Risk: ${inc.risk_score}
                    </span>
                </div>
                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 8px; font-size: 11px;">
                    <span style="color: #64748b;">Events: <strong>${inc.event_count}</strong></span>
                    <span class="meta-chip" style="font-size: 10px;">${inc.status}</span>
                </div>
            `;
            this.listContainer.appendChild(card);
        });
    }

    async selectIncident(incidentId) {
        try {
            const res = await fetch(`/api/incidents/${incidentId}`);
            if (res.ok) {
                this.activeIncident = await res.json();
                this.renderDetail();
                this.renderList(); // updates active highlight
            }
        } catch (e) {
            console.error('[SoarUI] Error selecting incident:', e);
        }
    }

    renderDetail() {
        if (!this.detailContainer || !this.activeIncident) return;
        const inc = this.activeIncident;

        const auditLogsHtml = inc.audit_trail.map(log => `
            <div style="display: flex; gap: 10px; font-size: 11px; padding: 6px 0; border-bottom: 1px solid rgba(255,255,255,0.04);">
                <span style="color: #64748b; font-family: var(--font-mono);">${new Date(log.timestamp * 1000).toLocaleTimeString()}</span>
                <span style="color: var(--cyan-neon); font-weight: 600;">${log.action}</span>
                <span style="color: #94a3b8;">${log.details}</span>
            </div>
        `).join('');

        const notesHtml = inc.notes.map(note => `
            <div style="background: rgba(255,255,255,0.03); border-radius: 6px; padding: 10px; margin-bottom: 8px; font-size: 12px;">
                <div style="display: flex; justify-content: space-between; color: #64748b; font-size: 10px; margin-bottom: 4px;">
                    <strong style="color: var(--cyan-neon);">${note.author}</strong>
                    <span>${new Date(note.timestamp * 1000).toLocaleTimeString()}</span>
                </div>
                <div style="color: #cbd5e1;">${note.content}</div>
            </div>
        `).join('');

        const playbooksExecutedHtml = inc.playbook_results.map(pb => `
            <div style="background: rgba(0, 255, 136, 0.08); border: 1px solid rgba(0, 255, 136, 0.3); border-radius: 8px; padding: 12px; margin-top: 10px;">
                <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px;">
                    <strong style="color: var(--emerald-safe); font-size: 13px;">🛡️ Playbook Enforced: ${pb.name}</strong>
                    <span class="badge-safe" style="font-size: 10px;">COMPLETED</span>
                </div>
                <div style="font-size: 11px; color: #94a3b8; margin-bottom: 8px;">Target: <strong>${pb.target}</strong></div>
                <div style="font-family: var(--font-mono); font-size: 11px; color: #cbd5e1;">
                    ${pb.steps_log.map(s => `<div>${s}</div>`).join('')}
                </div>
            </div>
        `).join('');

        this.detailContainer.innerHTML = `
            <div class="inc-detail-header">
                <div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <span class="severity-pill sev-${inc.severity.toLowerCase()}">${inc.severity}</span>
                        <span class="meta-chip">${inc.id}</span>
                        <span class="meta-chip">Rule: ${inc.rule_id}</span>
                    </div>
                    <h2 class="inc-hero-title">${inc.title}</h2>
                    <div style="font-size: 12px; color: #94a3b8; margin-top: 4px;">
                        ${inc.description}
                    </div>
                </div>
                <div class="inc-risk-meter">
                    <div style="font-size: 10px; color: #94a3b8; text-transform: uppercase; font-weight: 700;">Entity Risk</div>
                    <div class="inc-risk-val">${inc.risk_score}</div>
                    <span class="meta-chip" style="font-size: 10px;">Status: ${inc.status}</span>
                </div>
            </div>

            <!-- Threat Vectors & MITRE -->
            <div style="display: grid; grid-template-columns: repeat(3, 1fr); gap: 12px;">
                <div class="glass-panel" style="padding: 12px; background: rgba(10,15,26,0.6);">
                    <div style="font-size: 10px; color: #64748b; text-transform: uppercase; font-weight: 700;">Threat Origin (Src)</div>
                    <div style="font-family: var(--font-mono); font-size: 14px; color: var(--crimson-crit); font-weight: 700; margin-top: 4px;">${inc.src_ip}</div>
                </div>
                <div class="glass-panel" style="padding: 12px; background: rgba(10,15,26,0.6);">
                    <div style="font-size: 10px; color: #64748b; text-transform: uppercase; font-weight: 700;">Target Asset (Dst)</div>
                    <div style="font-family: var(--font-mono); font-size: 14px; color: var(--cyan-neon); font-weight: 700; margin-top: 4px;">${inc.dst_ip}</div>
                </div>
                <div class="glass-panel" style="padding: 12px; background: rgba(10,15,26,0.6);">
                    <div style="font-size: 10px; color: #64748b; text-transform: uppercase; font-weight: 700;">MITRE Technique</div>
                    <div style="font-size: 12px; color: #cbd5e1; font-weight: 600; margin-top: 4px;">${inc.mitre_technique || 'T1046'}</div>
                </div>
            </div>

            <!-- SOAR Playbooks Execution Center -->
            <div class="playbooks-box">
                <div style="display: flex; align-items: center; justify-content: space-between;">
                    <div style="font-size: 13px; font-weight: 700; color: #fff; display: flex; align-items: center; gap: 8px;">
                        <span>⚡ Autonomous SOAR Playbooks</span>
                        <span class="meta-chip" style="font-size: 10px; color: var(--emerald-safe);">Securonix Automated CIRT</span>
                    </div>
                </div>

                <div class="playbooks-grid">
                    <div class="playbook-btn-card danger" onclick="window.SoarManagerUI.executePlaybook('${inc.id}', 'isolate_host')">
                        <div class="playbook-card-name">🛡️ Isolate Host (Quarantine)</div>
                        <div class="playbook-card-desc">SDN null-route / isolate infected host from internal lateral movement.</div>
                    </div>
                    <div class="playbook-btn-card danger" onclick="window.SoarManagerUI.executePlaybook('${inc.id}', 'block_ip')">
                        <div class="playbook-card-name">🚫 Block IP on Perimeter WAF</div>
                        <div class="playbook-card-desc">Inject edge firewall ACL drop rule terminating all active adversary sessions.</div>
                    </div>
                    <div class="playbook-btn-card" onclick="window.SoarManagerUI.executePlaybook('${inc.id}', 'revoke_session')">
                        <div class="playbook-card-name">🔑 Revoke User & Session Tokens</div>
                        <div class="playbook-card-desc">Invalidate Kerberos tickets, terminate active SSH/VPN tunnels, reset MFA.</div>
                    </div>
                    <div class="playbook-btn-card" onclick="window.SoarManagerUI.executePlaybook('${inc.id}', 'capture_forensics')">
                        <div class="playbook-card-name">🔍 Capture Memory & PCAP Dump</div>
                        <div class="playbook-card-desc">Extract volatile RAM dump and rolling 5-minute raw network PCAP buffer.</div>
                    </div>
                </div>

                <!-- Executed Playbooks Log -->
                ${playbooksExecutedHtml}
            </div>

            <!-- Incident Actions & Status Bar -->
            <div style="display: flex; align-items: center; justify-content: space-between; background: rgba(10,15,26,0.6); padding: 12px 16px; border-radius: 8px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 12px; color: #94a3b8;">Change Status:</span>
                    <select id="incStatusSelect" style="background: #141d33; border: 1px solid var(--border-subtle); color: #fff; padding: 4px 10px; border-radius: 6px; font-size: 12px;" onchange="window.SoarManagerUI.changeStatus('${inc.id}', this.value)">
                        <option value="New" ${inc.status === 'New' ? 'selected' : ''}>New</option>
                        <option value="Investigating" ${inc.status === 'Investigating' ? 'selected' : ''}>Investigating</option>
                        <option value="Contained" ${inc.status === 'Contained' ? 'selected' : ''}>Contained</option>
                        <option value="Resolved" ${inc.status === 'Resolved' ? 'selected' : ''}>Resolved</option>
                        <option value="False_Positive" ${inc.status === 'False_Positive' ? 'selected' : ''}>False Positive</option>
                    </select>
                </div>
                <button class="btn-cyber-outline" style="font-size: 11px;" onclick="window.SoarManagerUI.generateReport('${inc.id}')">
                    📄 Export Incident Briefing
                </button>
            </div>

            <!-- Audit Trail & Analyst Notes -->
            <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 16px;">
                <div class="glass-panel" style="padding: 14px; background: rgba(10,15,26,0.5);">
                    <div style="font-size: 12px; font-weight: 700; color: #fff; margin-bottom: 8px;">CIRT Audit Trail</div>
                    <div style="max-height: 180px; overflow-y: auto;">
                        ${auditLogsHtml}
                    </div>
                </div>

                <div class="glass-panel" style="padding: 14px; background: rgba(10,15,26,0.5);">
                    <div style="font-size: 12px; font-weight: 700; color: #fff; margin-bottom: 8px;">Analyst Investigation Notes</div>
                    <div style="max-height: 130px; overflow-y: auto;">
                        ${notesHtml}
                    </div>
                    <div style="display: flex; gap: 6px; margin-top: 8px;">
                        <input type="text" id="analystNoteInput" placeholder="Add forensic note..." style="flex: 1; background: #0f1628; border: 1px solid var(--border-subtle); color: #fff; border-radius: 6px; padding: 6px 10px; font-size: 11px;">
                        <button class="btn-cyber" style="padding: 4px 10px; font-size: 11px;" onclick="window.SoarManagerUI.addNote('${inc.id}')">Add</button>
                    </div>
                </div>
            </div>
        `;
    }

    async executePlaybook(incidentId, playbookId) {
        try {
            const res = await fetch('/api/incidents/playbook', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ incident_id: incidentId, playbook_id: playbookId })
            });
            const data = await res.json();
            if (res.ok) {
                if (window.SecurinixApp) {
                    window.SecurinixApp.showToast(`Playbook executed: ${data.playbook.name}`, 'safe');
                    window.SecurinixApp.playCyberSound('playbook');
                }
                this.selectIncident(incidentId);
                this.loadIncidents();
            } else {
                alert('Playbook failed: ' + data.detail);
            }
        } catch (e) {
            console.error('[SoarUI] Error executing playbook:', e);
        }
    }

    async changeStatus(incidentId, newStatus) {
        try {
            const res = await fetch(`/api/incidents/${incidentId}/status`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ status: newStatus, analyst: 'SOC Analyst' })
            });
            if (res.ok) {
                if (window.SecurinixApp) {
                    window.SecurinixApp.showToast(`Incident status updated to ${newStatus}`, 'safe');
                }
                this.selectIncident(incidentId);
                this.loadIncidents();
            }
        } catch (e) {
            console.error('[SoarUI] Error changing status:', e);
        }
    }

    async addNote(incidentId) {
        const input = document.getElementById('analystNoteInput');
        if (!input || !input.value.trim()) return;
        const content = input.value.trim();

        try {
            const res = await fetch(`/api/incidents/${incidentId}/note`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ author: 'SOC Specialist', content })
            });
            if (res.ok) {
                input.value = '';
                this.selectIncident(incidentId);
            }
        } catch (e) {
            console.error('[SoarUI] Error adding note:', e);
        }
    }

    generateReport(incidentId) {
        if (!this.activeIncident) return;
        const inc = this.activeIncident;
        const reportContent = `
===========================================================
SECURINIX CIRT - INCIDENT FORENSIC BRIEFING REPORT
Generated: ${new Date().toISOString()}
Compliance Framework: NIST CSF / NIS2 / ISO 27035
===========================================================

INCIDENT IDENTIFIER: ${inc.id}
THREAT TITLE:        ${inc.title}
SEVERITY LEVEL:      ${inc.severity} (Calculated Risk Score: ${inc.risk_score}/100)
STATUS:              ${inc.status}
CORRELATED POLICY:   ${inc.rule_id} (${inc.rule_name})

THREAT VECTORS:
- Adversary Origin:  ${inc.src_ip}
- Target Infrastructure: ${inc.dst_ip}
- Observed Events:   ${inc.event_count} telemetry packets
- First Seen:        ${new Date(inc.first_seen * 1000).toLocaleString()}
- Last Seen:         ${new Date(inc.last_seen * 1000).toLocaleString()}

MITRE ATT&CK MATRIX:
- Tactic:            ${inc.mitre_tactic}
- Technique:         ${inc.mitre_technique}

AUTONOMOUS SOAR MITIGATION:
${inc.playbook_results.map(pb => `* ${pb.name} -> Target: ${pb.target} (Status: ${pb.status})`).join('\n') || 'No automated playbook executed yet.'}

AUDIT LOGS:
${inc.audit_trail.map(a => `[${new Date(a.timestamp * 1000).toLocaleTimeString()}] ${a.action}: ${a.details}`).join('\n')}

ANALYST NOTES:
${inc.notes.map(n => `[${n.author}] ${n.content}`).join('\n')}
===========================================================
        `;

        const blob = new Blob([reportContent], { type: 'text/plain;charset=utf-8' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `SECURINIX_REPORT_${inc.id}.txt`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);

        if (window.SecurinixApp) {
            window.SecurinixApp.showToast(`Forensic Report ${inc.id} downloaded!`, 'safe');
        }
    }
}

window.SoarManagerUI = new SoarUI();
