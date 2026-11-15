/**
 * Securinix Detection Rules Manager UI
 * Interactive rule tuning, threshold adjustments, live toggles, and custom rule creator.
 */

class RulesUI {
    constructor() {
        this.rules = [];
        this.container = document.getElementById('rulesGridContainer');
        this.initEventListeners();
    }

    async loadRules() {
        try {
            const res = await fetch('/api/rules');
            if (res.ok) {
                this.rules = await res.json();
                this.render();
            }
        } catch (e) {
            console.error('[RulesUI] Failed to fetch rules:', e);
        }
    }

    render() {
        if (!this.container) return;
        this.container.innerHTML = '';

        this.rules.forEach(rule => {
            const card = document.createElement('div');
            card.className = `glass-panel rule-card sev-${rule.severity}`;
            card.innerHTML = `
                <div class="rule-card-top">
                    <div>
                        <div class="rule-card-title">${rule.name}</div>
                        <span class="meta-chip">${rule.id}</span>
                    </div>
                    <label class="switch" title="Toggle Rule Enable/Disable">
                        <input type="checkbox" ${rule.enabled ? 'checked' : ''} data-rule-id="${rule.id}" class="rule-toggle-input">
                        <span class="slider"></span>
                    </label>
                </div>
                <div class="rule-card-desc">${rule.description}</div>
                <div class="rule-meta-chips">
                    <span class="severity-pill sev-${rule.severity.toLowerCase()}">${rule.severity}</span>
                    <span class="meta-chip">📂 ${rule.category}</span>
                    <span class="meta-chip">🎯 ${rule.mitre_tactic.split(' - ')[0]}</span>
                    <span class="meta-chip">⚙️ ${rule.protocol} ${rule.dst_port ? ':' + rule.dst_port : ':ANY'}</span>
                </div>
                <div class="rule-tuning-controls">
                    <div class="tuning-field">
                        <label>Threshold Count</label>
                        <input type="number" min="1" max="500" value="${rule.threshold}" id="thresh-${rule.id}">
                    </div>
                    <div class="tuning-field">
                        <label>Window (Seconds)</label>
                        <input type="number" min="1" max="300" value="${rule.window_seconds}" id="win-${rule.id}">
                    </div>
                </div>
                <div class="rule-card-actions">
                    <span style="font-size: 11px; color: #94a3b8;">
                        Action: <strong style="color: ${rule.action.includes('auto') ? 'var(--crimson-crit)' : 'var(--cyan-neon)'}">${rule.action}</strong>
                    </span>
                    <div style="display: flex; gap: 6px;">
                        <button class="btn-cyber-outline" style="padding: 4px 10px; font-size: 11px;" onclick="window.RulesManagerUI.saveRuleTuning('${rule.id}')">
                            Save Tuning
                        </button>
                        <button class="btn-cyber-outline" style="padding: 4px 8px; color: #f87171;" onclick="window.RulesManagerUI.deleteRule('${rule.id}')" title="Delete Rule">
                            🗑️
                        </button>
                    </div>
                </div>
            `;
            this.container.appendChild(card);
        });

        // Attach toggle listeners
        document.querySelectorAll('.rule-toggle-input').forEach(input => {
            input.addEventListener('change', async (e) => {
                const ruleId = e.target.getAttribute('data-rule-id');
                const isEnabled = e.target.checked;
                await this.toggleRule(ruleId, isEnabled);
            });
        });
    }

    async toggleRule(ruleId, enabled) {
        try {
            const res = await fetch(`/api/rules/${ruleId}/toggle`, {
                method: 'PATCH',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ enabled })
            });
            if (res.ok) {
                if (window.SecurinixApp) {
                    window.SecurinixApp.showToast(`Rule ${ruleId} is now ${enabled ? 'ENABLED' : 'DISABLED'}`, enabled ? 'safe' : 'warn');
                }
            }
        } catch (e) {
            console.error('[RulesUI] Error toggling rule:', e);
        }
    }

    async saveRuleTuning(ruleId) {
        const threshInput = document.getElementById(`thresh-${ruleId}`);
        const winInput = document.getElementById(`win-${ruleId}`);
        if (!threshInput || !winInput) return;

        const threshold = parseInt(threshInput.value, 10);
        const window_seconds = parseInt(winInput.value, 10);

        try {
            const res = await fetch(`/api/rules/${ruleId}`, {
                method: 'PUT',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ threshold, window_seconds })
            });
            if (res.ok) {
                if (window.SecurinixApp) {
                    window.SecurinixApp.showToast(`Rule ${ruleId} updated: Threshold=${threshold}, Window=${window_seconds}s`, 'safe');
                }
                this.loadRules();
            }
        } catch (e) {
            console.error('[RulesUI] Error saving tuning:', e);
        }
    }

    async deleteRule(ruleId) {
        if (!confirm(`Are you sure you want to delete detection policy ${ruleId}?`)) return;
        try {
            const res = await fetch(`/api/rules/${ruleId}`, { method: 'DELETE' });
            if (res.ok) {
                if (window.SecurinixApp) {
                    window.SecurinixApp.showToast(`Rule ${ruleId} deleted.`, 'warn');
                }
                this.loadRules();
            }
        } catch (e) {
            console.error('[RulesUI] Error deleting rule:', e);
        }
    }

    initEventListeners() {
        const createBtn = document.getElementById('openCreateRuleModalBtn');
        const modal = document.getElementById('createRuleModal');
        const closeBtn = document.getElementById('closeCreateRuleModalBtn');
        const form = document.getElementById('createRuleForm');

        if (createBtn && modal) {
            createBtn.addEventListener('click', () => modal.classList.add('active'));
        }
        if (closeBtn && modal) {
            closeBtn.addEventListener('click', () => modal.classList.remove('active'));
        }
        if (form) {
            form.addEventListener('submit', async (e) => {
                e.preventDefault();
                const formData = {
                    id: document.getElementById('newRuleId').value.trim() || undefined,
                    name: document.getElementById('newRuleName').value.trim(),
                    description: document.getElementById('newRuleDesc').value.trim(),
                    severity: document.getElementById('newRuleSev').value,
                    category: document.getElementById('newRuleCat').value,
                    mitre_tactic: document.getElementById('newRuleTactic').value,
                    mitre_technique: document.getElementById('newRuleTech').value,
                    protocol: document.getElementById('newRuleProto').value,
                    dst_port: document.getElementById('newRulePort').value ? parseInt(document.getElementById('newRulePort').value) : null,
                    threshold: parseInt(document.getElementById('newRuleThreshold').value) || 5,
                    window_seconds: parseInt(document.getElementById('newRuleWindow').value) || 15,
                    action: document.getElementById('newRuleAction').value,
                    condition_type: 'rate',
                    enabled: true
                };

                try {
                    const res = await fetch('/api/rules', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(formData)
                    });
                    if (res.ok) {
                        modal.classList.remove('active');
                        form.reset();
                        if (window.SecurinixApp) {
                            window.SecurinixApp.showToast(`Created new rule '${formData.name}' successfully!`, 'safe');
                        }
                        this.loadRules();
                    }
                } catch (err) {
                    console.error('[RulesUI] Error creating rule:', err);
                }
            });
        }
    }
}

window.RulesManagerUI = new RulesUI();
