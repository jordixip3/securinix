/**
 * Securinix Network Attack Topology & Flow Radar
 * High-performance HTML5 Canvas renderer for real-time cyber attacks and network telemetry.
 */

class NetworkTopology {
    constructor(canvasId) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.particles = [];
        this.shockwaves = [];
        this.activeThreats = new Map(); // ip -> expiry timestamp
        this.selectedNode = null;

        // Define cyber nodes
        this.nodes = [
            // External Adversary Cluster
            { id: 'ext_tor', label: 'Tor Exit Relay', ip: '185.220.101.5', x: 0.10, y: 0.25, type: 'external', status: 'hostile', icon: '☠️' },
            { id: 'ext_vps', label: 'Bulletproof VPS', ip: '45.154.255.88', x: 0.08, y: 0.55, type: 'external', status: 'hostile', icon: '⚡' },
            { id: 'ext_legit', label: 'Cloudflare / Edge DNS', ip: '1.1.1.1', x: 0.12, y: 0.82, type: 'external', status: 'legit', icon: '☁️' },

            // Perimeter Defense
            { id: 'gw_edge', label: 'Border Gateway / WAF', ip: '10.0.3.50', x: 0.35, y: 0.50, type: 'gateway', status: 'secure', icon: '🛡️' },

            // DMZ Cluster
            { id: 'srv_app', label: 'SRV-APP-PROD01 (DMZ)', ip: '10.0.1.25', x: 0.55, y: 0.32, type: 'server', status: 'normal', icon: '🌐' },
            { id: 'srv_cache', label: 'SRV-REDIS-CACHE', ip: '10.0.2.80', x: 0.55, y: 0.68, type: 'server', status: 'normal', icon: '⚡' },

            // Internal Core Subnet
            { id: 'srv_dc', label: 'DC-WIN2022-CORP', ip: '10.0.1.10', x: 0.82, y: 0.20, type: 'dc', status: 'elevated', icon: '👑' },
            { id: 'srv_db', label: 'SRV-POSTGRES-DB', ip: '10.0.2.14', x: 0.86, y: 0.48, type: 'database', status: 'secure', icon: '🗄️' },
            { id: 'ws_dev', label: 'DEV-WORKSTATION-08', ip: '10.0.4.15', x: 0.78, y: 0.75, type: 'workstation', status: 'warning', icon: '💻' },
            { id: 'ws_fin', label: 'FINANCE-PC-12', ip: '10.0.4.22', x: 0.92, y: 0.82, type: 'workstation', status: 'secure', icon: '💳' }
        ];

        // Define topological cyber links
        this.links = [
            ['ext_tor', 'gw_edge'],
            ['ext_vps', 'gw_edge'],
            ['ext_legit', 'gw_edge'],
            ['gw_edge', 'srv_app'],
            ['gw_edge', 'srv_cache'],
            ['srv_app', 'srv_dc'],
            ['srv_app', 'srv_db'],
            ['srv_app', 'ws_dev'],
            ['ws_dev', 'srv_dc'],
            ['ws_dev', 'srv_db'],
            ['ws_fin', 'srv_db']
        ];

        this.resize();
        window.addEventListener('resize', () => this.resize());
        this.initMouseListener();
        this.animate();
    }

    resize() {
        if (!this.canvas) return;
        const rect = this.canvas.parentElement.getBoundingClientRect();
        this.width = rect.width;
        this.height = rect.height;
        this.canvas.width = this.width * window.devicePixelRatio || this.width;
        this.canvas.height = this.height * window.devicePixelRatio || this.height;
        this.ctx.scale(window.devicePixelRatio || 1, window.devicePixelRatio || 1);
    }

    initMouseListener() {
        this.canvas.addEventListener('click', (e) => {
            const rect = this.canvas.getBoundingClientRect();
            const clickX = e.clientX - rect.left;
            const clickY = e.clientY - rect.top;

            for (const node of this.nodes) {
                const nx = node.x * this.width;
                const ny = node.y * this.height;
                const dist = Math.hypot(clickX - nx, clickY - ny);
                if (dist < 26) {
                    this.selectedNode = node;
                    this.emitNodeSelected(node);
                    return;
                }
            }
            this.selectedNode = null;
        });
    }

    emitNodeSelected(node) {
        if (window.SecurinixApp) {
            window.SecurinixApp.showNodeInspector(node);
        }
    }

    triggerAttack(srcIp, dstIp, severity = 'CRITICAL') {
        const srcNode = this.nodes.find(n => n.ip === srcIp) || this.nodes[0];
        const dstNode = this.nodes.find(n => n.ip === dstIp) || this.nodes[4];

        // Spawn red attack particles
        for (let i = 0; i < 6; i++) {
            this.particles.push({
                x1: srcNode.x * this.width,
                y1: srcNode.y * this.height,
                x2: dstNode.x * this.width,
                y2: dstNode.y * this.height,
                progress: -i * 0.12,
                speed: 0.035,
                color: severity === 'CRITICAL' ? '#ff0055' : '#ffaa00',
                size: 4
            });
        }

        // Add expanding shockwave on target
        this.shockwaves.push({
            x: dstNode.x * this.width,
            y: dstNode.y * this.height,
            radius: 8,
            maxRadius: 46,
            color: severity === 'CRITICAL' ? 'rgba(255, 0, 85, ' : 'rgba(255, 170, 0, ',
            alpha: 1.0
        });

        // Set active threat alert on node for 8 seconds
        this.activeThreats.set(dstNode.id, Date.now() + 8000);
        this.activeThreats.set(srcNode.id, Date.now() + 8000);
    }

    spawnNormalTraffic(srcIp, dstIp) {
        let srcNode = this.nodes.find(n => n.ip === srcIp);
        let dstNode = this.nodes.find(n => n.ip === dstIp);

        if (!srcNode || !dstNode) {
            srcNode = this.nodes[Math.floor(Math.random() * this.nodes.length)];
            dstNode = this.nodes[Math.floor(Math.random() * this.nodes.length)];
            if (srcNode === dstNode) return;
        }

        this.particles.push({
            x1: srcNode.x * this.width,
            y1: srcNode.y * this.height,
            x2: dstNode.x * this.width,
            y2: dstNode.y * this.height,
            progress: 0,
            speed: 0.02 + Math.random() * 0.015,
            color: '#00f0ff',
            size: 2.5
        });
    }

    animate() {
        requestAnimationFrame(() => this.animate());
        if (!this.ctx) return;

        this.ctx.clearRect(0, 0, this.width, this.height);

        // Draw Links
        for (const [sId, dId] of this.links) {
            const sNode = this.nodes.find(n => n.id === sId);
            const dNode = this.nodes.find(n => n.id === dId);
            if (!sNode || !dNode) continue;

            const x1 = sNode.x * this.width;
            const y1 = sNode.y * this.height;
            const x2 = dNode.x * this.width;
            const y2 = dNode.y * this.height;

            this.ctx.beginPath();
            this.ctx.moveTo(x1, y1);
            this.ctx.lineTo(x2, y2);
            this.ctx.strokeStyle = 'rgba(255, 255, 255, 0.06)';
            this.ctx.lineWidth = 1.5;
            this.ctx.stroke();

            // Link glow
            this.ctx.beginPath();
            this.ctx.moveTo(x1, y1);
            this.ctx.lineTo(x2, y2);
            this.ctx.strokeStyle = 'rgba(0, 240, 255, 0.02)';
            this.ctx.lineWidth = 4;
            this.ctx.stroke();
        }

        // Draw and update particles
        for (let i = this.particles.length - 1; i >= 0; i--) {
            const p = this.particles[i];
            p.progress += p.speed;

            if (p.progress >= 1) {
                this.particles.splice(i, 1);
                continue;
            }

            if (p.progress > 0) {
                const curX = p.x1 + (p.x2 - p.x1) * p.progress;
                const curY = p.y1 + (p.y2 - p.y1) * p.progress;

                this.ctx.beginPath();
                this.ctx.arc(curX, curY, p.size, 0, Math.PI * 2);
                this.ctx.fillStyle = p.color;
                this.ctx.shadowColor = p.color;
                this.ctx.shadowBlur = 10;
                this.ctx.fill();
                this.ctx.shadowBlur = 0;
            }
        }

        // Draw and update shockwaves
        for (let i = this.shockwaves.length - 1; i >= 0; i--) {
            const sw = this.shockwaves[i];
            sw.radius += 1.2;
            sw.alpha = Math.max(0, 1.0 - (sw.radius / sw.maxRadius));

            if (sw.radius >= sw.maxRadius || sw.alpha <= 0) {
                this.shockwaves.splice(i, 1);
                continue;
            }

            this.ctx.beginPath();
            this.ctx.arc(sw.x, sw.y, sw.radius, 0, Math.PI * 2);
            this.ctx.strokeStyle = `${sw.color}${sw.alpha})`;
            this.ctx.lineWidth = 2.5;
            this.ctx.stroke();
        }

        // Draw Nodes
        const now = Date.now();
        for (const node of this.nodes) {
            const nx = node.x * this.width;
            const ny = node.y * this.height;
            const isThreatened = (this.activeThreats.get(node.id) || 0) > now;
            const isSelected = this.selectedNode && this.selectedNode.id === node.id;

            // Outer node glow
            this.ctx.beginPath();
            this.ctx.arc(nx, ny, 22, 0, Math.PI * 2);
            if (isThreatened) {
                this.ctx.fillStyle = 'rgba(255, 0, 85, 0.2)';
                this.ctx.strokeStyle = '#ff0055';
            } else if (node.type === 'gateway') {
                this.ctx.fillStyle = 'rgba(0, 102, 255, 0.2)';
                this.ctx.strokeStyle = '#0066ff';
            } else if (node.type === 'external') {
                this.ctx.fillStyle = 'rgba(255, 170, 0, 0.15)';
                this.ctx.strokeStyle = '#ffaa00';
            } else {
                this.ctx.fillStyle = 'rgba(0, 240, 255, 0.15)';
                this.ctx.strokeStyle = '#00f0ff';
            }
            this.ctx.lineWidth = isSelected ? 3 : 1.5;
            this.ctx.fill();
            this.ctx.stroke();

            // Inner core
            this.ctx.beginPath();
            this.ctx.arc(nx, ny, 14, 0, Math.PI * 2);
            this.ctx.fillStyle = '#0b1120';
            this.ctx.fill();

            // Emoji / Icon
            this.ctx.font = '14px sans-serif';
            this.ctx.textAlign = 'center';
            this.ctx.textBaseline = 'middle';
            this.ctx.fillText(node.icon, nx, ny);

            // Label & IP
            this.ctx.font = '600 11px Inter, sans-serif';
            this.ctx.fillStyle = isThreatened ? '#ff0055' : '#ffffff';
            this.ctx.fillText(node.label, nx, ny + 32);

            this.ctx.font = '10px JetBrains Mono, monospace';
            this.ctx.fillStyle = '#94a3b8';
            this.ctx.fillText(node.ip, nx, ny + 46);
        }
    }
}
