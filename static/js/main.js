/**
 * AI-Assisted Secure Switch Dashboard
 * 主要 JavaScript 邏輯
 */

// ========== 全域變數 ==========
let chart = null;
let chartData = null;
let prevStats = null;
let lastAlertCount = 0;

// ========== 初始化圖表 ==========
function initChart() {
    const ctx = document.getElementById('trafficChart').getContext('2d');
    
    chartData = {
        labels: [],
        datasets: [
            {
                label: '總封包',
                data: [],
                borderColor: '#06b6d4',
                backgroundColor: 'rgba(6, 182, 212, 0.1)',
                fill: true,
                tension: 0.4,
                borderWidth: 2,
            },
            {
                label: 'ARP 封包',
                data: [],
                borderColor: '#ef4444',
                backgroundColor: 'rgba(239, 68, 68, 0.1)',
                fill: true,
                tension: 0.4,
                borderWidth: 2,
            },
            {
                label: '不同 MAC',
                data: [],
                borderColor: '#8b5cf6',
                backgroundColor: 'rgba(139, 92, 246, 0.1)',
                fill: true,
                tension: 0.4,
                borderWidth: 2,
            }
        ]
    };

    chart = new Chart(ctx, {
        type: 'line',
        data: chartData,
        options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
                intersect: false,
                mode: 'index',
            },
            plugins: {
                legend: {
                    display: false
                },
                tooltip: {
                    backgroundColor: '#1a2332',
                    titleColor: '#f1f5f9',
                    bodyColor: '#94a3b8',
                    borderColor: '#2a3544',
                    borderWidth: 1,
                    padding: 12,
                    cornerRadius: 8,
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(42, 53, 68, 0.5)',
                        drawBorder: false,
                    },
                    ticks: {
                        color: '#64748b',
                        font: { family: 'JetBrains Mono', size: 10 },
                        maxTicksLimit: 10,
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(42, 53, 68, 0.5)',
                        drawBorder: false,
                    },
                    ticks: {
                        color: '#64748b',
                        font: { family: 'JetBrains Mono', size: 10 },
                    },
                    beginAtZero: true,
                }
            },
            animation: {
                duration: 300
            }
        }
    });
}

// ========== 更新統計數據 ==========
async function updateStats() {
    try {
        const response = await fetch('/api/stats');
        const stats = await response.json();
        
        if (stats.error) return;
        
        document.getElementById('totalPkts').textContent = stats.total_pkts || 0;
        document.getElementById('arpPkts').textContent = stats.arp_pkts || 0;
        document.getElementById('uniqueMacs').textContent = stats.unique_src_macs || 0;
        
        // 更新趨勢
        if (prevStats) {
            updateTrend('totalTrend', stats.total_pkts, prevStats.total_pkts);
            
            // ARP 卡片警示（門檻從 status API 獲取，預設 10）
            const arpThreshold = window.currentThresholds?.arp || 10;
            const arpCard = document.getElementById('arpPktsCard');
            if (stats.arp_pkts > arpThreshold) {
                arpCard.classList.add('alert');
                document.getElementById('arpTrend').innerHTML = '⚠️ 超過門檻!';
                document.getElementById('arpTrend').className = 'stat-trend up';
            } else {
                arpCard.classList.remove('alert');
                document.getElementById('arpTrend').innerHTML = `門檻: ${arpThreshold}`;
                document.getElementById('arpTrend').className = 'stat-trend normal';
            }
            
            // MAC 卡片警示（門檻從 status API 獲取，預設 10）
            const macThreshold = window.currentThresholds?.mac || 10;
            const macCard = document.getElementById('uniqueMacsCard');
            if (stats.unique_src_macs > macThreshold) {
                macCard.classList.add('alert');
                document.getElementById('macTrend').innerHTML = '⚠️ 超過門檻!';
                document.getElementById('macTrend').className = 'stat-trend up';
            } else {
                macCard.classList.remove('alert');
                document.getElementById('macTrend').innerHTML = `門檻: ${macThreshold}`;
                document.getElementById('macTrend').className = 'stat-trend normal';
            }
        }
        
        prevStats = stats;
    } catch (e) {
        console.error('Failed to fetch stats:', e);
    }
}

// ========== 更新趨勢指示 ==========
function updateTrend(elementId, current, previous) {
    const el = document.getElementById(elementId);
    const diff = current - previous;
    if (diff > 10) {
        el.innerHTML = '↑ 上升';
        el.className = 'stat-trend up';
    } else if (diff < -10) {
        el.innerHTML = '↓ 下降';
        el.className = 'stat-trend down';
    } else {
        el.innerHTML = '— 穩定';
        el.className = 'stat-trend normal';
    }
}

// ========== 更新歷史圖表 ==========
async function updateHistory() {
    try {
        const response = await fetch('/api/history');
        const history = await response.json();
        
        chartData.labels = history.map(h => {
            const date = new Date(h.timestamp * 1000);
            return date.toLocaleTimeString('zh-TW', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        });
        chartData.datasets[0].data = history.map(h => h.total_pkts);
        chartData.datasets[1].data = history.map(h => h.arp_pkts);
        chartData.datasets[2].data = history.map(h => h.unique_src_macs);
        
        chart.update('none');
    } catch (e) {
        console.error('Failed to fetch history:', e);
    }
}

// ========== 更新警報列表 ==========
async function updateAlerts() {
    try {
        const response = await fetch('/api/alerts');
        const alerts = await response.json();
        
        const alertsList = document.getElementById('alertsList');
        document.getElementById('alertCount').textContent = alerts.length;
        
        if (alerts.length === 0) {
            alertsList.innerHTML = `
                <div class="no-alerts">
                    <div class="no-alerts-icon">✅</div>
                    <div>目前沒有警報</div>
                </div>
            `;
        } else {
            alertsList.innerHTML = alerts.map(alert => {
                let typeClass = '';
                if (alert.type === 'BLOCK') typeClass = 'block';
                if (alert.type === 'UNBLOCK') typeClass = 'unblock';
                
                return `
                    <div class="alert-item ${typeClass}">
                        <div class="alert-type">${alert.type}</div>
                        <div class="alert-message">${alert.message}</div>
                        <div class="alert-time">${alert.timestamp}</div>
                    </div>
                `;
            }).join('');
        }
        
        // 新警報提示
        if (alerts.length > lastAlertCount && lastAlertCount > 0) {
            // 可在此加入提示音效
        }
        lastAlertCount = alerts.length;
        
    } catch (e) {
        console.error('Failed to fetch alerts:', e);
    }
}

// ========== 更新封鎖列表 ==========
async function updateBlocked() {
    try {
        const response = await fetch('/api/blocked');
        const blocked = await response.json();
        
        document.getElementById('blockedCount').textContent = blocked.length;
        
        const blockedList = document.getElementById('blockedList');
        
        if (blocked.length === 0) {
            blockedList.innerHTML = '<div class="no-blocked">尚無封鎖的 MAC</div>';
        } else {
            blockedList.innerHTML = blocked.map(mac => `
                <div class="mac-item">
                    <span class="mac-address">${mac}</span>
                    <button class="unblock-btn" onclick="unblockMac('${mac}')">解除封鎖</button>
                </div>
            `).join('');
        }
    } catch (e) {
        console.error('Failed to fetch blocked:', e);
    }
}

// ========== 更新系統狀態 ==========
async function updateStatus() {
    try {
        const response = await fetch('/api/status');
        const status = await response.json();
        
        // 儲存門檻值到全域變數供其他函數使用
        window.currentThresholds = status.thresholds;
        
        const statusDot = document.getElementById('systemStatus');
        const statusText = document.getElementById('statusText');
        
        if (status.arp_under_attack || status.mac_under_attack) {
            statusDot.className = 'status-dot alert';
            statusText.textContent = '⚠️ 偵測到攻擊!';
        } else {
            statusDot.className = 'status-dot online';
            statusText.textContent = '系統監控中...';
        }
        
        // 更新門檻顯示
        document.getElementById('thresholdArp').textContent = `${status.thresholds.arp} pkts/s`;
        document.getElementById('thresholdArpConsec').textContent = `${status.thresholds.arp_consec} 秒`;
        document.getElementById('thresholdMac').textContent = `${status.thresholds.mac} MACs/s`;
        document.getElementById('thresholdMacConsec').textContent = `${status.thresholds.mac_consec} 秒`;
        
    } catch (e) {
        console.error('Failed to fetch status:', e);
    }
}

// ========== 解除封鎖 MAC ==========
async function unblockMac(mac) {
    try {
        const response = await fetch('/api/unblock', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ mac })
        });
        const result = await response.json();
        
        if (result.success) {
            updateBlocked();
            updateAlerts();
        } else {
            alert(result.error || '解除封鎖失敗');
        }
    } catch (e) {
        console.error('Failed to unblock:', e);
    }
}

// ========== 清除所有警報 ==========
async function clearAlerts() {
    try {
        await fetch('/api/clear_alerts', { method: 'POST' });
        updateAlerts();
    } catch (e) {
        console.error('Failed to clear alerts:', e);
    }
}

// ========== 啟動定時輪詢 ==========
function startPolling() {
    // 初始載入
    updateStats();
    updateHistory();
    updateAlerts();
    updateBlocked();
    updateStatus();
    
    // 定時更新
    setInterval(updateStats, 1000);
    setInterval(updateHistory, 1000);
    setInterval(updateAlerts, 2000);
    setInterval(updateBlocked, 3000);
    setInterval(updateStatus, 1000);
    setInterval(updateAIStatus, 1000);

}

// ========== 頁面載入時初始化 ==========
document.addEventListener('DOMContentLoaded', () => {
    initChart();
    startPolling();
});

// ========== AI 狀態更新 ==========
async function updateAIStatus() {
    try {
        const res = await fetch("/api/ai_status");
        const ai = await res.json();

        document.getElementById("ai-prediction").textContent = ai.prediction;
        document.getElementById("ai-confidence").textContent =
            (ai.confidence * 100).toFixed(1) + "%";
        document.getElementById("ai-source").textContent = ai.source;

        const box = document.getElementById("ai-status-box");
        if (ai.prediction === "ARP_FLOOD") {
            box.className = "ai-box alert";
        } else {
            box.className = "ai-box normal";
        }
    } catch (e) {
        console.error("AI status error:", e);
    }
}
