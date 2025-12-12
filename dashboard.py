#!/usr/bin/env python3
"""
dashboard.py - Web Dashboard（簡化版）
"""

import json
import os
import subprocess
import threading
import time
from datetime import datetime
from collections import deque
from flask import Flask, render_template, jsonify, request

app = Flask(__name__)

# ========== 設定 ==========
STATS_JSON_PATH = "stats.json"
SWITCH_NAME = "s1"
THRESHOLD_ARP = 10
ARP_CONSEC = 2
THRESHOLD_MAC = 10
MAC_CONSEC = 2
HISTORY_SIZE = 60

# ========== 全域狀態 ==========
history_data = deque(maxlen=HISTORY_SIZE)
alerts = []
blocked_macs = set()
detection_state = {
    "arp_high_count": 0,
    "mac_high_count": 0,
    "arp_under_attack": False,
    "mac_under_attack": False,
    "last_timestamp": None,
}


def load_stats():
    """讀取 stats.json"""
    if not os.path.exists(STATS_JSON_PATH):
        return None
    try:
        with open(STATS_JSON_PATH, "r") as f:
            return json.load(f)
    except:
        return None


def block_mac(mac: str):
    """封鎖 MAC"""
    cmd = ["ovs-ofctl", "add-flow", SWITCH_NAME, f"priority=200,dl_src={mac},actions=drop"]
    print(f"[dashboard] 🚫 封鎖 MAC: {mac}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            print(f"[dashboard] ✅ 封鎖成功")
            return True
        else:
            print(f"[dashboard] ❌ 失敗: {result.stderr}")
            return False
    except Exception as e:
        print(f"[dashboard] ❌ 例外: {e}")
        return False


def add_alert(alert_type: str, message: str):
    """新增警報"""
    global alerts
    alert = {
        "id": len(alerts) + 1,
        "type": alert_type,
        "message": message,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
    alerts.insert(0, alert)
    if len(alerts) > 50:
        alerts = alerts[:50]
    print(f"[dashboard] 📝 新增警報: {message}")


def monitor_loop():
    """背景監控"""
    global detection_state, blocked_macs
    
    print("[dashboard] 🔄 監控執行緒啟動")
    
    while True:
        try:
            stats = load_stats()
            if stats is None:
                time.sleep(1)
                continue
            
            ts = stats.get("timestamp_epoch")
            if ts is None or ts == detection_state["last_timestamp"]:
                time.sleep(0.5)
                continue
            
            detection_state["last_timestamp"] = ts
            
            # 儲存歷史
            history_data.append({
                "timestamp": ts,
                "total_pkts": stats.get("total_pkts", 0),
                "arp_pkts": stats.get("arp_pkts", 0),
                "unique_src_macs": stats.get("unique_src_macs", 0),
            })
            
            arp_pkts = stats.get("arp_pkts", 0)
            macs = stats.get("src_macs", [])
            
            # ARP Flood 偵測
            if arp_pkts > THRESHOLD_ARP:
                detection_state["arp_high_count"] += 1
                print(f"[dashboard] ⚠️ ARP 高: {arp_pkts} (連續 {detection_state['arp_high_count']})")
            else:
                detection_state["arp_high_count"] = 0
                detection_state["arp_under_attack"] = False
            
            if detection_state["arp_high_count"] >= ARP_CONSEC and not detection_state["arp_under_attack"]:
                detection_state["arp_under_attack"] = True
                print(f"[dashboard] 🚨 ARP FLOOD 確認！")
                add_alert("ARP_FLOOD", f"ARP Flood 攻擊！封包數: {arp_pkts}/秒")
                
                # 封鎖 MAC（在鎖外面執行）
                for mac in macs:
                    if mac not in blocked_macs:
                        if block_mac(mac):
                            blocked_macs.add(mac)
                            add_alert("BLOCK", f"已封鎖: {mac}")
            
            time.sleep(1)
            
        except Exception as e:
            print(f"[dashboard] ❌ 監控錯誤: {e}")
            time.sleep(1)


# ========== API ==========

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/api/stats")
def api_stats():
    stats = load_stats()
    if stats:
        return jsonify(stats)
    return jsonify({"error": "無資料", "total_pkts": 0, "arp_pkts": 0, "unique_src_macs": 0})


@app.route("/api/history")
def api_history():
    return jsonify(list(history_data))


@app.route("/api/alerts")
def api_alerts():
    return jsonify(alerts)


@app.route("/api/blocked")
def api_blocked():
    return jsonify(list(blocked_macs))


@app.route("/api/status")
def api_status():
    return jsonify({
        "arp_under_attack": detection_state["arp_under_attack"],
        "mac_under_attack": detection_state["mac_under_attack"],
        "blocked_count": len(blocked_macs),
        "alert_count": len(alerts),
        "thresholds": {
            "arp": THRESHOLD_ARP,
            "arp_consec": ARP_CONSEC,
            "mac": THRESHOLD_MAC,
            "mac_consec": MAC_CONSEC,
        }
    })


@app.route("/api/unblock", methods=["POST"])
def api_unblock():
    data = request.get_json()
    mac = data.get("mac")
    if mac and mac in blocked_macs:
        cmd = ["ovs-ofctl", "del-flows", SWITCH_NAME, f"dl_src={mac}"]
        subprocess.run(cmd, capture_output=True, timeout=5)
        blocked_macs.discard(mac)
        add_alert("UNBLOCK", f"已解除: {mac}")
        return jsonify({"success": True})
    return jsonify({"error": "MAC 不存在"}), 404


@app.route("/api/clear_alerts", methods=["POST"])
def api_clear_alerts():
    global alerts
    alerts = []
    return jsonify({"success": True})


# ========== 啟動 ==========

if __name__ == "__main__":
    os.makedirs("templates", exist_ok=True)
    
    # 啟動監控執行緒
    monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()
    
    print("=" * 50)
    print("🛡️  AI-Assisted Secure Switch Dashboard")
    print("=" * 50)
    print(f"📊 監控: {STATS_JSON_PATH}")
    print(f"⚠️  ARP 門檻: {THRESHOLD_ARP} pkts/s")
    print(f"🌐 網址: http://localhost:5000")
    print("=" * 50)
    
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
