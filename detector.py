#!/usr/bin/env python3
"""
detector.py (Hybrid Rule-based + AI)

功能：
    - 每秒讀取 stats.json
    - 使用「規則式 + AI」混合偵測 ARP Flood
    - MAC Flood 仍維持規則式
    - 偵測到攻擊後自動對 OVS 下 drop flow
"""

import json
import time
import subprocess
import os
from datetime import datetime

# === AI 相關 import ===
import joblib
import pandas as pd

# ---------------- 基本設定 ----------------

STATS_JSON_PATH = "stats.json"
SWITCH_NAME = "s1"

# 模式設定
ACTION_MODE = "block"   # "log" | "block"

# 是否啟用 AI
USE_AI = True
AI_MODEL_PATH = "ai_model.pkl"

# 規則式門檻
THRESHOLD_ARP = 50
ARP_CONSEC = 3

THRESHOLD_MAC = 20
MAC_CONSEC = 3

POLL_INTERVAL = 1.0

AI_RESULT_PATH = "ai_result.json"


# ---------------- AI 模型載入 ----------------

ai_model = None
if USE_AI:
    try:
        ai_model = joblib.load(AI_MODEL_PATH)
        print("[detector] AI model loaded successfully")
    except Exception as e:
        print(f"[detector] AI model load failed: {e}")
        USE_AI = False

# ---------------- 工具函式 ----------------

def load_stats(path):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return None


def pretty_time(epoch):
    try:
        return datetime.fromtimestamp(epoch).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(epoch)


def block_mac(switch, mac):
    cmd = [
        "sudo", "ovs-ofctl", "add-flow", switch,
        f"priority=200,dl_src={mac},actions=drop"
    ]
    subprocess.run(cmd, check=False)


# ---------------- 攻擊處理 ----------------

def handle_arp_attack(stats, blocked_macs):
    ts = stats.get("timestamp_epoch", 0)
    ts_readable = stats.get("timestamp_readable", pretty_time(ts))
    macs = stats.get("src_macs", [])
    arp_pkts = stats.get("arp_pkts", 0)

    print("\n========== ⚠ ARP FLOOD DETECTED ⚠ ==========")
    print(f"Time        : {ts_readable}")
    print(f"ARP packets : {arp_pkts}")
    print(f"MACs        : {macs}")
    print("===========================================\n")

    if ACTION_MODE == "block":
        for mac in macs:
            if mac not in blocked_macs:
                print(f"[detector] Block MAC (ARP): {mac}")
                block_mac(SWITCH_NAME, mac)
                blocked_macs.add(mac)


def handle_mac_attack(stats, blocked_macs):
    ts = stats.get("timestamp_epoch", 0)
    ts_readable = stats.get("timestamp_readable", pretty_time(ts))
    macs = stats.get("src_macs", [])

    print("\n========== ⚠ MAC FLOOD DETECTED ⚠ ==========")
    print(f"Time  : {ts_readable}")
    print(f"MACs  : {macs}")
    print("===========================================\n")

    if ACTION_MODE == "block":
        for mac in macs:
            if mac not in blocked_macs:
                print(f"[detector] Block MAC (MAC): {mac}")
                block_mac(SWITCH_NAME, mac)
                blocked_macs.add(mac)


# ---------------- 主偵測迴圈 ----------------

def detector_loop():
    last_ts = None

    arp_high_count = 0
    mac_high_count = 0

    arp_under_attack = False
    mac_under_attack = False

    blocked_macs = set()

    print(">>> Hybrid detector started")
    print(f"    USE_AI      : {USE_AI}")
    print(f"    ACTION_MODE : {ACTION_MODE}\n")

    while True:
        stats = load_stats(STATS_JSON_PATH)
        if stats is None:
            time.sleep(POLL_INTERVAL)
            continue

        ts = stats.get("timestamp_epoch")
        if ts == last_ts:
            time.sleep(POLL_INTERVAL)
            continue
        last_ts = ts

        total_pkts = stats.get("total_pkts", 0)
        arp_pkts = stats.get("arp_pkts", 0)
        uniq_mac = stats.get("unique_src_macs", 0)

        arp_ratio = arp_pkts / total_pkts if total_pkts > 0 else 0

        ts_readable = stats.get("timestamp_readable", pretty_time(ts))

        print(
            f"[{ts_readable}] total={total_pkts:<5} "
            f"arp={arp_pkts:<5} unique_mac={uniq_mac}"
        )

        # ===== ARP Flood（Hybrid） =====

        rule_says_attack = arp_pkts > THRESHOLD_ARP

        ai_says_attack = False
        if USE_AI and ai_model is not None:
            X = pd.DataFrame([{
                "total_pkts": total_pkts,
                "arp_pkts": arp_pkts,
                "unique_src_macs": uniq_mac,
                "arp_ratio": arp_ratio
            }])
            try:
                ai_pred = ai_model.predict(X)[0]
                ai_conf = 0.0

                if hasattr(ai_model, "predict_proba"):
                    ai_conf = ai_model.predict_proba(X)[0][ai_pred]

                ai_says_attack = (ai_pred == 1)

                # === 寫入 AI 結果給 Dashboard ===
                ai_result = {
                    "timestamp_epoch": ts,
                    "prediction": "ARP_FLOOD" if ai_pred == 1 else "NORMAL",
                    "confidence": round(float(ai_conf), 3),
                    "source": "AI" if ai_says_attack else "RULE",
                    "hybrid_triggered": bool(rule_says_attack or ai_says_attack)
                }

                with open(AI_RESULT_PATH, "w") as f:
                    json.dump(ai_result, f, indent=2)

            except Exception as e:
                print(f"[detector] AI predict error: {e}")

        if rule_says_attack or ai_says_attack:
            arp_high_count += 1
        else:
            arp_high_count = 0
            arp_under_attack = False

        if arp_high_count >= ARP_CONSEC and not arp_under_attack:
            arp_under_attack = True
            handle_arp_attack(stats, blocked_macs)

        # ===== MAC Flood（Rule-based） =====

        if uniq_mac > THRESHOLD_MAC:
            mac_high_count += 1
        else:
            mac_high_count = 0
            mac_under_attack = False

        if mac_high_count >= MAC_CONSEC and not mac_under_attack:
            mac_under_attack = True
            handle_mac_attack(stats, blocked_macs)

        time.sleep(POLL_INTERVAL)


if __name__ == "__main__":
    detector_loop()
