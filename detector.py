#!/usr/bin/env python3
"""
detector.py

功能：
    每秒讀取一次 stats.json（由 collector.py 產生），
    根據以下規則做「簡單的規則式異常偵測」：

        1. ARP Flood：
            - 若 arp_pkts > THRESHOLD_ARP，且連續超過 ARP_CONSEC 秒
            - 則判定為 ARP Flood

        2. MAC Flood：
            - 若 unique_src_macs > THRESHOLD_MAC，且連續超過 MAC_CONSEC 秒
            - 則判定為 MAC Flood

    當偵測到攻擊時：
        - 在 terminal 印出警告與詳細資訊
        - 若 ACTION_MODE = "block"，
          則針對當前秒出現的所有 src_macs，
          呼叫 ovs-ofctl 在交換機 s1 上新增 drop flow：
              dl_src=<mac>,actions=drop

使用方式：
    請搭配 topo_4h1s.py + collector.py 一起使用。

    Terminal A:
        sudo python3 topo_4h1s.py

    Terminal B:
        sudo python3 collector.py

    Terminal C:
        sudo python3 detector.py
"""

import json
import time
import subprocess
import os
from datetime import datetime

# --- 基本設定 ---

# stats.json 路徑（collector.py 產生的檔案）
STATS_JSON_PATH = "stats.json"

# OVS 交換機名稱（你的 topo 預設就是 s1）
SWITCH_NAME = "s1"

# 動作模式：
#   "log"   : 只偵測與印出警告，不真的下封包
#   "block" : 偵測到攻擊時，用 ovs-ofctl 封鎖 MAC
ACTION_MODE = "block"

# ARP Flood 偵測門檻
THRESHOLD_ARP = 50          # 一秒內 ARP 封包數超過多少視為「高」
ARP_CONSEC = 3              # 連續幾秒「高」才判定為攻擊

# MAC Flood 偵測門檻
THRESHOLD_MAC = 20          # 一秒內不同來源 MAC 數超過多少視為「高」
MAC_CONSEC = 3              # 連續幾秒「高」才判定為攻擊

# 每幾秒檢查一次 stats.json
POLL_INTERVAL = 1.0


def load_stats(path: str):
    """
    嘗試讀取 stats.json，如果檔案不存在或解析失敗，回傳 None。
    """
    if not os.path.exists(path):
        return None

    try:
        with open(path, "r") as f:
            data = json.load(f)
        return data
    except Exception as e:
        print(f"[detector] 讀取 {path} 失敗：{e}")
        return None


def pretty_time(epoch_sec: float) -> str:
    """
    將 epoch 秒數轉成可讀時間字串。
    """
    try:
        return datetime.fromtimestamp(epoch_sec).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return str(epoch_sec)


def block_mac(switch: str, mac: str):
    """
    在指定的 OVS 交換機上，新增一條 drop flow：
        priority=200, dl_src=<mac>, actions=drop

    這裡使用 ovs-ofctl 控制 OVS。
    """
    cmd = [
        "sudo", "ovs-ofctl", "add-flow", switch,
        f"priority=200,dl_src={mac},actions=drop"
    ]
    print(f"[detector] 呼叫指令：{' '.join(cmd)}")
    try:
        # 不強制 check=True，避免 ovs-ofctl 失敗時整個程式崩掉
        subprocess.run(cmd, check=False)
    except Exception as e:
        print(f"[detector] 封鎖 MAC {mac} 失敗：{e}")


def handle_arp_attack(stats: dict, blocked_macs: set):
    """
    處理 ARP Flood 事件：
        - 印出警告訊息
        - 若 ACTION_MODE = 'block'，則封鎖這一秒出現的所有 MAC
    """
    ts = stats.get("timestamp_epoch", 0)
    ts_readable = stats.get("timestamp_readable", pretty_time(ts))
    arp_pkts = stats.get("arp_pkts", 0)
    macs = stats.get("src_macs", [])

    print("\n================= ⚠ ARP FLOOD DETECTED ⚠ =================")
    print(f"時間        : {ts_readable} ({ts})")
    print(f"ARP 封包數  : {arp_pkts}")
    print(f"來源 MAC 數 : {len(macs)}")
    print(f"來源 MAC 列表：{macs}")
    print("==========================================================\n")

    if ACTION_MODE == "block":
        for mac in macs:
            if mac not in blocked_macs:
                print(f"[detector] (ARP) 封鎖 MAC: {mac}")
                block_mac(SWITCH_NAME, mac)
                blocked_macs.add(mac)
    else:
        print("[detector] ACTION_MODE='log'，僅顯示警告，不實際封鎖。")


def handle_mac_attack(stats: dict, blocked_macs: set):
    """
    處理 MAC Flood 事件：
        - 印出警告訊息
        - 若 ACTION_MODE = 'block'，則封鎖這一秒出現的所有 MAC
    """
    ts = stats.get("timestamp_epoch", 0)
    ts_readable = stats.get("timestamp_readable", pretty_time(ts))
    uniq_mac = stats.get("unique_src_macs", 0)
    macs = stats.get("src_macs", [])

    print("\n================= ⚠ MAC FLOOD DETECTED ⚠ =================")
    print(f"時間            : {ts_readable} ({ts})")
    print(f"不同來源 MAC 數 : {uniq_mac}")
    print(f"來源 MAC 列表   : {macs}")
    print("==========================================================\n")

    if ACTION_MODE == "block":
        for mac in macs:
            if mac not in blocked_macs:
                print(f"[detector] (MAC) 封鎖 MAC: {mac}")
                block_mac(SWITCH_NAME, mac)
                blocked_macs.add(mac)
    else:
        print("[detector] ACTION_MODE='log'，僅顯示警告，不實際封鎖。")


def detector_loop():
    """
    主偵測迴圈：
        - 每 POLL_INTERVAL 秒讀一次 stats.json
        - 根據 ARP / MAC 門檻，累積連續「高流量」秒數
        - 連續秒數達門檻後，觸發 handle_arp_attack / handle_mac_attack
    """

    last_timestamp = None

    # 累積「高」的秒數
    arp_high_count = 0
    mac_high_count = 0

    # 是否已進入攻擊狀態，用來避免一直重複觸發
    arp_under_attack = False
    mac_under_attack = False

    # 記錄已封鎖過的 MAC，避免重複下 flow
    blocked_macs = set()

    print(">>> detector.py 啟動")
    print(f"    監控檔案   : {STATS_JSON_PATH}")
    print(f"    Switch     : {SWITCH_NAME}")
    print(f"    ACTION_MODE: {ACTION_MODE}")
    print(f"    ARP 門檻   : {THRESHOLD_ARP} pkts/s, 連續 {ARP_CONSEC} 秒")
    print(f"    MAC 門檻   : {THRESHOLD_MAC} src_macs/s, 連續 {MAC_CONSEC} 秒")
    print("    (按 Ctrl+C 結束)\n")

    try:
        while True:
            stats = load_stats(STATS_JSON_PATH)
            if stats is None:
                # stats.json 還沒被建立或讀取失敗
                time.sleep(POLL_INTERVAL)
                continue

            ts = stats.get("timestamp_epoch", None)
            if ts is None:
                time.sleep(POLL_INTERVAL)
                continue

            # 若時間沒有更新，代表 collector 還沒產生新一秒的統計
            if ts == last_timestamp:
                time.sleep(POLL_INTERVAL)
                continue

            last_timestamp = ts

            # 讀取目前一秒的統計值
            arp_pkts = stats.get("arp_pkts", 0)
            uniq_mac = stats.get("unique_src_macs", 0)
            total_pkts = stats.get("total_pkts", 0)
            ts_readable = stats.get("timestamp_readable", pretty_time(ts))

            # summary log：這邊是「主要觀察視窗」
            print(
                f"[detector {ts_readable}] total={total_pkts:<5} "
                f"arp={arp_pkts:<5} unique_src_mac={uniq_mac}"
            )

            # --- ARP Flood 偵測 ---
            if arp_pkts > THRESHOLD_ARP:
                arp_high_count += 1
            else:
                arp_high_count = 0
                arp_under_attack = False  # 回到正常狀態

            if arp_high_count >= ARP_CONSEC and not arp_under_attack:
                # 首次達到連續門檻，觸發攻擊事件
                arp_under_attack = True
                handle_arp_attack(stats, blocked_macs)

            # --- MAC Flood 偵測 ---
            if uniq_mac > THRESHOLD_MAC:
                mac_high_count += 1
            else:
                mac_high_count = 0
                mac_under_attack = False

            if mac_high_count >= MAC_CONSEC and not mac_under_attack:
                mac_under_attack = True
                handle_mac_attack(stats, blocked_macs)

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:
        print("\n>>> detector.py 結束")


if __name__ == "__main__":
    detector_loop()
