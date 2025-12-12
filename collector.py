#!/usr/bin/env python3
"""
collector.py - 封包收集器（簡化版）

使用 tshark 監聽 OVS 介面，每秒統計封包並寫入 stats.json
"""

import subprocess
import json
import time
import threading
from datetime import datetime
from pathlib import Path

# OVS 介面
INTERFACES = ["s1-eth1", "s1-eth2", "s1-eth3", "s1-eth4"]
STATS_JSON_PATH = Path("stats.json")

# 全域統計變數
stats_lock = threading.Lock()
current_stats = {
    "total_pkts": 0,
    "arp_pkts": 0,
    "src_macs": set()
}


def write_stats():
    """每秒寫入統計到 stats.json"""
    while True:
        time.sleep(1)
        
        with stats_lock:
            now = int(time.time())
            ts_readable = datetime.fromtimestamp(now).strftime("%Y-%m-%d %H:%M:%S")
            
            stats = {
                "timestamp_epoch": now,
                "timestamp_readable": ts_readable,
                "total_pkts": current_stats["total_pkts"],
                "arp_pkts": current_stats["arp_pkts"],
                "unique_src_macs": len(current_stats["src_macs"]),
                "src_macs": sorted(current_stats["src_macs"]),
            }
            
            # 輸出統計
            print(f"[{ts_readable}] total={stats['total_pkts']:<5} arp={stats['arp_pkts']:<5} macs={stats['unique_src_macs']}")
            
            # 寫入檔案
            try:
                with open(STATS_JSON_PATH, "w") as f:
                    json.dump(stats, f, indent=2)
            except Exception as e:
                print(f"!!! 寫入失敗: {e}")
            
            # 重置計數
            current_stats["total_pkts"] = 0
            current_stats["arp_pkts"] = 0
            current_stats["src_macs"] = set()


def capture_packets():
    """使用 tshark 抓取封包"""
    cmd = ["tshark"]
    for ifname in INTERFACES:
        cmd += ["-i", ifname]
    cmd += [
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "eth.src",
        "-e", "_ws.col.Protocol",
        "-e", "arp.opcode",
        "-l",
    ]
    
    print(">>> collector.py 啟動")
    print(f">>> 執行: {' '.join(cmd)}")
    
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,
    )
    
    print(">>> 等待封包中...")
    
    pkt_count = 0
    while True:
        line = proc.stdout.readline()
        if not line:
            if proc.poll() is not None:
                print("!!! tshark 已結束")
                break
            continue
        
        line = line.strip()
        if not line:
            continue
        
        parts = line.split("\t")
        
        with stats_lock:
            current_stats["total_pkts"] += 1
            
            # MAC 地址
            if len(parts) >= 2 and parts[1]:
                current_stats["src_macs"].add(parts[1])
            
            # 檢查是否是 ARP
            proto = parts[2].upper() if len(parts) >= 3 and parts[2] else ""
            arp_opcode = parts[3] if len(parts) >= 4 and parts[3] else ""
            
            if arp_opcode or "ARP" in proto:
                current_stats["arp_pkts"] += 1
        
        # 顯示前幾個封包
        pkt_count += 1
        if pkt_count <= 5:
            print(f">>> [封包 {pkt_count}] {line[:60]}")


def main():
    print("=" * 50)
    print("🔍 Packet Collector")
    print("=" * 50)
    
    # 啟動統計寫入執行緒
    writer_thread = threading.Thread(target=write_stats, daemon=True)
    writer_thread.start()
    
    # 開始抓取封包
    try:
        capture_packets()
    except KeyboardInterrupt:
        print("\n>>> 收到中斷信號，結束")
    except Exception as e:
        print(f"!!! 錯誤: {e}")


if __name__ == "__main__":
    main()
