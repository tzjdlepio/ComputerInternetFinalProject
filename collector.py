#!/usr/bin/env python3
"""
collector.py

功能：
    針對 Mininet 拓樸中的 OVS 交換機介面（例如 s1-eth1~s1-eth4）
    使用 tshark 進行即時封包截取，並且每「一秒」統計一次：

        - total_pkts      : 總封包數
        - arp_pkts        : ARP 封包數
        - unique_src_macs : 不同來源 MAC 數量

    並將統計結果寫入 stats.json（之後 detector / Web Dashboard 可以拿這份檔案來用）。
"""

import subprocess
import json
import sys
from datetime import datetime
from pathlib import Path

# 你可以依拓樸修改要監聽的 OVS 介面
INTERFACES = ["s1-eth1", "s1-eth2", "s1-eth3", "s1-eth4"]

STATS_JSON_PATH = Path("stats.json")


def build_tshark_cmd(interfaces):
    """
    根據指定介面組出 tshark 指令
    """
    cmd = ["tshark"]

    # -i 介面1 -i 介面2 ...
    for ifname in interfaces:
        cmd += ["-i", ifname]

    # 不要印出一堆額外訊息，只要封包資料
    cmd += ["-q"]

    # 只輸出我們要的欄位：
    #   frame.time_epoch   : 時間戳 (unix time, 秒.小數)
    #   eth.src            : 來源 MAC
    #   _ws.col.Protocol   : 協定名稱 (不一定可靠，但可用來 debug)
    #   arp.opcode         : 如果是 ARP 會有值，否則空
    cmd += [
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "eth.src",
        "-e", "_ws.col.Protocol",
        "-e", "arp.opcode",
        "-l",  # line buffered，讓我們可以即時讀取輸出
    ]

    # 不另外加 display filter，全部抓下來，在 Python 內自己判斷是不是 ARP
    return cmd


def collector_loop():
    """
    以無限迴圈方式執行 tshark，並且每秒統計一次封包資訊
    """

    cmd = build_tshark_cmd(INTERFACES)
    print(">>> collector.py 啟動")
    print(">>> Running:", " ".join(cmd))

    # 啟動 tshark 子行程
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,  # line-buffered
        )
    except FileNotFoundError:
        print("!!! 找不到 tshark，請先安裝 Wireshark / tshark", file=sys.stderr)
        sys.exit(1)

    total_pkts = 0
    arp_pkts = 0
    src_macs = set()
    current_sec = None  # 目前統計的是哪一「秒」

    def flush_stats(sec):
        """
        當時間換秒時，輸出上一秒的統計結果到 stats.json
        """
        nonlocal total_pkts, arp_pkts, src_macs

        if sec is None:
            return

        # 將 epoch 秒數轉成可讀時間字串
        ts_readable = datetime.fromtimestamp(sec).strftime("%Y-%m-%d %H:%M:%S")

        stats = {
            "timestamp_epoch": sec,
            "timestamp_readable": ts_readable,
            "total_pkts": total_pkts,
            "arp_pkts": arp_pkts,
            "unique_src_macs": len(src_macs),
            "src_macs": sorted(src_macs),
        }

        try:
            with open(STATS_JSON_PATH, "w") as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            print(f"!!! 寫入 {STATS_JSON_PATH} 失敗：{e}", file=sys.stderr)

        # 下一秒要重新計數，所以這裡先 reset 數值
        total_pkts = 0
        arp_pkts = 0
        src_macs = set()

    # 逐行讀取 tshark 輸出
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue

        parts = line.split("\t")
        # 期望格式：
        #   parts[0] = frame.time_epoch
        #   parts[1] = eth.src
        #   parts[2] = _ws.col.Protocol
        #   parts[3] = arp.opcode (如果是 ARP 會有值)

        try:
            epoch = float(parts[0])
        except (IndexError, ValueError):
            continue

        sec = int(epoch)

        # 如果是新的秒數，先把上一秒 flush 出去
        if current_sec is None:
            current_sec = sec
        elif sec != current_sec:
            flush_stats(current_sec)
            current_sec = sec

        # 更新統計
        total_pkts += 1

        # parts[1]: eth.src (來源 MAC)
        if len(parts) >= 2 and parts[1]:
            src_macs.add(parts[1])

        # parts[2]: _ws.col.Protocol (協定名稱，例如 "ARP", "TCP", ...)，純粹 debug 用
        proto = ""
        if len(parts) >= 3 and parts[2]:
            proto = parts[2].upper()

        # parts[3]: arp.opcode
        arp_opcode = ""
        if len(parts) >= 4 and parts[3]:
            arp_opcode = parts[3]

        # 只要有 arp.opcode，就一定是 ARP 封包
        # （為了保險也保留原本的 "ARP" in proto 判斷）
        if arp_opcode or "ARP" in proto:
            arp_pkts += 1

    # 如果 tshark 結束了，最後再 flush 一次
    flush_stats(current_sec)
    proc.wait()


if __name__ == "__main__":
    collector_loop()
