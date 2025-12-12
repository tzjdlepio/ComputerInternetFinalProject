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

前置需求：
    - 已安裝 tshark（Wireshark 的 CLI）
        sudo apt-get update
        sudo apt-get install -y tshark

    - 需以 root / sudo 執行：
        sudo python3 collector.py
"""

import subprocess
import json
import signal
import sys
from datetime import datetime

# 針對你現在這個拓樸 (s1 接 4 個 host)，預設要監聽的介面
INTERFACES = ["s1-eth1", "s1-eth2", "s1-eth3", "s1-eth4"]

# 每秒統計結果會寫到這個檔案
STATS_JSON_PATH = "stats.json"


def build_tshark_command(interfaces):
    """
    組合 tshark 指令：
        tshark -i s1-eth1 -i s1-eth2 ... -T fields \
               -e frame.time_epoch -e eth.src -e _ws.col.Protocol -l
    """
    cmd = ["tshark"]

    # 多個 -i 接不同介面
    for iface in interfaces:
        cmd += ["-i", iface]

    # 只輸出我們要的欄位：時間戳、來源 MAC、協定名稱
    cmd += [
        "-T", "fields",
        "-e", "frame.time_epoch",
        "-e", "eth.src",
        "-e", "_ws.col.Protocol",
        "-l",   # line buffered，讓我們可以即時讀取輸出
    ]

    # 不另外加 display filter，全部抓下來，在 Python 內自己判斷是不是 ARP
    return cmd


def collector_loop():
    cmd = build_tshark_command(INTERFACES)

    # 使用 sudo 來執行 tshark
    full_cmd = ["sudo"] + cmd
    print(">>> collector.py 啟動")
    print(">>> Running:", " ".join(full_cmd))

    # 開子行程執行 tshark，stdout 讓我們一行一行讀
    proc = subprocess.Popen(
        full_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        bufsize=1,  # line buffered
    )

    # 儲存目前這一秒的統計
    current_sec = None
    total_pkts = 0
    arp_pkts = 0
    src_macs = set()

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

        # 不再每秒印 log，改由 detector 來統一顯示
        try:
            with open(STATS_JSON_PATH, "w") as f:
                json.dump(stats, f, indent=2)
        except Exception as e:
            print(f"!!! 寫入 {STATS_JSON_PATH} 失敗：{e}", file=sys.stderr)

        # 下一秒要重新計數，所以這裡先 reset 數值
        total_pkts = 0
        arp_pkts = 0
        src_macs.clear()

    def handle_sigint(signum, frame):
        """
        Ctrl+C 時，優雅結束並 flush 最後一批統計
        """
        print("\n>>> 收到中斷訊號，正在結束 collector ...")
        flush_stats(current_sec)
        proc.terminate()
        sys.exit(0)

    # 綁定 Ctrl+C handler
    signal.signal(signal.SIGINT, handle_sigint)

    print(">>> 監聽介面:", ", ".join(INTERFACES))
    print(">>> 每秒更新 stats.json 一次 (Ctrl+C 結束)\n")

    # 主迴圈：一行一行讀 tshark 輸出
    for line in proc.stdout:
        line = line.strip()
        if not line:
            continue

        parts = line.split("\t")
        if len(parts) < 1:
            continue

        # parts[0]: frame.time_epoch
        try:
            ts = float(parts[0])
        except ValueError:
            # 如果時間解析失敗就跳過
            continue

        sec = int(ts)

        if current_sec is None:
            current_sec = sec

        # 如果秒數變了，表示上一秒的統計可以輸出
        if sec != current_sec:
            flush_stats(current_sec)
            current_sec = sec

        # 更新統計
        total_pkts += 1

        # parts[1]: eth.src (來源 MAC)
        if len(parts) >= 2 and parts[1]:
            src_macs.add(parts[1])

        # parts[2]: _ws.col.Protocol (協定名稱，例如 "ARP", "TCP", ...)
        proto = ""
        if len(parts) >= 3 and parts[2]:
            proto = parts[2].upper()

        if "ARP" in proto:
            arp_pkts += 1

    # 如果 tshark 結束了，最後再 flush 一次
    flush_stats(current_sec)
    proc.wait()


if __name__ == "__main__":
    collector_loop()
