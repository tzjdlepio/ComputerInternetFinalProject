# 🛡️ AI-Assisted Secure Switch

**Mininet + Open vSwitch (OVS) 智慧安全交換機原型**

本專題在 Mininet + Open vSwitch (OVS) 平台上建置一個具備  
**流量蒐集、異常偵測、自動封包控制與 AI 輔助分析** 的軟體交換機雛形。

系統能即時監控網路封包特徵，透過 **規則式（Rule-based）偵測機制**  
偵測 ARP Flood / MAC Flood 類型攻擊，並自動對攻擊來源下達封鎖（drop）策略。

此外，本系統導入 **機器學習（AI）模型** 作為 **輔助偵測模組**，  
用以分析即時流量行為模式，驗證異常是否屬於實際攻擊，而非單純高流量情境。

---

## 📌 專題目標 (Project Requirements)

| 項目 | 說明 | 目前完成狀態 |
| --- | --- | --- |
| 即時流量蒐集（Flow / Packet Level） | 使用 `tshark` 即時監控 OVS ports 流量特徵（total packets、ARP packets、unique MACs） | ✅ collector.py 已完成 |
| 規則式異常偵測（ARP / MAC Flood） | 依據 ARP 封包數量與來源 MAC 數量進行異常判斷 | ⚠️ ARP Flood 已完成 |
| AI 輔助異常分析 | 使用機器學習模型分析流量行為模式（非僅依封包數） | ✅ 已完成（僅輔助） |
| 自動控制回應（Drop） | 偵測到攻擊後使用 `ovs-ofctl` 注入 flow 封鎖來源 MAC | ✅ 已完成 |
| Web Dashboard | 即時顯示流量趨勢、警報狀態與 AI 判斷結果 | ✅ 已完成 |
| Mininet 拓撲 | 4 hosts + 1 OVS switch | ✅ 已完成 |
| 攻擊模擬（ARP Flood） | 使用 arping 模擬洪水攻擊 | ✅ 已完成 |
| 實驗驗證 | 比較正常高流量與實際攻擊下之偵測結果 | ✅ 已完成 |

---

## 📂 專案結構 (Project Structure)

```text
FinalProject/
│
├── topo_4h1s.py              # Mininet 4 hosts + 1 switch 拓撲
├── collector.py              # 使用 tshark 即時收集封包特徵
├── detector.py               # 規則式偵測 + 自動下 OVS flow + AI 輔助分析
├── dashboard.py              # Web Dashboard（Flask）
├── templates/
│   └── index.html            # Dashboard HTML
├── static/
│   ├── css/
│   │   └── style.css         # Dashboard 樣式
│   └── js/
│       └── main.js           # Dashboard 前端邏輯
├── attack_arp_flood.sh       # ARP Flood 攻擊腳本
├── stats.json                # 即時流量統計資料
├── ai_model.pkl              # 訓練完成之 AI 模型
├── requirements.txt          # Python 套件需求
└── README.md                 # 專案說明文件

🔌 系統運作流程 (Architecture)
[ Mininet Hosts ]
h1  h2  h3  h4   ← 攻擊來源 h3
      │
      ▼
+----------------+
|     OVS s1     |
+----------------+
      ▲
      │
  tshark 收集流量
      │
      ▼
 collector.py
      │
      ▼
 stats.json
      │
      ├─▶ 規則式偵測（detector.py）
      │      └─▶ ovs-ofctl drop flow
      │
      └─▶ AI 模型推論（輔助分析）
               │
               ▼
          Web Dashboard
          
🚀 執行方式 (How to Run)
📘 Terminal 1 — 啟動 Mininet 拓撲
sudo python3 topo_4h1s.py


測試連線：

mininet> pingall

📘 Terminal 2 — 啟動即時封包蒐集器
cd FinalProject/
sudo python3 collector.py


stats.json 範例：

{
  "timestamp_epoch": 1765528500,
  "total_pkts": 120,
  "arp_pkts": 25,
  "unique_src_macs": 3,
  "src_macs": ["00:00:00:00:00:01"]
}

📘 Terminal 3 — 啟動異常偵測器
cd FinalProject/
sudo python3 detector.py


偵測到 ARP Flood 時：

[WARNING] ARP FLOOD DETECTED
→ Applying DROP rule via ovs-ofctl

📘 Terminal 4 — 啟動 Web Dashboard（可選）
cd FinalProject/
pip install -r requirements.txt
python3 dashboard.py


瀏覽器開啟：

http://localhost:5000


Dashboard 顯示內容：

📈 即時流量趨勢（Total / ARP / MAC）

⚠️ 規則式偵測警報

🚫 封鎖列表

⚙️ 偵測門檻

🤖 AI 判斷結果（NORMAL / ARP_FLOOD + 信心值）

🤖 說明：AI 模組僅作為輔助分析，不直接參與封鎖決策。

⚔️ 攻擊模擬（ARP Flood）
mininet> h3 ./attack_arp_flood.sh


可觀察到：

ARP 封包比例明顯上升

detector 觸發警報並封鎖來源 MAC

Dashboard 即時顯示流量與 AI 判斷結果

🧪 實驗方法

Baseline（正常流量）

僅進行 ping / TCP 傳輸

Rule 與 AI 均判定為 NORMAL

ARP Flood 攻擊

啟動攻擊腳本

Rule 觸發封鎖

AI 同步判定為 ARP_FLOOD

高流量非攻擊情境（AI 驗證）

產生大量非 ARP 流量

驗證 AI 不會因封包數過高而誤判

🔧 可進一步延伸
項目	說明
MAC Flood 攻擊	使用 scapy 產生大量假 MAC
Rate Limiting	使用 OVS meter table 取代 drop
偵測效能分析	偵測時間、誤判率、Rule vs AI 比較
✔️ 系統完成度總結

✔ 建立完整 Mininet + OVS 網路環境

✔ 即時流量蒐集與統計

✔ 規則式異常偵測與自動封鎖

✔ AI 輔助行為分析（非僅依封包數）

✔ Web Dashboard 即時視覺化

✔ 可完整 demo「蒐集 → 偵測 → 防禦 → 分析」流程