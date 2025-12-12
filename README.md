# 🛡️ AI-Assisted Secure Switch

**Mininet + Open vSwitch (OVS) 智慧安全交換機原型**

本專題在 Mininet + OVS 平台上建置一個具備 **流量蒐集、異常偵測、自動封包控制** 的軟體交換機雛形。
系統能即時監控網路封包特徵，偵測 ARP Flood / MAC Flood 類型攻擊，並自動對攻擊來源下達封鎖（drop）策略。

---

# 📌 專題目標 (Project Requirements)


| 項目                                    | 說明                                                                               | 目前完成狀態                                    |
| --------------------------------------- | ---------------------------------------------------------------------------------- | ----------------------------------------------- |
| **即時流量蒐集（Flow / Packet Level）** | 使用`tshark`即時監控 OVS ports 之流量特徵：total packets、ARP packets、unique MACs | ✅  collector.py 已完成、數據會寫入`stats.json` |
| **規則式異常偵測（ARP / MAC Flood）**   | 偵測 ARP 封包量異常 / MAC 數量突增，自動判定攻擊                                   | ⚠️ ARP Flood 已完成；MAC Flood 可擴充         |
| **自動控制回應（Drop / Rate-limit）**   | 一旦偵測攻擊，立即使用`ovs-ofctl`注入 flow（例如 drop 來源 MAC）                   | ✅ 已完成，detector.py 會自動下指令             |
| **Web Dashboard**                       | 顯示流量趨勢、告警狀態                                                             | ✅ 已完成（dashboard.py + Flask + Chart.js）    |
| **Mininet 拓撲（4 hosts + 1 switch）**  | h1\~ h4 + OVS s1 + controller                                                      | ✅ topo\_4h1s.py 已完成且可啟動                 |
| **封包蒐集程式（tshark）**              | 每秒統計封包資料與 MAC 數量                                                        | ✅ collector.py 已完成                          |
| **攻擊模擬（ARP/MAC Flood）**           | 用 arping/scapy 產生洪水攻擊                                                       | ⚠️ ARP Flood 已完成（attack\_arp\_flood.sh）  |
| **實驗結果（偵測率 / 反應時間）**       | 記錄 detector 時戳與攻擊開始時間做統計                                             | ⏳ 可在 demo 時加入紀錄腳本                     |

---

# 📂 專案結構 (Project Structure)

<pre class="overflow-visible! px-0!" data-start="1280" data-end="1635"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>FinalProject/
│
├── topo_4h1s.py              </span><span># Mininet 4 hosts + 1 switch 拓撲</span><span>
├── collector.py              </span><span># 使用 tshark 即時收集封包特徵</span><span>
├── detector.py               </span><span># 規則式偵測 + 自動下 OVS flow 封鎖來源 MAC</span><span>
├── dashboard.py              </span><span># Web Dashboard 後端（Flask）</span><span>
├── templates/
│   └── index.html            </span><span># Dashboard HTML 結構</span><span>
├── static/
│   ├── css/
│   │   └── style.css         </span><span># Dashboard 樣式表</span><span>
│   └── js/
│       └── main.js           </span><span># Dashboard JavaScript 邏輯</span><span>
├── attack_arp_flood.sh       </span><span># 從 h3 發動 ARP Flood 攻擊</span><span>
├── stats.json                </span><span># collector.py 每秒輸出的流量統計資料</span><span>
├── requirements.txt          </span><span># Python 依賴套件</span><span>
└── README.md                 </span><span># 專案說明（你正在閱讀的文件）</span><span>
</span></span></code></div></div></pre>

---

# 🔌 系統運作流程 (Architecture)

<pre class="overflow-visible! px-0!" data-start="1670" data-end="2058"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>        </span><span>[Mininet Hosts]</span><span>
     </span><span>h1</span><span>  </span><span>h2</span><span>  </span><span>h3</span><span>  </span><span>h4</span><span>  ← (攻擊來源 h3)
         │   │
         ▼   ▼
     +</span><span>----------------</span><span>+
     |     </span><span>OVS</span><span> </span><span>s1</span><span>     |
     +</span><span>----------------</span><span>+
         ▲    ▲
         │    │
  </span><span>tshark</span><span> 收集流量特徵
         │
         ▼
   </span><span>collector</span><span>.py</span><span> ——> </span><span>stats</span><span>.json</span><span>
         │
         ▼
  </span><span>detector</span><span>.py</span><span>（每秒分析）
         │
   若異常 → 下 </span><span>drop</span><span> </span><span>flow</span><span>
         |
         ▼
  </span><span>ovs-ofctl</span><span> </span><span>add-flow</span><span> ...
</span></span></code></div></div></pre>

---

# 🚀 執行方式 (How to Run)

以下流程需開 **三個終端機視窗**。

---

## 📘 Terminal 1 — 啟動 Mininet 拓撲

<pre class="overflow-visible! px-0!" data-start="2149" data-end="2186"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>sudo</span><span> python3 topo_4h1s.py
</span></span></code></div></div></pre>

Mininet CLI 啟動後，可測試基本連線：

<pre class="overflow-visible! px-0!" data-start="2214" data-end="2242"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>mininet> pingall
</span></span></code></div></div></pre>

---

## 📘 Terminal 2 — 啟動實時封包蒐集器 collector

<pre class="overflow-visible! px-0!" data-start="2289" data-end="2343"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>cd</span><span> FinalProject/
</span><span>sudo</span><span> python3 collector.py
</span></span></code></div></div></pre>

此程式會每秒更新一次 **stats.json**，格式類似：

<pre class="overflow-visible! px-0!" data-start="2378" data-end="2530"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-json"><span><span>{</span><span>
  </span><span>"timestamp_epoch"</span><span>:</span><span> </span><span>1765528500</span><span>,</span><span>
  </span><span>"total_pkts"</span><span>:</span><span> </span><span>120</span><span>,</span><span>
  </span><span>"arp_pkts"</span><span>:</span><span> </span><span>25</span><span>,</span><span>
  </span><span>"unique_src_macs"</span><span>:</span><span> </span><span>3</span><span>,</span><span>
  </span><span>"src_macs"</span><span>:</span><span> </span><span>[</span><span>"00:00:00:00:00:01"</span><span>,</span><span> ...</span><span>]</span><span>
</span><span>}</span><span>
</span></span></code></div></div></pre>

---

## 📘 Terminal 3 — 啟動異常偵測器 detector

<pre class="overflow-visible! px-0!" data-start="2574" data-end="2627"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>cd</span><span> FinalProject/
</span><span>sudo</span><span> python3 detector.py
</span></span></code></div></div></pre>

當偵測到異常，例如 ARP Flood：

<pre class="overflow-visible! px-0!" data-start="2651" data-end="2749"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre!"><span><span>[</span><span>WARNING</span><span>] ARP FLOOD DETECTED </span><span>from</span><span> MAC </span><span>00</span><span>:</span><span>00</span><span>:</span><span>00</span><span>:</span><span>00</span><span>:</span><span>00</span><span>:</span><span>03</span><span>
→ Applying </span><span>DROP</span><span> </span><span>rule</span><span> via ovs-ofctl
</span></span></code></div></div></pre>

OVS flow table 會被加入：

<pre class="overflow-visible! px-0!" data-start="2773" data-end="2846"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>ovs-ofctl add-flow s1 </span><span>"dl_src=00:00:00:00:00:03,actions=drop"</span><span>
</span></span></code></div></div></pre>

---

## 📘 Terminal 4 — 啟動 Web Dashboard（可選）

<pre class="overflow-visible! px-0!"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>cd</span><span> FinalProject/
pip install -r requirements.txt
</span><span>sudo</span><span> python3 dashboard.py
</span></span></code></div></div></pre>

開啟瀏覽器訪問 **http://localhost:5000**，即可看到即時監控面板：

- 📈 **即時流量趨勢圖表**：顯示總封包、ARP 封包、不同 MAC 數的歷史趨勢
- ⚠️ **警報記錄**：即時顯示偵測到的攻擊警報
- 🚫 **封鎖列表**：查看並管理已封鎖的 MAC 地址
- ⚙️ **偵測門檻**：顯示當前的偵測閾值設定

> 💡 **注意**：Dashboard 內建了 detector 功能，如果使用 Dashboard 就不需要另外執行 detector.py

---

## ⚔️ 在 Mininet 中發動攻擊（ARP Flood）

在 Mininet CLI（Terminal 1）中輸入：

<pre class="overflow-visible! px-0!" data-start="2918" data-end="2963"><div class="contain-inline-size rounded-2xl corner-superellipse/1.1 relative bg-token-sidebar-surface-primary"><div class="sticky top-9"><div class="absolute end-0 bottom-0 flex h-9 items-center pe-2"><div class="bg-token-bg-elevated-secondary text-token-text-secondary flex items-center gap-4 rounded-sm px-2 font-sans text-xs"></div></div></div><div class="overflow-y-auto p-4" dir="ltr"><code class="whitespace-pre! language-bash"><span><span>mininet> h3 ./attack_arp_flood.sh
</span></span></code></div></div></pre>

你會看到 collector → arp\_pkts 開始增加
detector → 偵測攻擊並阻擋來源 MAC

---

# 🧪 實驗方法（可寫進你的報告）

1. **Baseline**
   * 啟動拓撲＋collector＋detector
   * 執行正常 ping 流量
   * 確保 detector 不會誤判
2. **ARP Flood 攻擊測試**
   * `h3 ./attack_arp_flood.sh`
   * 記錄攻擊時間
   * 觀察 detector 偵測時間點
   * 計算反應時間（偵測 − 攻擊）
3. **MAC Flood（可擴充）**
   * 使用 scapy 產生大量 fake MAC
   * 測試 unique\_src\_macs 門檻是否會觸發

---

# 🔧 可進一步延伸


| 項目                            | 說明                             |
| ------------------------------- | -------------------------------- |
| **MAC Flood 攻擊腳本（scapy）** | 用大量 fake MAC 測試另一種攻擊   |
| **Rate Limiting（非僅 drop）**  | 使用 OVS meter table 實現限速    |
| **實驗分析與報告撰寫**          | 偵測率 / 反應時間 / 誤判率等統計 |

---

# ✔️ 目前系統可以做到的事（總結）

* ✔ 使用 Mininet 建立完整 4-hosts + 1-switch 網路環境
* ✔ 使用 tshark **即時蒐集封包資訊**（total / ARP / MAC）
* ✔ 自動寫入 stats.json 由其他模組使用
* ✔ detector 可成功偵測 **ARP Flood** 與 **MAC Flood**
* ✔ 一旦攻擊被偵測，能即時對來源 MAC 下 **封鎖（drop）flow**
* ✔ 已可模擬 ARP Flood 攻擊並成功防禦
* ✔ 專題核心流程已可完整 demo（Collector → Detector → Mitigation）
* ✔ **Web Dashboard** 提供即時監控介面（流量圖表、警報記錄、封鎖管理）

所有 MVP 目標功能已完成！
