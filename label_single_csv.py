import pandas as pd

df = pd.read_csv("stats.csv")

features = [
    "total_pkts",
    "arp_pkts",
    "unique_src_macs",
    "arp_ratio",
    "label"
]

df_ai = df[features]

# 移除 total_pkts = 0 的秒（無資訊）
df_ai = df_ai[df_ai["total_pkts"] > 0]

df_ai.to_csv("stats_ai.csv", index=False)

print("✅ stats_ai.csv ready")
print(df_ai["label"].value_counts())