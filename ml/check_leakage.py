import pandas as pd

df = pd.read_parquet("data/processed/cicids2017.parquet")

print("All columns:")
for c in df.columns:
    print(" ", c)

print("\nDuplicate rows (excluding source_file):")
cols = [c for c in df.columns if c != "source_file"]
print(df.duplicated(subset=cols).sum(), "/", len(df))
