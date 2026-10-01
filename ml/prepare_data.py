from pathlib import Path
from collections import Counter
import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

RAW = Path("data/raw/extracted/MachineLearningCVE")
OUT = Path("data/processed")
OUT.mkdir(parents=True, exist_ok=True)
out_path = OUT / "cicids2017.parquet"

writer = None
label_counts = Counter()
total_rows = 0
nan_rows = 0

for f in sorted(RAW.glob("*.csv")):
    df = pd.read_csv(f, encoding="latin-1", low_memory=False)
    df.columns = df.columns.str.strip()
    df["Label"] = (
        df["Label"].astype(str).str.strip()
        .str.replace(r"[^\x00-\x7F]+", "-", regex=True)
    )
    feature_cols = [c for c in df.columns if c != "Label"]
    df[feature_cols] = (
        df[feature_cols].replace([np.inf, -np.inf], np.nan).astype("float32")
    )
    df["source_file"] = f.name

    total_rows += len(df)
    nan_rows += int(df[feature_cols].isna().any(axis=1).sum())
    label_counts.update(df["Label"].value_counts().to_dict())

    table = pa.Table.from_pandas(df, preserve_index=False)
    if writer is None:
        writer = pq.ParquetWriter(out_path, table.schema)
    writer.write_table(table)
    print(f"{f.name}: {len(df):>7} rows")
    del df, table

writer.close()

print("\nTotal rows:", total_rows)
print("Rows with any NaN:", nan_rows)
print("\nLabel counts:")
for label, n in label_counts.most_common():
    print(f"  {label:<32}{n:>9}")
print("\nSaved", out_path)
