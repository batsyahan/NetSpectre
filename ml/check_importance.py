import joblib
import pandas as pd
from sklearn.inspection import permutation_importance

bundle = joblib.load("models/binary_hgb.joblib")
clf, feature_cols = bundle["model"], bundle["feature_cols"]

test_df = pd.read_parquet("data/processed/test.parquet").sample(20000, random_state=42)
X_test = test_df[feature_cols]
y_test = test_df["binary_label"]

result = permutation_importance(
    clf, X_test, y_test, n_repeats=3, random_state=42, n_jobs=-1
)

imp = pd.Series(result.importances_mean, index=feature_cols).sort_values(ascending=False)
print(imp.head(15))
