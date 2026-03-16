#!/usr/bin/env python3

from pathlib import Path
from datetime import datetime
import time
import json
import pandas as pd
import joblib
from collections import Counter

# ==========================================
# CONFIGURATION
# ==========================================
# Assuming script runs from /src/
CLEANED_DIR = Path("../data/cleaned_csvs")
REPORTS_DIR = Path("../data/reports")  # Changed to a reports directory
MODEL_DIR = Path("../models")

POLL_INTERVAL = 20     
STABLE_WAIT = 2        
PROCESSED_DB = REPORTS_DIR / "inference_processed.json"

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def ensure_dirs_exist():
    if not CLEANED_DIR.exists():
        raise RuntimeError(f"Missing input directory: {CLEANED_DIR}")
    if not MODEL_DIR.exists():
        raise RuntimeError(f"Missing model directory: {MODEL_DIR}")
    
    # Create reports directory if it doesn't exist
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

def load_processed():
    if PROCESSED_DB.exists():
        try:
            return set(json.loads(PROCESSED_DB.read_text()))
        except Exception:
            return set()
    return set()

def save_processed(s):
    PROCESSED_DB.write_text(json.dumps(sorted(list(s))))

def stable_files(processed):
    """Check for new, stable files in the cleaned directory."""
    sizes_before = {}
    for p in CLEANED_DIR.glob("*.cleaned.csv"):
        if p.name in processed:
            continue
        try:
            sizes_before[p] = p.stat().st_size
        except FileNotFoundError:
            continue

    if not sizes_before:
        return []

    time.sleep(STABLE_WAIT)

    stable = []
    for p, s1 in sizes_before.items():
        try:
            s2 = p.stat().st_size
        except FileNotFoundError:
            continue
        if s1 == s2 and s1 > 0:
            stable.append(p)
    return sorted(stable)

# ==========================================
# MODEL LOADING & PREDICTION LOGIC
# ==========================================
print(f"[{now()}] Loading Random Forest models...")
ensure_dirs_exist()

try:
    rf_bin = joblib.load(MODEL_DIR / "rf_bin_model.pkl")
    rf_multi = joblib.load(MODEL_DIR / "rf_multi_model.pkl")
    print(f"[{now()}] Models loaded successfully.")
except Exception as e:
    raise RuntimeError(f"Failed to load models: {e}. Check the MODEL_DIR path.")

def run_inference(path: Path):
    """Read cleaned data, run predictions, and generate a text report."""
    print(f"[{now()}] Predicting on {path.name}...")
    try:
        df = pd.read_csv(path, low_memory=False)
    except Exception as e:
        print(f"[{now()}] Failed to read {path.name}: {e}")
        return False

    drop_cols = [c for c in ["label1", "label2", "target_bin", "target_multi"] if c in df.columns]
    X_infer = df.drop(columns=drop_cols)

    # 1. Generate Predictions
    try:
        bin_preds = rf_bin.predict(X_infer)
        multi_preds = rf_multi.predict(X_infer)
    except ValueError as e:
        print(f"[{now()}] Feature mismatch error on {path.name}: {e}")
        return False

    # 2. Build the Report
    total_flows = len(bin_preds)
    attack_indices = [i for i, p in enumerate(bin_preds) if p == 1]
    num_attacks = len(attack_indices)

    report_lines = [
        f"==========================================",
        f"INFERENCE REPORT: {path.name}",
        f"GENERATED AT: {now()}",
        f"==========================================",
        f"Total Flows Analyzed: {total_flows}",
        f"------------------------------------------"
    ]

    if num_attacks == 0:
        report_lines.append("STATUS: CLEAN - All flows are benign.")
    else:
        report_lines.append(f"STATUS: ALERT - {num_attacks} attacks detected ({(num_attacks/total_flows)*100:.2f}% of traffic).")
        report_lines.append("\n--- ATTACK TYPE SUMMARY ---")
        
        # Get the specific attack types for the flagged rows
        attack_types = [multi_preds[i] for i in attack_indices]
        type_counts = Counter(attack_types)
        
        for atk_type, count in type_counts.items():
            report_lines.append(f"Encoded Attack Type [{atk_type}]: {count} flows")

        report_lines.append("\n--- DETAILED ANOMALY LOG (By Row Index) ---")
        # List each malicious flow. (If files are huge, you might want to cap this)
        for idx, atk_type in zip(attack_indices, attack_types):
            report_lines.append(f"Row {idx:06d} -> Flagged as Type {atk_type}")

    # 3. Save the Report
    out_name = path.name.replace(".cleaned.csv", ".report.txt")
    out_path = REPORTS_DIR / out_name
    
    try:
        out_path.write_text("\n".join(report_lines))
        print(f"[{now()}] Saved report to: {out_path.name}")
        return True
    except Exception as e:
        print(f"[{now()}] Failed to save report for {path.name}: {e}")
        return False

# ==========================================
# MAIN LOOP
# ==========================================
def main():
    processed = load_processed()
    print(f"[{now()}] Watching {CLEANED_DIR} (poll every {POLL_INTERVAL}s).")
    try:
        while True:
            ready = stable_files(processed)
            if ready:
                for p in ready:
                    ok = run_inference(p)
                    if ok:
                        processed.add(p.name)
                        save_processed(processed)
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        print(f"\n[{now()}] Interrupted by user. Saving processed DB and exiting.")
        save_processed(processed)

if __name__ == "__main__":
    main()