#!/usr/bin/env python3

from pathlib import Path
from datetime import datetime
import time
import json
import pandas as pd
import joblib

# ==========================================
# CONFIGURATION
# ==========================================
CLEANED_DIR = Path("../data/cleaned_csvs")
REPORTS_DIR = Path("../data/reports")
MODEL_DIR = Path("../models")

POLL_INTERVAL = 20     
PROCESSED_DB = REPORTS_DIR / "inference_processed.json"

def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def ensure_dirs_exist():
    for d in [CLEANED_DIR, REPORTS_DIR, MODEL_DIR]:
        if not d.exists():
            d.mkdir(parents=True, exist_ok=True)

def load_processed():
    if PROCESSED_DB.exists():
        try:
            return set(json.loads(PROCESSED_DB.read_text()))
        except Exception:
            return set()
    return set()

def save_processed(s):
    PROCESSED_DB.write_text(json.dumps(sorted(list(s))))

def run_inference(file_path: Path, models: dict):
    print(f"\n[{now()}] Analyzing {file_path.name}...")
    
    try:
        df = pd.read_csv(file_path, low_memory=False)
    except Exception as e:
        print(f"Error reading {file_path.name}: {e}")
        return False

    if df.empty:
        print("Dataframe is empty. Skipping.")
        return True

    expected_cols = models['features']
    
    # Force the exact column order required by the Random Forest
    try:
        X_live = df[expected_cols]
    except KeyError as e:
        print(f"CRITICAL ERROR: Cleaned CSV is missing expected training features: {e}")
        return False

    # Run Predictions (Multi-class only)
    multi_preds_encoded = models['rf_multi'].predict(X_live)
    
    # Decode Multi-Class Predictions
    multi_preds_decoded = models['label_encoder'].inverse_transform(multi_preds_encoded)

    # Generate Report
    total_flows = len(df)
    
    # Any flow that isn't exactly 'benign' is counted as an attack
    # (Checking against your exact log string 'benign')
    attacks_detected = sum(multi_preds_decoded != 'benign') 
    
    report_lines = [
        "=" * 42,
        f"INFERENCE REPORT: {file_path.name}",
        f"GENERATED AT: {now()}",
        "=" * 42,
        f"Total Flows Analyzed: {total_flows}",
        "-" * 42
    ]

    if attacks_detected > 0:
        pct = (attacks_detected / total_flows) * 100
        report_lines.append(f"STATUS: ALERT - {attacks_detected} attacks detected ({pct:.2f}% of traffic).")
    else:
        report_lines.append("STATUS: NORMAL - No attacks detected.")

    report_lines.append("\n--- ATTACK TYPE SUMMARY ---")
    
    attack_counts = pd.Series(multi_preds_decoded).value_counts()
    for attack_type, count in attack_counts.items():
        report_lines.append(f"Type [{attack_type}]: {count} flows")

    report_lines.append("\n--- DETAILED LOG (First 10 Flows) ---")
    for i in range(min(10, total_flows)):
        status = multi_preds_decoded[i]
        report_lines.append(f"Row {i:06d} -> Flagged as: {status}")

    # Save Report
    report_name = f"report_{file_path.stem}.txt"
    report_path = REPORTS_DIR / report_name
    report_path.write_text("\n".join(report_lines))
    
    print(f"[{now()}] Report saved: {report_path.name}")
    return True

def main():
    ensure_dirs_exist()
    processed = load_processed()
    
    print(f"[{now()}] Loading Model into memory...")
    try:
        # Load ONLY the required features, encoder, and multi-class model
        models = {
            'features': joblib.load(MODEL_DIR / "training_columns.pkl"),
            'label_encoder': joblib.load(MODEL_DIR / "label_encoder.pkl"),
            'rf_multi': joblib.load(MODEL_DIR / "rf_multi_model.pkl")
        }
    except Exception as e:
        print(f"Failed to load models. Did you save them in the training script? Error: {e}")
        return

    print(f"[{now()}] Listening for cleaned CSVs in {CLEANED_DIR}...")
    
    try:
        while True:
            for p in sorted(CLEANED_DIR.glob("*.cleaned.csv")):
                if p.name not in processed:
                    time.sleep(1) 
                    success = run_inference(p, models)
                    if success:
                        processed.add(p.name)
                        save_processed(processed)
            time.sleep(POLL_INTERVAL)
            
    except KeyboardInterrupt:
        print(f"\n[{now()}] Shutting down Inference Engine.")
        save_processed(processed)

if __name__ == "__main__":
    main()