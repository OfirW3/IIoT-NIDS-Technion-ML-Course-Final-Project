# ML-Powered NIDS for IIoT Security
This project is an end-to-end, real-time Network Intrusion Detection System (NIDS) designed explicitly for Industrial IoT (IIoT) networks. 
## About the Project
**The Application Pipeline:** The system continuously captures live network traffic, processes the raw packets into structured behavioral flows (CSV), and feeds them into a machine learning inference engine. The model then classifies the traffic in real-time as either benign or belonging to specific attack families (such as DDoS, Brute Force, Malware, Reconnaissance, MiTM, or Web attacks), displaying the results dynamically in a command-center GUI.

### Data Source
The machine learning models were trained and evaluated using the highly regarded **CIC IIoT 2025** dataset, provided by the Canadian Institute for Cybersecurity (CIC). This dataset represents a modern, realistic Industry 4.0 network environment.
* 🔗 [Link to the CIC IIoT 2025 Dataset](https://www.unb.ca/cic/datasets/iiot-dataset-2025.html)

---

## Machine Learning Engine 

The core of this NIDS is a machine learning pipeline, strictly designed to recognize generalized threat behaviors rather than memorizing laboratory artifacts.

### 1. Preprocessing & Splitting
To prepare the raw data for training, we first addressed class imbalances by under-sampling the majority classes and merging identical flow behaviors (like DoS and DDoS) into single categories. 

The dataset was then rigorously partitioned to ensure unbiased evaluation:
* **Training Phase (80%):** Divided into **64% Train** and **16% Validation** sets to build and tune the models.
* **Testing Phase (20%):** A completely isolated **20% Test** dataset was saved independently for final evaluation in an external testing notebook.

### 2. The Anti-Leakage Filter
To ensure the model learns actual network behaviors (like packet rates, byte ratios, and connection durations) rather than the specific environment it was trained in, we implemented a high-level anti-leakage filter. This process systematically strips out environment-specific identifiers—such as IP addresses, MAC addresses, and exact timestamps. By removing these artifacts, we prevent the model from "cheating" and guarantee that its predictive capabilities will generalize accurately to any real-world network topology.

### 3. Model Training & Architectures
During the research phase, four distinct machine learning architectures were trained and evaluated to find the optimal inference engine:

* **Random Forest (The Chosen Model):** Explored for its proven track record with complex tabular datasets and rapid real-time inference speeds, this is a powerful ensemble learning method that creates a highly diverse set of decision trees. It achieves this by using bootstrapping to train each tree on a random subset of the data, and applying feature randomness so each tree evaluates different behavioral metrics. Once all the trees are built, the model aggregates their individual predictions and uses majority voting to make the final classification. This approach makes the model exceptionally robust, accurate, and resistant to overfitting.
* **Autoencoder + XGBoost:** Tested this hybrid approach to see if deep feature compression could effectively filter out raw network noise before classification. The Autoencoder (an unsupervised neural network) was used to compress the input features into a lower-dimensional representation. This compressed data was then passed to XGBoost, a gradient boosting framework that builds decision trees sequentially, with each new tree correcting the residual errors of the previous ones.
* **TabNet:** Selected to evaluate if cutting-edge deep learning, specifically engineered for tabular data, which was developed by Google researchers could outperform traditional tree-based algorithms. This architecture processes data through sequential steps, using an attentive transformer paired with a sparsemax activation function to perform instance-wise feature selection—meaning it learns to focus only on the most relevant metrics for a given network flow. A feature transformer then processes these selections, while prior scales dynamically adjust to ensure the network doesn't over-rely on the exact same features repeatedly across different steps.
* **Unsupervised Isolation Forest:** Evaluated for its potential to detect unknown, zero-day attacks without relying on labeled threat data. This is a pure anomaly detection algorithm. Instead of trying to profile what "normal" traffic looks like, it directly isolates anomalies by building trees that randomly partition the data. Because attacks are mathematically distinct and less frequent, they require far fewer partitions to be separated from the rest of the data. The model assigns an anomaly score based on this principle: the shorter the path length required to isolate a specific network flow, the more anomalous it is.

> **Final Test Evaluation**
> 
> <img width="1584" height="590" alt="image" src="https://github.com/user-attachments/assets/bb763e0b-39d7-4c41-8a5e-40f1714fd862" />


---

## Code Structure & Pipeline

The repository is modular, separating the GUI from the pipeline's daemons 

```text
IIoT-NIDS-Technion-ML-Course-Final-Project/
├── main.py                              # Root execution script (Launches the GUI and Pipeline)
├── README.md                   
├── notebooks/                           # Google colab notebooks containing data preparation, model training, and evaluation.
│   ├── merge_and_clean_datasets.ipynb   # Merges cleans and under-samples the datasets into a single dataset.
│   ├── train_model.ipynb                # Filters leaking features and train the models.
│   └── test_models.ipynb                # External models testing notebook.
├── src/
│   ├── __init__.py             
│   ├── nids_gui.py                      # Graphical dashboard to control the pipeline.
│   ├── pipeline_engine.py               # Orchestrates the parallel threads safely.
│   ├── pcap_to_csv_daemon.py            # Converts raw PCAPs into ML-ready flow statistics.
│   └── model_classification.py          # Loads the RF model and predicts on incoming data.
├── bash_scripts/
│   ├── setup_dirs.sh                    # Initializes required temp/data directories.
│   └── sniff_rotate.sh                  # Captures and rotates live PCAP files.
├── models/                              # Contains the trained .pkl models, label encoders, and feature arrays.
│   ├── label_encoder.pkl                # Saved multi-class label encoder which used in training.
│   ├── rf_multi_model.pkl               # Saved trained multi-class Random Forest model
│   └── training_columns.pkl             # Saved ordered training columns used in training.
└── data/
```

## Installation Guide

1. **Clone the repository:**
   ```bash
   git clone https://github.com/OfirW3/IIoT-NIDS-Technion-ML-Course-Final-Project
   cd IIoT-NIDS-Technion-ML-Course-Final-Project
   ```

2. **Create a Python virtual environment:**
   ```bash
   python3 -m venv nids_env
   source nids_env/bin/activate
   ```

3. **Install the dependencies:**
   ```bash
   pip install -r requirements.txt
   ```
   > **Note for Linux users:** If you encounter a `ModuleNotFoundError: No module named 'tkinter'` error when launching the GUI, you will need to install it via your system's package manager (e.g., `sudo apt-get install python3-tk`).

4. **Ensure network utilities are installed:**
   Ensure you have standard packet capture tools, like `tcpdump` or `tshark`, installed on your Linux machine, as the bash scripts rely on them.

---

## Usage

To launch the NIDS, run the main script as a standard user (the script will handle `sudo` prompts dynamically for the packet sniffer inside the terminal):

```bash
python3 main.py
```
Once the GUI opens, click **START PIPELINE**. 

---

## Limitations & Future Work

While the Random Forest model achieves high accuracy on offline datasets, running the inference engine in real-time presents unique challenges:

* **The "Sniffing Window" Limitation:** Currently, the live pipeline captures traffic in distinct time chunks (e.g., rotating PCAP files every few seconds) to feed the model quickly. However, this artificial segmentation can truncate long-running network flows. If a flow is cut in half, the calculated statistics (like `duration`, `packet_count`, or `mean_bytes`) will differ significantly from the complete flows the model was trained on, potentially reducing real-time accuracy with false-positives. For example, flagging benign flows as MiTM or Malware attacks because of truncation of the TCP handshake flags.
* **Future Improvements:** To solve this, future iterations should transition from chunk-based PCAP rotation to a **stateful flow-tracking mechanism** (e.g., using an in-memory datastore like Redis or a continuous stream processor). This would maintain the context of active connections across time windows, ensuring the ML engine always receives accurate, running totals for flow statistics.

---

## Acknowledgments

This project was developed as the final project for a Machine Learning course at the **Technion - Israel Institute of Technology**.
