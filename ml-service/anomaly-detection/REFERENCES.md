# References and research background

Every design decision in this project traces to something below. Cite these in
the report and the deck — judges notice when the literature is real.

---

## 1. Datasets

None are bundled (they range from 12 MB to 70 GB and carry their own licences).
Download and place under `data/raw/`, then run the adapter:

```bash
python -m src.datasets --list                                  # show catalogue
python -m src.datasets --source lanl --path data/raw/lanl --out data/lanl
python run_pipeline.py --source generic --path data/lanl
```

### 1.1 LANL — Comprehensive, Multi-Source Cyber-Security Events ★ closest fit

- **Link:** https://csr.lanl.gov/data/cyber1/
- **Record:** https://www.osti.gov/biblio/1179829 (DOI `10.17021/1179829`)
- **Files:** `auth.txt.gz` (authentication events), `redteam.txt.gz` (4.8 KB, ground truth), plus `proc`, `dns`, `flow`
- **Scale:** 58 consecutive days of de-identified events from LANL's internal network — roughly 1.65 billion events across 12,425 users, 17,684 computers and 62,974 processes, about 12 GB compressed
- **Labels:** `redteam.txt` gives known compromise events as `time,user@domain,src_computer,dst_computer`
- **Why it matters here:** real enterprise authentication logs with red-team ground truth, and a positive rate low enough to be genuinely representative — published work notes malicious events are a vanishingly small share of the total, which is exactly the imbalance the problem statement describes
- **Cite:** A. D. Kent, *Comprehensive, Multi-Source Cyber-Security Events*, Los Alamos National Laboratory, 2015.
- **Adapter:** `src/datasets.py::load_lanl` (defaults to days 6–12, where most red-team activity sits, to keep it laptop-sized). Note LANL has no geographic field, so geo-velocity features degrade to zero — say this explicitly rather than hiding it.

### 1.2 CMU CERT Insider Threat Test Dataset ★ closest behavioural analogue

- **Link:** https://kilthub.cmu.edu/articles/dataset/Insider_Threat_Test_Dataset/12841247
- **SEI page:** https://resources.sei.cmu.edu/library/asset-view.cfm?assetid=508099
- **Release to use:** `r4.2` — the "dense needle" release, ~1,000 users over 17 months, with multiple instances of each malicious scenario
- **Files:** `logon.csv`, `device.csv`, `file.csv`, `http.csv`, `email.csv`, `psychometric.csv`, plus an `answers/` directory holding the ground-truth key
- **Why it matters here:** per-user behavioural logs with insider scenarios; the standard benchmark in the insider-threat literature and the closest public analogue to this problem statement
- **Cite:** Glasser & Lindauer, *Bridging the Gap: A Pragmatic Approach to Generating Insider Threat Data*, IEEE Security & Privacy Workshops, 2013.
- **Adapter:** `src/datasets.py::load_cert`

### 1.3 Others worth naming in the report

| Dataset | Link | Use |
|---|---|---|
| UNSW-NB15 | https://research.unsw.edu.au/projects/unsw-nb15-dataset | network-flow intrusion detection, nine attack families |
| CIC-IDS2017 | https://www.unb.ca/cic/datasets/ids-2017.html | labelled flows including brute force and infiltration |
| CSE-CIC-IDS2018 | https://www.unb.ca/cic/datasets/ids-2018.html | successor to the above |
| LogHub (HDFS, BGL, Thunderbird) | https://github.com/logpai/loghub | log-sequence anomaly detection benchmarks |
| DARPA OpTC | https://github.com/FiveDirections/OpTC-data | host telemetry with red-team activity |

> Verify links before submission — dataset hosting moves. All were reachable at
> the time of writing.

---

## 2. Papers behind each component

### Anomaly detection
- **Liu, Ting & Zhou, *Isolation Forest*, ICDM 2008.** The `IsolationForest` signal in `src/detect.py`. Isolates anomalies by random partitioning rather than modelling normality — cheap and effective on mixed tabular features.
- **Schölkopf et al., *Estimating the Support of a High-Dimensional Distribution*, Neural Computation 2001.** One-class SVM; the alternative baseline profiler the problem statement names.
- **Chandola, Banerjee & Kumar, *Anomaly Detection: A Survey*, ACM Computing Surveys 2009.** The standard taxonomy — point vs contextual vs collective anomalies. Worth one slide: low-and-slow exfiltration is a *collective* anomaly, which is precisely why point-wise detectors miss it and a sequence model is needed.

### Sequence models on logs
- **Du et al., *DeepLog: Anomaly Detection and Diagnosis from System Logs through Deep Learning*, CCS 2017.** The canonical LSTM-over-log-sequences paper and the direct ancestor of the sequence autoencoder here.
- **Meng et al., *LogAnomaly*, IJCAI 2019.** Template-level sequential and quantitative log anomaly detection.
- **Malhotra et al., *LSTM-based Encoder-Decoder for Multi-sensor Anomaly Detection*, ICML Anomaly Detection Workshop 2016.** Reconstruction error as an anomaly score — the exact mechanism used in `SequenceAutoencoder`.

### Lateral movement and authentication graphs
- **Bowman et al., *Detecting Lateral Movement in Enterprise Computer Networks with Unsupervised Graph AI*, RAID 2020.** Graph approach on LANL.
- **Kent, Liebrock & Neil, *Authentication Graphs: Analyzing User Behavior within an Enterprise Network*, Computers & Security 2015.** Motivates entity-resource relationship features.

### Explainability
- **Lundberg & Lee, *A Unified Approach to Interpreting Model Predictions*, NeurIPS 2017.** SHAP — `src/explain.py`.
- **Lundberg et al., *From Local Explanations to Global Understanding with Explainable AI for Trees*, Nature Machine Intelligence 2020.** `TreeExplainer`, which is what makes SHAP fast enough to run per alert.

### Concept drift and class imbalance
- **Gama et al., *A Survey on Concept Drift Adaptation*, ACM Computing Surveys 2014.** Justifies EWMA-style incremental adaptation over periodic retraining.
- **Wu & Olson, *Introduction to Population Stability Index*, 2010** (and general credit-risk practice). PSI > 0.25 as a major-shift threshold — the drift monitor in `src/baseline.py`.
- **Chawla et al., *SMOTE: Synthetic Minority Over-sampling Technique*, JAIR 2002.** The standard imbalance remedy; noted in the report as the alternative to the approach actually taken.
- **Saito & Rehmsmeier, *The Precision-Recall Plot Is More Informative than the ROC Plot When Evaluating Binary Classifiers on Imbalanced Datasets*, PLoS ONE 2015.** Why this project leads with PR-AUC. Cite it when a judge asks why ROC-AUC is not the headline.

### Cold start
- **Gelman et al., *Bayesian Data Analysis*, 3rd ed., ch. 5 (hierarchical models).** The shrinkage estimator `w = n / (n + k)` blending an entity's own history with its peer-group prior is a standard hierarchical partial-pooling result.

### Operational framing
- **Hassan, Guo et al., *NoDoze: Combatting Threat Alert Fatigue with Automated Provenance Triage*, NDSS 2019.** Alert fatigue as a first-class constraint — the justification for evaluating at a fixed analyst budget and for incident-level deduplication.
- **MITRE ATT&CK** — https://attack.mitre.org/ — map your attack taxonomy to technique IDs, it costs ten minutes and makes the deck look professional:

| Your class | ATT&CK |
|---|---|
| `brute_force` | T1110 Brute Force |
| `credential_stuffing` | T1110.004 Credential Stuffing |
| `lateral_movement` | TA0008 Lateral Movement / T1021 Remote Services |
| `device_spoofing` | T1036 Masquerading |
| `low_slow_exfil` | TA0010 Exfiltration / T1030 Data Transfer Size Limits |
| `impossible_travel` | T1078 Valid Accounts |

---

## 3. Tooling

- scikit-learn — Pedregosa et al., JMLR 2011
- PyTorch — Paszke et al., NeurIPS 2019
- LightGBM — Ke et al., NeurIPS 2017
- SHAP — https://github.com/shap/shap
- Streamlit — https://streamlit.io

---

## 4. Suggested citation block for the report

```
[1] A. D. Kent. Comprehensive, Multi-Source Cyber-Security Events.
    Los Alamos National Laboratory, 2015. doi:10.17021/1179829
[2] J. Glasser and B. Lindauer. Bridging the Gap: A Pragmatic Approach to
    Generating Insider Threat Data. IEEE S&P Workshops, 2013.
[3] F. T. Liu, K. M. Ting, Z.-H. Zhou. Isolation Forest. ICDM, 2008.
[4] M. Du, F. Li, G. Zheng, V. Srikumar. DeepLog: Anomaly Detection and
    Diagnosis from System Logs through Deep Learning. ACM CCS, 2017.
[5] S. Lundberg and S.-I. Lee. A Unified Approach to Interpreting Model
    Predictions. NeurIPS, 2017.
[6] J. Gama et al. A Survey on Concept Drift Adaptation. ACM CSUR, 2014.
[7] T. Saito and M. Rehmsmeier. The Precision-Recall Plot Is More Informative
    than the ROC Plot on Imbalanced Datasets. PLoS ONE, 2015.
[8] W. U. Hassan et al. NoDoze: Combatting Threat Alert Fatigue with Automated
    Provenance Triage. NDSS, 2019.
```
