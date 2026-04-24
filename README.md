# SQL Injection Detection

SQL Injection Detection is a machine learning system that classifies SQL queries as **normal** or **malicious**. The model is designed with a security-first mindset, prioritizing the detection of malicious inputs while maintaining a low false positive rate.

---

## Overview

This project implements a production-style machine learning pipeline for detecting SQL injection attacks. Given a raw SQL query, the system predicts whether the query is benign or potentially malicious.

The system focuses on:
- High recall for malicious queries (minimizing missed attacks)
- Controlled false positives for practical usability
- Reproducible and deployable ML pipeline design

---

## Features

### SQL Injection Detection

The model takes raw SQL queries and classifies them into:

| Label | Description |
|---|---|
| `0` | Normal query |
| `1` | Malicious query |

The system is optimized to detect subtle injection patterns such as:
- Tautologies (`' OR '1'='1`)
- Comment-based attacks (`--`, `#`)
- Data extraction (`UNION SELECT`)
- Query manipulation patterns

---

### Machine Learning Pipeline

The detection system is built using a clean and modular pipeline:

| Component | Description |
|---|---|
| Feature Extraction | Character-level TF-IDF (n-grams 2–6) |
| Model | Linear Support Vector Machine (`LinearSVC`) |
| Class Handling | Weighted classes to prioritize malicious detection |
| Threshold Tuning | Custom decision threshold (`-0.40`) |
| Validation | 5-fold stratified cross-validation |

---

### Threshold Optimization

Instead of relying on default predictions, the model uses a custom decision threshold:

`score >= -0.40 → Malicious`  
`score < -0.40 → Normal`

This allows fine-grained control over:

| Objective | Description |
|---|---|
| False Negatives | Missed malicious queries |
| False Positives | Incorrectly flagged normal queries |

---

## Evaluation Metrics

| Metric | Value |
|---|---|
| Accuracy | 99.63% |
| Malicious Recall | 99.69% |
| Malicious Precision | 99.30% |
| False Negatives | 7 |
| False Positives | 16 |

---

## Confusion Matrix

The model performance is visualized using:

| File | Description |
|---|---|
| `confusion_matrix.png` | Confusion matrix visualization |


---

## Usage

### Train and Evaluate

Run the pipeline on the dataset:

```bash
python sql_injection_pipeline.py --data Modified_SQL_Dataset.csv
```
---

### Optional Flags (Usage Examples)

| Command | Description |
|---|---|
| `python sql_injection_pipeline.py --data Modified_SQL_Dataset.csv --no-show` | Disable confusion matrix display |
| `python sql_injection_pipeline.py --data Modified_SQL_Dataset.csv --verbose` | Show detailed logs (cross-validation, threshold tuning, error analysis) |
| `python sql_injection_pipeline.py --data Modified_SQL_Dataset.csv --no-show --verbose` | Full usage with all options |

## Output

| Output | Description |
|---|---|
| Terminal Metrics | Final evaluation results |
| `confusion_matrix.png` | Performance visualization |
| `sql_injection_svm_model.joblib` | Saved trained model |

---

## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python |
| ML Library | scikit-learn |
| Data Processing | pandas |
| Visualization | matplotlib |
| Model Persistence | joblib |

---

## Design Decisions

| Decision | Reason |
|---|---|
| Security-first optimization | Prioritize detecting malicious queries |
| Threshold tuning | Improve control over classification trade-offs |
| Character-level TF-IDF | Capture SQL patterns effectively |
| Linear SVM | High performance with low complexity |

---

## Future Work

- Deploy as an API for real-time query validation  
- Integrate with web applications for input filtering  
- Expand the dataset with real-world attack patterns  