# DNS DDoS Detection using Decision Tree

This project uses a **Decision Tree classifier** to detect **DDoS attacks in DNS traffic**. By analyzing flow-level features from the **CICDDoS2019 dataset**, the model classifies DNS queries as either **legitimate** or **malicious**. It selects optimal features using information gain or Gini impurity to recursively build a tree for fast, real-time classification.

### Dataset:

* **CICDDoS2019**: Contains labeled network traffic including benign and modern DDoS attacks (e.g., DNS, NTP, SYN, UDP-Lag).
* Generated using realistic user behavior and attack simulations.
* Link: https://www.unb.ca/cic/datasets/ddos-2019.html

### Key Features:

* Binary classification: Legitimate vs DDoS
* Interpretable and efficient model
* Trained on real-world network flow data
