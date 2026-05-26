# Flow-Based Post-Breach Detection Framework for Datacenters

## Overview

This repository contains the implementation developed for the BSc thesis:

**“Post-Breach Cybersecurity inside Datacenters via Anomaly-Detection Network Defence and SDN-Based Deception”**

The framework combines:

* Flow-based anomaly detection
* Dynamic trust evaluation aligned with Zero Trust principles
* Software-Defined Networking (SDN)-enabled policy enforcement
* Adaptive deception techniques using honeypots

The objective of the system is to provide lightweight post-breach detection and automated response capabilities for cloud-native Kubernetes infrastructures.

---

# Architecture

The framework operates by continuously monitoring network flow telemetry generated within a Kubernetes cluster. Suspicious behavior is identified using threshold-based anomaly detection and dynamic trust scoring.

When malicious activity is detected:

1. Trust scores are reduced
2. Mitigation policies are generated
3. Traffic may be redirected to honeypot services
4. Suspicious entities may be isolated or monitored

Core technologies used include:

* Kubernetes
* Cilium
* Hubble
* Python
* SDN-based policy enforcement
* Honeypot deployment mechanisms

---

# Features

* Lightweight flow-based monitoring
* Real-time anomaly detection
* Dynamic trust scoring
* Automated response policies
* Honeypot redirection
* Detection of reconnaissance and brute-force activity
* Kubernetes-native deployment
* Support for simultaneous attack scenarios

---

# Experimental Scenarios

The framework was evaluated against multiple attack categories including:

* SYN scans
* FIN scans
* NULL scans
* XMAS scans
* DNS enumeration
* Brute-force attacks
* Directory enumeration attacks
* Simultaneous multi-attacker scenarios

Attack simulation tools included:

* Nmap
* Gobuster
* nslookup

---

---

# Requirements

## Software

* Ubuntu 22.04 LTS
* Docker
* Kubernetes
* Cilium
* Hubble
* Python 3.10+

## Recommended Resources

* Multi-core CPU
* Minimum 16 GB RAM
* Kubernetes-compatible environment

---

# Installation

## Clone Repository

```bash
git clone https://github.com/yourusername/your-repository.git
cd your-repository
```

## Deploy Kubernetes Components

```bash
kubectl apply -f kubernetes/
```

## Start Monitoring Components

```bash
python3 revisedTrustEngine.py
```

# Usage

The framework continuously monitors Kubernetes network flow telemetry generated through Hubble.

When suspicious behavior exceeds predefined thresholds:

* trust scores are updated,
* mitigation policies are applied,
* and traffic may be redirected toward honeypot environments.

Logs and detection events are exported through the monitoring components.

---

# Example Detection Workflow

1. Attacker initiates malicious activity
2. Hubble exports flow telemetry
3. Detection engine analyzes behavior
4. Trust score decreases
5. Threshold exceeded
6. SDN mitigation policy applied
7. Traffic redirected to honeypot
8. Attacker activity monitored

---

# Research Objectives

This project investigates whether combining:

* flow-based telemetry,
* dynamic trust evaluation,
* and adaptive deception mechanisms

can provide effective post-breach detection and response with lower overhead compared to traditional deep packet inspection approaches.

---

# Thesis Reference

If you use this repository in academic work, please cite:

```text
Symeon Konstantinos Zampethanis,
“A Flow-Based Post-Breach Detection and Response Framework for Kubernetes Environments,”
BSc Thesis, University of Thessali, 2026.
```

---

# Future Work

Potential future extensions include:

* machine learning-based behavioral analysis
* distributed trust synchronization
* SOAR platform integration
* automated forensic collection
* large-scale distributed deployment
* threat intelligence integration

---

# License

This project is released under the MIT License.

---

# Disclaimer

This project was developed for academic and research purposes only. The offensive security tools and techniques used during experimentation must only be executed within authorized environments.
