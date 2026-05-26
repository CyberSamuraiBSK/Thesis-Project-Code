# Thesis-Project-Code
This is the code for my thesis project
Lightweight Container-native IPS for Data Center Workloads
https://img.shields.io/badge/License-MIT-yellow.svg
https://img.shields.io/badge/python-3.8+-blue.svg
https://img.shields.io/badge/kubernetes-1.20+-blue.svg
https://img.shields.io/badge/cilium-1.12+-purple.svg

Overview
This project presents a lightweight, container-native Intrusion Prevention System (IPS) designed specifically for data center environments running Kubernetes. Unlike traditional IPS solutions that inspect all traffic at the perimeter, this system operates inside the cluster, monitoring east-west traffic between microservices with minimal overhead.

The system makes Layer 4 (L4) decisions by default - analyzing TCP/UDP flow characteristics, connection patterns, and traffic volumes to detect attacks efficiently. However, it recognizes that certain scenarios (e.g., distinguishing legitimate load balancing from port scans, or health checks from reconnaissance) cannot be reliably decided using L4 information alone.

For these edge cases, the system selectively escalates to Layer 7 (L7) inspection through a novel health-based whitelist mechanism - pods that regularly exchange health checks are automatically trusted and exempted from certain L4 heuristics, reducing false positives while maintaining detection accuracy.

Key Features
🛡️ Attack Detection (L4 Priority)
Port & Host Scanning - Detects reconnaissance behavior across ports and IPs

SYN/UDP Floods - Identifies volumetric DDoS attacks

Connection Failure Anomalies - Spots failed connection patterns indicative of exploitation

Suspicious TCP Flags - Detects NULL, FIN, and XMAS scans

DNS Tunneling/Enumeration - Monitors for DNS-based exfiltration

Brute Force Attacks - Detects HTTP and SSH credential stuffing

🔄 Adaptive Response
Honeypot Redirection - Attackers are transparently redirected to decoy services

Server Quarantine - Compromised workloads are restricted to DNS-only egress

Trust Score System - Dynamic scoring with automatic decay over time

Policy Reconciliation - Automatic cleanup when manual interventions occur

🧠 Hybrid L4/L7 Decision Making
L4-First Architecture - 95% of decisions use fast, stateless L4 analysis

Selective L7 Escalation - Only ambiguous scenarios trigger deeper inspection

Health-based Whitelisting - Pod pairs that exchange /health endpoints automatically trust each other

Configurable Thresholds - All detection parameters can be tuned per deployment

🏗️ Kubernetes-Native Design
Cilium Integration - Leverages eBPF for efficient network monitoring

Hubble Observability - Consumes real-time flow events from Hubble

Network Policy Enforcement - Implements responses via CiliumNetworkPolicy

No Sidecars Required - Operates as a standalone controller
