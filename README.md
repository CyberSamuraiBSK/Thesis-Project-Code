# Autonomous LightWeight IPS for Kubernetes Pod Network Security

This repository contains the source code for my final thesis project as a BSc student: **Post-Breach Cybersecurity inside Datacenter via Anomaly-Detection Network Defence and SDN-Based Deception**. 

The system leverages **Cilium Hubble** to perform non-intrusive **Layer 4 (L4)** network flow monitoring inside a data center like environment. It utilizes a dynamic **Trust Score Engine** to autonomously detect attack patterns and execute rapid mitigation strategies, either quarantining compromised internal servers or redirecting malicious client pods to decoupled honeypots. To further enchance the engine's realability, it implements a **Layer 7 (L7)** application data monitoring and a **dynamic whitelist mechanism** to prevent false positives in scenarios where L4 inspection lacks sufficient context to make accurate security decisions.

---

## 🚀 Core Architecture & System Logic


The engine operates on a stateless-to-stateful event-processing architecture. It streams live JSON flow events from Hubble, processes them via a multi-threaded data pipeline, updates individual pod trust profiles, and reconciles state mutations directly with the Kubernetes API via `kubectl` and `CiliumNetworkPolicy` manifests.

### 1. Dual-Layer (L4/L7) Detection & Whitelisting
While the engine primary monitors L4 traffic metrics (ports, IPs, connection success ratios, and packet flags) to remain highly lightweight, L4 metrics can sometimes mimic malicious behavior during normal operations (e.g., rapid microservice health probing look identical to port/host scanning). 
* **The L7 Adaptive Pivot:** When a legitimate Layer 7 interaction is observed (such as an HTTP towards the `/health` endpoint), the system dynamically pivots. It establishes a transient, bidirectional **Health Whitelist Pair**. 
* **Bypass Execution:** As long as the whitelisted pods continue to communicate strictly within their established structural pairs, the engine suppresses L4 anomaly penalties. If a pod deviates from its structural pair profile or conducts anomalous activity outside of it, the whitelist is instantly stripped, and aggressive L4 metrics analysis resumes.

### 2. The Dynamic Trust Engine
Every pod starts with a maximum trust score of $100$. Network events yield deterministic trust penalties calculated through live tracking metrics:
* **Trust Threshold:** $\text{THRESHOLD} = 60$ dictates the boundary between normal operation and active containment.
* **Trust Decay & Recovery:** To prevent permanent penalization from transient network jitter or misconfigurations, a background thread runs an asynchronous recovery mechanism. For pods not under active containment, trust rebounds by a calculated recovery rate ($\Delta = +0.5$) over configured time-intervals ($t = 10\text{s}$), allowing the score to asymptotically approach $100$.

---

## 🛡️ Threat Detection Vectors

The IPS monitors and isolates several distinct network attack categories:

| Attack Category | Detection Signature Logic | Engine Penalty |
| :--- | :--- | :--- |
| **Port Scanning** | Evaluation of unique destination ports accessed exceeding $\text{Threshold} = 20$. | $-10$ Trust |
| **Host Scanning** | Evaluation of unique destination pod targets accessed exceeding $\text{Threshold} = 4$. | $-10$ Trust |
| **SYN Flooding** | Volumetric parsing of pure `SYN` flags (without `ACK`) within a rolling time window. | $-15$ Trust |
| **UDP Flooding** | Volumetric processing of raw UDP datagram flows inside a rolling time window. | $-15$ Trust |
| **Suspicious Flag Scans** | Detection of anomalous raw TCP flag combinations (**NULL**, **FIN**, or **XMAS** scans). | $-15$ Trust |
| **DNS Enumeration** | High-frequency DNS queries ($53/\text{UDP}$) absent corresponding L7 application traffic. | $-10$ Trust |
| **Application Brute Force** | High-velocity connection attempts on application boundaries ($80/\text{HTTP}$ and $22/\text{SSH}$). | $-15$ Trust |
| **Connection Failures** | Dropped connections tracking. Evaluates drop-to-connect ratios ($>60\%$) over samples. | Variable (Up to $-5$) |

ℹ️ *For the `Connection Failures` Servers labeled as `trusted` are punished less ( -1 each time) than the other `untrusted` devices.*

---

## ⚡ Automated Response Engineering

When a pod's trust score drops below the critical threshold ($< 60$), the engine classifies it as a threat and spawns detached threads to execute automated, real-time remediation based on the pod's architectural role:

### A. Client Pods (Untrusted) $\rightarrow$ Honeypot Redirection
When an untrusted client pod exhibits malicious signatures, the system avoids flat drops which might alert the attacker. Instead, it spins up an isolated, dedicated honeypot instance tailored to the last-contacted server.
1. Dynamically generates and applies a targeted `CiliumNetworkPolicy` matching the attacker's pod labels.
2. Intercepts all egress traffic from the attacker, confining it strictly within the local cluster boundaries.
3. Patches the attacker's internal `/etc/hosts` at runtime via an ephemeral container execution, seamlessly routing the targeted server's DNS to the honeypot's `ClusterIP`.

### B. Server Pods (Trusted) $\rightarrow$ Strict Quarantine
If a trusted server pod drops below the threshold, it implies that the container has been fully compromised (e.g., remote code execution).
1. The engine instantly labels the pod with `quarantine=true`.
2. It pushes a severe `CiliumNetworkPolicy` that shuts down all application-layer ingress and egress.
3. The server is restricted to **DNS-Only egress** ($53/\text{UDP}$ to the `kube-dns` core cluster IP) to allow essential system resolution for diagnostics while neutralizing its ability to engage in lateral attack propagation or exfiltrate data.

---

## 🛠️ System Components & Code Structure

The runtime relies heavily on multi-threaded data structures shielded by atomic `threading.Lock()` wrappers to maintain data integrity across thousands of asynchronous flow events:

* **Thread-Safe Data Pools:** Utilizes rolling `collections.deque` structures paired with timing data to evaluate attacks within strict, moving time-windows without memory exhaustion.
* **Asynchronous Workers:**
  * `decay_trust()`: Recovers trust over time for clean pods.
  * `reset_stats()`: Periodically purges old network metric counters to prevent memory leaks and integer overflows.
  * `reconcile_pods()`: Constantly polls the Kubernetes API. If an administrator manually modifies or clears a pod's quarantine label, the engine handles policy teardown, restores trust to $100$, and clears historical penalties cleanly.
  * `validate_health_whitelist()`: Automatically expires old L7 health mappings if active heartbeats cease within a specific timeframe.

---

## ⚙️ Example Detection Workflow
* Attacker initiates malicious activity
* Hubble exports flow telemetry
* Detection engine analyzes behavior
* Trust score decreases
* Threshold exceeded
* SDN mitigation policy applied
* Traffic redirected to honeypot
* Attacker activity monitored
---

## 📋 Prerequisites & Local Development

### Requirements
* **Kubernetes Cluster** (v1.24+ recommended)
* **Cilium CNI** deployed with **Hubble** enabled and the `hubble` CLI binary accessible in the system `$PATH`.
* Python 3.8+ 

### Installation & Execution
1. Clone the repository into your development environment:
   ```bash
   https://github.com/CyberSamuraiBSK/Thesis-Project-Code.git
   cd Thesis-Project-Code
2. Run the code:
   ```bash
   python3 revisedTrustEngine.py   
⚠️**NOTE** *It is crucial to properly setup the enviroment (Kubernetes, Cillium, Hubble etc.) before running the code as it cannot run natively on Kubernetes.*  


---
## 📜 License

This project is released under the MIT License.

---
## ❗Disclaimer

This project was developed for academic and research purposes only. The offensive security tools and techniques used during experimentation must only be executed within authorized environments.
