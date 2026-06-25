#!/usr/bin/env python3
"""
Current Version: [2.0.0]

Trust Engine for Kubernetes Pod Network Security

This module monitors network flows in a Kubernetes cluster using Hubble,
detects various attack patterns (port scans, SYN floods, DNS enumeration, etc.),
and automatically responds by redirecting attackers to honeypots or quarantining
compromised servers.

Key Features:
- Real-time network flow monitoring with Hubble
- Attack detection (port scans, host scans, SYN floods, UDP floods, DNS enumeration,
  HTTP/SSH brute force, suspicious TCP flag patterns)
- Trust score system with decay over time
- Health-based traffic whitelisting
- Automatic redirection of attackers to honeypots
- Quarantine of compromised servers with DNS-only egress
- Policy reconciliation and cleanup
"""

import subprocess
import json
import time
import threading
from collections import defaultdict, deque
import copy
import builtins
import datetime

# ==================== LOCKS FOR THREAD SAFETY ====================
log_lock = threading.Lock()
trust_lock = threading.Lock()
stats_out_lock = threading.Lock()
stats_in_lock = threading.Lock()
syn_lock = threading.Lock()
udp_lock = threading.Lock()
quarantine_pending_lock = threading.Lock()
request_tracker_lock = threading.Lock()
request_tracker2_lock = threading.Lock()
dns_lock = threading.Lock()
last_contacted_lock = threading.Lock()
pod_roles_lock = threading.Lock()
l7_lock = threading.Lock()
health_whitelist_lock = threading.Lock()
attack_lock = threading.Lock()
first_seen_lock = threading.Lock()
redirect_lock = threading.Lock()
quarantine_lock = threading.Lock()

# ==================== CONFIGURATION ====================
THRESHOLD = 60                # Trust threshold for redirection/quarantine
DECAY_RATE = 0.5              # Trust recovery rate per interval
DECAY_INTERVAL = 10           # Seconds between trust decay events
TRUST_MAX = 100.0             # Maximum trust score
POLICY_LAG = 3                # Seconds to wait before applying policies

# Detection window configurations
SYN_WINDOW = 5                # Seconds to track SYN packets
SYN_THRESHOLD = 15            # SYN packets per window to trigger detection
UDP_WINDOW = 5                # Seconds to track UDP packets
UDP_THRESHOLD = 50            # UDP packets per window to trigger detection
PORT_SCAN_THRESHOLD = 20      # Unique ports to trigger port scan detection
HOST_SCAN_THRESHOLD = 4       # Unique destinations to trigger host scan detection
FAIL_RATIO_THRESHOLD = 0.6    # Connection failure ratio to trigger detection
REQUEST_WINDOW = 1            # Seconds to track HTTP/SSH requests
REQUEST_THRESHOLD = 5         # Requests per window to trigger brute force detection
DNS_THRESHOLD = 10            # DNS queries to trigger enumeration detection
DNS_WINDOW = 5                # Seconds to track DNS queries
L7_TRUST_WINDOW = 10          # Seconds L7 trust is considered valid
HEALTH_TIMEOUT = 10           # Seconds without health check before whitelist expiry
CHECK_INTERVAL = 10           # Seconds between health whitelist validation
FIRST_SEEN_GRACE = 2          # Seconds before new pods are monitored
MIN_WHITELIST_TIME = 3        # Minimum seconds in whitelist before enforcement

# ==================== DATA STORES ====================
# Track attack types per pod
attack_history = defaultdict(set)

# Health-based whitelist for trusted pod pairs
health_whitelist = set()           # Pods in whitelist
health_last_seen = {}              # Last health check timestamp
health_pairs = {}                  # Bidirectional pod pairs
first_seen = {}                    # First time pod was observed

# Request tracking for brute force detection
request_tracker = defaultdict(lambda: deque())   # HTTP requests
request_tracker2 = defaultdict(lambda: deque())  # SSH SYN packets
dns_tracker = defaultdict(lambda: deque())       # DNS queries
l7_trusted = defaultdict(lambda: deque())        # L7 trust status

# Trust scores per pod
trust_scores = defaultdict(lambda: TRUST_MAX)

# Outgoing traffic statistics per pod
stats_outgoing = defaultdict(lambda: {
    "connections": 0,
    "unique_destinations": set(),
    "failed_connections": 0,
    "syn_count": 0,
    "unique_ports": set()
})

# Incoming traffic statistics per pod (monitoring only)
stats_incoming = defaultdict(lambda: {
    "connections": 0,
    "unique_destinations": set(),
    "failed_connections": 0,
    "syn_count": 0,
    "unique_ports": set()
})

# Attack detection trackers
syn_tracker = defaultdict(deque)    # SYN packet tracking
udp_tracker = defaultdict(deque)    # UDP packet tracking

# Response tracking
redirected = set()                   # Pods redirected to honeypot
quarantined = set()                  # Pods quarantined (blocked)
quarantine_pending = {}              # Pending quarantine actions
pod_roles_cache = {}                 # Cached pod roles (trusted/untrusted)
last_contacted_server = {}           # Last server contacted by each pod

# ==================== LOGGING UTILITIES ====================
log_file = None
log_start_time = None


def init_logging():
    """Initialize the logging system with file rotation."""
    global log_file, log_start_time
    log_file = open_log_file("a")
    log_start_time = datetime.datetime.now()


def open_log_file(mode="a"):
    """Open the log file with the specified mode."""
    return open("trustLog.txt", mode, buffering=1)


def print(*args, **kwargs):
    """
    Custom print function that writes to both console and log file.
    Overrides built-in print for consistent logging.
    """
    global log_file

    # Call built-in print for console output
    builtins.print(*args, **kwargs)

    try:
        msg = " ".join(str(a) for a in args)
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with log_lock:
            log_file.write(f"[{timestamp}] {msg}\n")
            log_file.flush()  # Ensure logs are written immediately

    except Exception:
        pass  # Silently fail if logging fails


def rotate_logs():
    """
    Rotate log files every 24 hours.
    Overwrites the log file instead of creating multiple files.
    """
    global log_file, log_start_time

    while True:
        time.sleep(60)  # Check every minute

        now = datetime.datetime.now()

        if (now - log_start_time).total_seconds() >= 86400:  # 24 hours
            with log_lock:
                try:
                    log_file.close()
                except Exception:
                    pass

                log_file = open_log_file("w")  # Overwrite mode
                log_start_time = now

                builtins.print("\n[*] Log file rotated (24h overwrite)\n")


# ==================== POD ROLE MANAGEMENT ====================
def get_pod_role(pod_name):
    """
    Determine if a pod is trusted (server) or untrusted (client).

    Args:
        pod_name: Name of the Kubernetes pod

    Returns:
        "trusted" for server pods, "untrusted" for client pods
    """
    with pod_roles_lock:
        if pod_name in pod_roles_cache:
            return pod_roles_cache[pod_name]

    try:
        role_label = subprocess.check_output(
            ["kubectl", "get", "pod", pod_name, "-n", "default",
             "-o", "jsonpath={.metadata.labels.role}"],
            text=True
        ).strip()
        role = "trusted" if role_label.startswith("server") else "untrusted"
    except subprocess.CalledProcessError:
        role = "untrusted"

    with pod_roles_lock:
        pod_roles_cache[pod_name] = role

    return role


# ==================== TRUST SCORE MANAGEMENT ====================
def decay_trust():
    """
    Periodically increase trust scores for pods that are not under attack.
    This allows pods to recover trust over time.
    """
    while True:
        time.sleep(DECAY_INTERVAL)

        for pod in list(trust_scores.keys()):
            # Skip pods that are already quarantined or redirected
            if pod in redirected or pod in quarantined:
                continue

            with trust_lock:
                old = trust_scores[pod]
                if trust_scores[pod] < TRUST_MAX:
                    trust_scores[pod] += DECAY_RATE
                    if trust_scores[pod] > TRUST_MAX:
                        trust_scores[pod] = TRUST_MAX
                    print(f"{pod} → Trust rebounded: {round(old,2)} → {round(trust_scores[pod],2)}")


# ==================== STATISTICS MANAGEMENT ====================
def reset_stats():
    """Periodically reset traffic statistics to prevent overflow."""
    while True:
        time.sleep(60)

        with stats_out_lock:
            for pod in list(stats_outgoing.keys()):
                print(f"[*] Sender stats reset for {pod}")
                stats_outgoing[pod] = {
                    "connections": 0,
                    "unique_destinations": set(),
                    "failed_connections": 0,
                    "syn_count": 0,
                    "unique_ports": set()
                }

        with stats_in_lock:
            for pod in list(stats_incoming.keys()):
                print(f"[*] Receiver stats reset for {pod}")
                stats_incoming[pod] = {
                    "connections": 0,
                    "unique_destinations": set(),
                    "failed_connections": 0,
                    "syn_count": 0,
                    "unique_ports": set()
                }

        # Clear all trackers
        with dns_lock:
            dns_tracker.clear()

        with syn_lock:
            syn_tracker.clear()

        with udp_lock:
            udp_tracker.clear()

        with request_tracker_lock:
            request_tracker.clear()

        with request_tracker2_lock:
            request_tracker2.clear()


# ==================== RESPONSE MECHANISMS ====================
def safe_redirect_worker(attacker_pod):
    """Wrapper to execute redirect and revert state if it completely fails."""
    try:
        redirect_to_honeypot(attacker_pod)
    except Exception as e:
        print(f"[!] Critical failure executing redirect for {attacker_pod}: {e}")
        with redirect_lock:
            redirected.discard(attacker_pod)
        with quarantine_pending_lock:
            quarantine_pending.pop(attacker_pod, None)

def redirect_to_honeypot(attacker_pod):
    """
    Redirect an attacking pod to a honeypot instead of the intended target.

    This function:
    1. Deploys a honeypot pod and service for the targeted server
    2. Labels the attacker pod for redirection
    3. Applies a CiliumNetworkPolicy to restrict egress
    4. Patches /etc/hosts for DNS redirection

    Args:
        attacker_pod: Name of the pod to redirect
    """
    if attacker_pod in redirected:
        return
    redirected.add(attacker_pod)
    quarantine_pending[attacker_pod] = time.time()

    print(f"\n[*] Redirecting {attacker_pod} to Honeypot")

    # Determine target server from last contact
    with last_contacted_lock:
        target_server = last_contacted_server.get(attacker_pod, "server1")

    honeypot_name = f"honeypot-{target_server}"
    honeypot_yaml_file = f"/home/kira/dc-lab/{honeypot_name}.yaml"
    honeypot_service_yaml_file = f"/home/kira/dc-lab/{honeypot_name}-service.yaml"

    # Deploy honeypot if not already running
    try:
        existing = subprocess.run(
            ["kubectl", "get", "pod", honeypot_name, "-n", "default"],
            capture_output=True, text=True
        )
        if "NotFound" in existing.stderr or existing.returncode != 0:
            subprocess.run(["kubectl", "apply", "-f", honeypot_yaml_file, "-n", "default"], check=True)
            subprocess.run(["kubectl", "apply", "-f", honeypot_service_yaml_file, "-n", "default"], check=True)
            print(f"[*] Honeypot {honeypot_name} deployed")
        else:
            print(f"[*] Honeypot {honeypot_name} already running")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to deploy honeypot: {e.stderr}")
        return

    time.sleep(1)

    # Label the attacker pod for redirection
    try:
        subprocess.run([
            "kubectl", "label", "pod", attacker_pod,
            f"redirect={attacker_pod}", "--overwrite", "-n", "default"
        ], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Failed to label attacker pod: {e.stderr}")
        return

    # Apply Cilium network policy for redirection
    policy_file = f"/tmp/redirect-{attacker_pod}.yaml"
    policy_yaml = f"""
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: redirect-{attacker_pod}
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      redirect: "{attacker_pod}"
  egress:
  - toEntities:
    - cluster
  - toFQDNs:
    - matchName: "honeypot-{target_server}.default.svc.cluster.local"
"""
    with open(policy_file, "w") as f:
        f.write(policy_yaml)

    try:
        subprocess.run(
            ["kubectl", "apply", "-f", policy_file, "-n", "default"],
            check=True
        )
        print(f"[*] Cilium policy applied: {attacker_pod} → {honeypot_name}")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to apply redirect policy: {e.stderr}")

    # Patch /etc/hosts for DNS reliability
    try:
        svc_ip = subprocess.check_output(
            ["kubectl", "get", "svc", honeypot_name, "-n", "default",
             "-o", "jsonpath={.spec.clusterIP}"],
            text=True
        ).strip()

        subprocess.run([
            "kubectl", "exec", "-n", "default", attacker_pod, "--",
            "sh", "-c", f"echo '{svc_ip} {target_server}' >> /etc/hosts"
        ], check=True)

        print(f"{attacker_pod} /etc/hosts patched: {target_server} -> {svc_ip}")

    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to patch DNS: {e.stderr}")

def safe_quarantine_worker(pod_name):
    """Wrapper to execute quarantine and revert state if it completely fails."""
    try:
        quarantine_server(pod_name)
    except Exception as e:
        print(f"[!] Critical failure executing quarantine for {pod_name}: {e}")
        with quarantine_lock:
            quarantined.discard(pod_name)
        with quarantine_pending_lock:
            quarantine_pending.pop(pod_name, None)

def quarantine_server(pod_name):
    """
    Apply quarantine to a compromised server pod.

    Quarantine restricts the pod to DNS-only egress traffic,
    preventing it from communicating with other services.

    Args:
        pod_name: Name of the server pod to quarantine
    """
    if pod_name in quarantined:
        return
    quarantined.add(pod_name)
    quarantine_pending[pod_name] = time.time()

    print(f"\n[*] Applying quarantine to {pod_name}\n")

    # Label the pod as quarantined
    try:
        subprocess.run(
            ["kubectl", "label", "pod", pod_name, "quarantine=true", "--overwrite", "-n", "default"],
            check=True
        )
    except subprocess.CalledProcessError:
        print(f"[!] {pod_name} disappeared before quarantine.")
        return

    time.sleep(1)  # Allow Kubernetes to register the label

    # Apply DNS-only egress policy
    kube_dns_ip = "10.96.0.10"  # Adjust for your cluster's DNS IP
    policy_file = f"/tmp/quarantine-{pod_name}.yaml"
    policy_yaml = f"""
apiVersion: cilium.io/v2
kind: CiliumNetworkPolicy
metadata:
  name: quarantine-{pod_name}
  namespace: default
spec:
  endpointSelector:
    matchLabels:
      quarantine: "true"
  ingress:
  - fromEndpoints: []
  egress:
  - toCIDR:
    - "{kube_dns_ip}/32"
    toPorts:
    - ports:
      - port: "53"
        protocol: UDP
      - port: "53"
        protocol: TCP
"""
    with open(policy_file, "w") as f:
        f.write(policy_yaml)

    try:
        subprocess.run(
            ["kubectl", "apply", "-f", policy_file, "-n", "default"],
            check=True
        )
        print(f"[*] {pod_name} is quarantined until manually released.\n")
    except subprocess.CalledProcessError as e:
        print(f"[!] Failed to apply quarantine for {pod_name}: {e.stderr}")


def reconcile_pods():
    """
    Periodically check for pods that have been manually un-quarantined or un-redirected.
    Clean up related policies and restore normal operation.
    """
    while True:
        time.sleep(5)

        with quarantine_lock:
            for pod in list(quarantined):
                try:
                    label = subprocess.check_output(
                        ["kubectl", "get", "pod", pod, "-n", "default",
                         "-o", "jsonpath={.metadata.labels.quarantine}"],
                        text=True
                    ).strip()

                    if label != "true":
                        print(f"\nServer {pod} released from quarantine by admin")

                        with quarantine_lock:
                            quarantined.remove(pod)
                        with trust_lock:
                            trust_scores[pod] = TRUST_MAX
                        with stats_out_lock:
                            stats_outgoing[pod] = {
                                "connections": 0,
                                "unique_destinations": set(),
                                "failed_connections": 0,
                                "syn_count": 0,
                                "unique_ports": set()
                            }
                        with stats_in_lock:
                            stats_incoming[pod] = {
                                "connections": 0,
                                "unique_destinations": set(),
                                "failed_connections": 0,
                                "syn_count": 0,
                                "unique_ports": set()
                            }
                        with syn_lock:
                            syn_tracker[pod].clear()
                        with udp_lock:
                            udp_tracker[pod].clear()
                        with quarantine_pending_lock:
                            quarantine_pending.pop(pod, None)

                except subprocess.CalledProcessError:
                    continue


# ==================== HEALTH WHITELIST MANAGEMENT ====================
def validate_health_whitelist():
    """
    Periodically remove expired entries from the health whitelist.
    Pods that haven't sent health checks within HEALTH_TIMEOUT seconds are removed.
    """
    while True:
        time.sleep(CHECK_INTERVAL)
        now = time.time()

        with health_whitelist_lock:
            to_remove = []

            for pod in list(health_whitelist):
                last = health_last_seen.get(pod, 0)

                if now - last > HEALTH_TIMEOUT:
                    to_remove.append(pod)

            for pod in to_remove:
                pair = health_pairs.get(pod)

                health_whitelist.discard(pod)
                health_last_seen.pop(pod, None)

                if pair:
                    health_whitelist.discard(pair)
                    health_last_seen.pop(pair, None)
                    health_pairs.pop(pair, None)

                health_pairs.pop(pod, None)

                print(f"[WHITELIST -] {pod} expired (no health in last {HEALTH_TIMEOUT}s)")


def is_l7_trusted(pod):
    """
    Check if a pod is currently trusted at L7 layer.

    Args:
        pod: Pod name to check

    Returns:
        True if pod is L7 trusted within the time window
    """
    now = time.time()

    with l7_lock:
        t = l7_trusted.get(pod)
        if not t:
            return False

        if now - t > L7_TRUST_WINDOW:
            l7_trusted.pop(pod, None)
            return False

        return True


# ==================== ATTACK DETECTION ====================
def update_trust(pod, dport=None, tcp_flags=None, protocol=None,
                 stats_store=None, initiator=True, http=None, dst_pod=None):
    """
    Update trust score based on observed network behavior.

    This is the core detection function that evaluates multiple attack patterns:
    - Connection failures
    - Port scans
    - Host scans
    - DNS enumeration
    - SYN floods
    - UDP floods
    - Suspicious TCP flag patterns (NULL, FIN, XMAS scans)
    - HTTP brute force
    - SSH brute force

    Args:
        pod: Source pod name
        dport: Destination port
        tcp_flags: TCP flags dictionary
        protocol: Protocol (TCP/UDP)
        stats_store: Statistics store to use
        initiator: Whether this pod initiated the connection
        http: HTTP request information
        dst_pod: Destination pod name

    Returns:
        Updated trust score
    """
    # Grace period for new pods
    with first_seen_lock:
        first = first_seen.setdefault(pod, time.time())

    if time.time() - first < MIN_WHITELIST_TIME:
        return trust_scores.get(pod, 100.0)

   # Only evaluate initiator pods
    if not initiator:
        return trust_scores.get(pod, 100.0)

    penalty = 0

    # === OPTIMIZED STATS EXTRACTION (Replaces copy.deepcopy) ===
    # Extract only the specific metrics needed for detection to maximize throughput
    with stats_out_lock:
        pod_stats = stats_store[pod]
        connections_count = pod_stats["connections"]
        failed_connections_count = pod_stats["failed_connections"]
        unique_ports_count = len(pod_stats["unique_ports"])
        unique_destinations_count = len(pod_stats["unique_destinations"])

	# Capture whether real web traffic exists safely while inside the lock
        has_real_web_traffic = any(p in [80, 443] for p in pod_stats["unique_ports"])
        
        # Shallow copy or a quick snapshot of the destinations set for the whitelist enforcement check later in this function
        unique_destinations_snapshot = set(pod_stats["unique_destinations"])

    # Check whitelist status
    with health_whitelist_lock:
        is_whitelisted = pod in health_whitelist
        pair = health_pairs.get(pod)

    role = get_pod_role(pod)
    suspicious = False

    # === Connection Failure Detection ===
    fail_ratio = 0
    if connections_count > 10:
        fail_ratio = failed_connections_count / connections_count

    if failed_connections_count > 10 or fail_ratio > FAIL_RATIO_THRESHOLD:
        suspicious = True
        if not is_whitelisted:
            print(f"[!] High connection failure from {pod}")
            penalty += 1 if role == "trusted" else 5

    # === Port Scan Detection ===
    if unique_ports_count > PORT_SCAN_THRESHOLD:
        if is_whitelisted:
            pair = health_pairs.get(pod)
            destinations = unique_destinations_snapshot

            if not (pair and destinations == {pair}):
                print(f"[WHITELIST !] {pod} Port scan outside pair → removing whitelist")

                with health_whitelist_lock:
                    for p in [pod, pair]:
                        if p:
                            health_whitelist.discard(p)
                            health_last_seen.pop(p, None)
                            health_pairs.pop(p, None)
        else:
            print(f"[!] Possible Port Scan attack from {pod}")
            penalty += 10

            with attack_lock:
                attack_history[pod].add("port_scan")

    # === Host Scan Detection ===
    if unique_destinations_count > HOST_SCAN_THRESHOLD:
        if is_whitelisted:
            pair = health_pairs.get(pod)
            destinations = unique_destinations_snapshot

            if not (pair and destinations == {pair}):
                print(f"[WHITELIST !] {pod} Host scan outside pair → removing whitelist")

                with health_whitelist_lock:
                    for p in [pod, pair]:
                        if p:
                            health_whitelist.discard(p)
                            health_last_seen.pop(p, None)
                            health_pairs.pop(p, None)
        else:
            print(f"[!] Possible Host Scan attack from {pod}")
            penalty += 10
            with attack_lock:
                attack_history[pod].add("host_scan")

    # === DNS Enumeration Detection ===
    with dns_lock:
        dns_queue = dns_tracker[pod]

    dns_rate = len(dns_queue)

    if connections_count >= 5 and dns_rate > DNS_THRESHOLD:

        if not has_real_traffic and dns_rate > connections_count * 0.7:
            if is_whitelisted:
                pair = health_pairs.get(pod)
                destinations = unique_destinations_snapshot

                if not (pair and destinations == {pair}):
                    print(f"[WHITELIST !] {pod} DNS outside pair → removing whitelist")

                    with health_whitelist_lock:
                        for p in [pod, pair]:
                            if p:
                                health_whitelist.discard(p)
                                health_last_seen.pop(p, None)
                                health_pairs.pop(p, None)
            else:
                print(f"[!] Possible DNS enumeration from {pod}")
                penalty += 10

                with attack_lock:
                    attack_history[pod].add("dns_enum")

    # === SYN Flood Detection ===
    if tcp_flags and tcp_flags.get("SYN") and not tcp_flags.get("ACK"):
        now = time.time()

        with syn_lock:
            syn_queue = syn_tracker[pod]
            syn_queue.append((now, dport, health_pairs.get(pod)))

            while syn_queue and now - syn_queue[0][0] > SYN_WINDOW:
                syn_queue.popleft()

            if len(syn_queue) > SYN_THRESHOLD:
                if is_whitelisted:
                    pair = health_pairs.get(pod)
                    destinations = unique_destinations_snapshot

                    if not (pair and destinations == {pair}):
                        print(f"[WHITELIST !] {pod} SYN outside pair → removing whitelist")

                        with health_whitelist_lock:
                            for p in [pod, pair]:
                                if p:
                                    health_whitelist.discard(p)
                                    health_last_seen.pop(p, None)
                                    health_pairs.pop(p, None)
                else:
                    print(f"[!] Possible SYN flood attack from {pod}")
                    penalty += 15

                    with attack_lock:
                        attack_history[pod].add("syn_flood")

    # === UDP Flood Detection ===
    if protocol == "UDP":
        now = time.time()

        with udp_lock:
            udp_queue = udp_tracker[pod]
            udp_queue.append((now, dport, health_pairs.get(pod)))

            while udp_queue and now - udp_queue[0][0] > UDP_WINDOW:
                udp_queue.popleft()

            if len(udp_queue) > UDP_THRESHOLD:
                if is_whitelisted:
                    pair = health_pairs.get(pod)
                    destinations = unique_destinations_snapshot

                    if not (pair and destinations == {pair}):
                        print(f"[WHITELIST !] {pod} UDP outside pair → removing whitelist")

                        with health_whitelist_lock:
                            for p in [pod, pair]:
                                if p:
                                    health_whitelist.discard(p)
                                    health_last_seen.pop(p, None)
                                    health_pairs.pop(p, None)
                else:
                    print(f"[!] Possible UDP flood attack from {pod}")
                    penalty += 15

                    with attack_lock:
                        attack_history[pod].add("udp_flood")

    # === Suspicious TCP Flag Detection (NULL, FIN, XMAS scans) ===
    if tcp_flags:
        flags_set = [k for k, v in tcp_flags.items() if v]

        scan_type = None
        msg = None

        if len(flags_set) == 0:
            scan_type = "null_scan"
            msg = "NULL scan"
        elif flags_set == ["FIN"]:
            scan_type = "fin_scan"
            msg = "FIN scan"
        elif all(f in flags_set for f in ["FIN", "PSH", "URG"]):
            scan_type = "xmas_scan"
            msg = "XMAS scan"

        if scan_type:
            if is_whitelisted:
                pair = health_pairs.get(pod)
                destinations = unique_destinations_snapshot

                if not (pair and destinations == {pair}):
                    print(f"[WHITELIST !] {pod} {msg} outside pair → removing whitelist")

                    with health_whitelist_lock:
                        for p in [pod, pair]:
                            if p:
                                health_whitelist.discard(p)
                                health_last_seen.pop(p, None)
                                health_pairs.pop(p, None)
            else:
                print(f"[!] Possible {msg} from {pod}")
                penalty += 15

                with attack_lock:
                    attack_history[pod].add(scan_type)

    # === HTTP Brute Force Detection ===
    now = time.time()

    if dport == 80:
        with request_tracker_lock:
            queue = request_tracker[pod]
            
            queue.append(now)

            # Prune stale entries to prevent memory leaks / OOM
            while queue and now - queue[0] > REQUEST_WINDOW:
                queue.popleft()

            # Evaluate brute force behavior if it bypasses health metrics
            is_http_request = http is not None
            is_health_check = http and (http.get("url") or "").endswith("/health")

            if is_http_request and not is_health_check:
                if len(queue) > REQUEST_THRESHOLD:
                    suspicious = True

                    if is_whitelisted:
                        pair = health_pairs.get(pod)
                        destinations = unique_destinations_snapshot

                        if not (pair and destinations == {pair}):
                            print(f"[WHITELIST !] {pod} HTTP brute force outside pair → removing whitelist")
                            with health_whitelist_lock:
                                for p in [pod, pair]:
                                    if p:
                                        health_whitelist.discard(p)
                                        health_last_seen.pop(p, None)
                                        health_pairs.pop(p, None)
                    else:
                        print(f"[!] Possible HTTP Brute Force attack from {pod}")
                        penalty += 15
                        with attack_lock:
                            attack_history[pod].add("http_bruteforce")

    # === SSH Brute Force Detection ===
    if dport == 22:
        with request_tracker2_lock:
            queue = request_tracker2[pod]
            
            queue.append(now)

            # Prune stale entries to prevent memory leaks / OOM
            while queue and now - queue[0] > REQUEST_WINDOW:
                queue.popleft()

            # Check for specific brute-force signatures safely
            is_syn_packet = tcp_flags and tcp_flags.get("SYN") and not tcp_flags.get("ACK")
            
            if is_syn_packet:
                if len(queue) > REQUEST_THRESHOLD:
                    suspicious = True

                    if is_whitelisted:
                        pair = health_pairs.get(pod)
                        destinations = unique_destinations_snapshot

                        if not (pair and destinations == {pair}):
                            print(f"[WHITELIST !] {pod} SSH brute force outside pair → removing whitelist")
                            with health_whitelist_lock:
                                for p in [pod, pair]:
                                    if p:
                                        health_whitelist.discard(p)
                                        health_last_seen.pop(p, None)
                                        health_pairs.pop(p, None)
                    else:
                        print(f"[!] Possible SSH Brute Force attack from {pod}")
                        penalty += 15
                        with attack_lock:
                            attack_history[pod].add("ssh_bruteforce")

    # === Whitelist Enforcement ===
    with health_whitelist_lock:
        in_whitelist = pod in health_whitelist
        paired_pod = health_pairs.get(pod)

    if in_whitelist:
        # If no paired pod, skip enforcement
        if not paired_pod:
            return trust_scores.get(pod, 100.0)

        # Verify traffic only goes to paired pod
        if paired_pod and dport is not None:
            if paired_pod not in unique_destinations_snapshot:
                print(f"[WHITELIST !] {pod} contacted external → removing whitelist")

                with health_whitelist_lock:
                    for p in [pod, paired_pod]:
                        health_whitelist.discard(p)
                        health_last_seen.pop(p, None)
                        health_pairs.pop(p, None)
            else:
                return trust_scores.get(pod, 100.0)

    # === Apply Penalty ===
    if not is_whitelisted:
        with trust_lock:
            old = trust_scores.get(pod, 100.0)
            new = max(0, old - penalty)
            trust_scores[pod] = new

            if old != new:
                print(f"{pod} → Trust: {round(old,2)} → {round(new,2)}")

    # === Trigger Responses ===
    # Redirect attackers (untrusted pods below threshold)
    if role != "trusted" and trust_scores[pod] < THRESHOLD:
        # Acquire the specific response lock immediately to prevent race conditions
        with redirect_lock:
            if pod not in redirected:
                # 1. MARK IMMEDIATELY to block subsequent flows from spawning threads
                redirected.add(pod)
                with quarantine_pending_lock:
                    quarantine_pending[pod] = time.time()
                
                # 2. Safely spawn the worker thread now that the door is shut
                threading.Thread(
                    target=safe_redirect_worker,
                    args=(pod,),
                    daemon=True
                ).start()

    # Quarantine compromised servers
    if role == "trusted" and trust_scores[pod] < THRESHOLD:
        # Acquire the specific response lock immediately
        with quarantine_lock:
            if pod not in quarantined:
                # MARK IMMEDIATELY to block subsequent loops
                quarantined.add(pod)
                with quarantine_pending_lock:
                    quarantine_pending[pod] = time.time()
                
                # Safely spawn the quarantine thread
                threading.Thread(
                    target=safe_quarantine_worker,
                    args=(pod,),
                    daemon=True
                ).start()

    return trust_scores[pod]


# ==================== FLOW PARSING UTILITIES ====================
def parse_flow(flow):
    """
    Parse a Hubble flow JSON object into a standardized dictionary.

    Args:
        flow: Hubble flow dictionary

    Returns:
        Parsed flow data or None if invalid
    """
    if not isinstance(flow, dict):
        return None

    src_info = flow.get("source") or {}
    dst_info = flow.get("destination") or {}
    ip_info = flow.get("IP") or {}

    l4 = flow.get("l4") or {}
    tcp = l4.get("TCP") if isinstance(l4.get("TCP"), dict) else None
    udp = l4.get("UDP") if isinstance(l4.get("UDP"), dict) else None

    protocol = None
    tcp_flags = {}
    src_port = None
    dst_port = None

    if tcp:
        protocol = "TCP"
        tcp_flags = tcp.get("flags") or {}
        src_port = tcp.get("source_port")
        dst_port = tcp.get("destination_port")
    elif udp:
        protocol = "UDP"
        src_port = udp.get("source_port")
        dst_port = udp.get("destination_port")

    return {
        "src_pod": src_info.get("pod_name"),
        "src_ns": src_info.get("namespace"),
        "src_ip": ip_info.get("source"),
        "dst_pod": dst_info.get("pod_name"),
        "dst_ns": dst_info.get("namespace"),
        "dst_ip": ip_info.get("destination"),
        "protocol": protocol,
        "tcp_flags": tcp_flags,
        "src_port": src_port,
        "dst_port": dst_port,
        "verdict": flow.get("verdict"),
        "time": flow.get("time"),
        "l7": flow.get("l7") if isinstance(flow.get("l7"), dict) else None
    }


def extract_http(flow):
    """
    Extract HTTP information from a flow.

    Args:
        flow: Hubble flow dictionary

    Returns:
        HTTP info dictionary or None
    """
    l7 = flow.get("l7")
    if not l7:
        return None

    http = l7.get("http")
    if not http:
        return None

    return {
        "method": http.get("method"),
        "url": http.get("url"),
        "code": http.get("code"),
        "protocol": http.get("protocol"),
        "type": l7.get("type")
    }


def extract_dns(flow):
    """
    Extract DNS query from a flow.

    Args:
        flow: Hubble flow dictionary

    Returns:
        DNS query string or None
    """
    l7 = flow.get("l7")
    if not l7:
        return None

    dns = l7.get("dns")
    if not dns:
        return None

    return dns.get("query")


# ==================== MAIN MONITORING LOOP ====================
def main():
    """Main monitoring loop that consumes Hubble flow events."""
    # Initialize logging
    init_logging()

    # Start background threads
    threading.Thread(target=reset_stats, daemon=True).start()
    threading.Thread(target=reconcile_pods, daemon=True).start()
    threading.Thread(target=decay_trust, daemon=True).start()
    threading.Thread(target=rotate_logs, daemon=True).start()
    threading.Thread(target=validate_health_whitelist, daemon=True).start()

    while True:
        try:
            # Start Hubble process
            process = subprocess.Popen(
                ["hubble", "observe", "--follow", "-o", "json"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                bufsize=1
            )

            # Process each flow line
            for line in process.stdout:
                try:
                    data = json.loads(line.strip())
                    flow = data.get("flow")
                    if not flow:
                        continue

                    flow_data = parse_flow(flow)
                    if not flow_data:
                        continue

                    # Extract HTTP info if present
                    flow_data["http"] = extract_http(flow)

                    src_pod = flow_data["src_pod"]
                    dst_pod = flow_data["dst_pod"]

                    # Filter out non-default namespace and system pods
                    if not src_pod or flow_data["src_ns"] != "default":
                        continue
                    if src_pod.startswith("coredns") or src_pod.startswith("hubble"):
                        continue

                    # === Health Check Whitelist Management ===
                    http = flow_data.get("http")

                    if http and src_pod and dst_pod:
                        path = http.get("url") or ""
                        now = time.time()

                        with health_whitelist_lock:
                            # Add to whitelist on health check
                            if "/health" in path:
                                if src_pod not in health_whitelist:
                                    health_whitelist.add(src_pod)
                                    health_whitelist.add(dst_pod)

                                    health_pairs[src_pod] = dst_pod
                                    health_pairs[dst_pod] = src_pod

                                    print(f"[WHITELIST +] {src_pod} <-> {dst_pod} (health detected)")

                                health_last_seen[src_pod] = now
                                health_last_seen[dst_pod] = now

                    # Policy lag delay for new redirections/quarantines
                    with quarantine_pending_lock:
                        if src_pod in quarantine_pending:
                            if time.time() - quarantine_pending[src_pod] < POLICY_LAG:
                                continue
                            else:
                                quarantine_pending.pop(src_pod)

                    # === Determine Flow Initiator ===
                    is_initiator = False

                    if flow_data.get("http"):
                        is_initiator = True
                    elif flow_data["protocol"] == "TCP":
                        tcp_flags = flow_data["tcp_flags"] or {}
                        if tcp_flags.get("SYN") and not tcp_flags.get("ACK"):
                            is_initiator = True
                    elif flow_data["protocol"] == "UDP":
                        is_initiator = True

                    # === Update Statistics and Trust ===
                    if is_initiator:
                        with stats_out_lock:
                            s_out = stats_outgoing[src_pod]
                            s_out["connections"] += 1

                            if flow_data["protocol"] == "TCP" and flow_data["tcp_flags"] and \
                               flow_data["tcp_flags"].get("SYN"):
                                s_out["syn_count"] += 1

                            if flow_data["dst_port"] is not None:
                                s_out["unique_ports"].add(flow_data["dst_port"])

                            if dst_pod:
                                s_out["unique_destinations"].add(dst_pod)

                                # Track last contacted server for redirection
                                if flow_data["dst_ns"] == "default" and dst_pod.startswith("server"):
                                    with last_contacted_lock:
                                        last_contacted_server[src_pod] = dst_pod

                            if flow_data["verdict"] == "DROPPED":
                                s_out["failed_connections"] += 1

                        # Track DNS queries
                        if flow_data["dst_port"] == 53:
                            now = time.time()
                            dns_query = extract_dns(flow)

                            with dns_lock:
                                q = dns_tracker[src_pod]
                                q.append((now, dst_pod, dns_query))

                                while q and now - q[0][0] > DNS_WINDOW:
                                    q.popleft()

                        # Update trust score for this pod
                        score = update_trust(
                            pod=src_pod,
                            dport=flow_data["dst_port"],
                            tcp_flags=flow_data["tcp_flags"],
                            protocol=flow_data["protocol"],
                            stats_store=stats_outgoing,
                            initiator=is_initiator,
                            http=flow_data.get("http"),
                            dst_pod=dst_pod
                        )

                    else:
                        with trust_lock:
                            score = trust_scores.get(src_pod, TRUST_MAX)

                            if dst_pod:
                                with stats_in_lock:
                                    s_in = stats_incoming[dst_pod]
                                    s_in["connections"] += 1

                                    if flow_data["protocol"] == "TCP" and flow_data["tcp_flags"] and \
                                       flow_data["tcp_flags"].get("SYN"):
                                        s_in["syn_count"] += 1

                                    if flow_data["dst_port"] is not None:
                                        s_in["unique_ports"].add(flow_data["dst_port"])

                                    if src_pod:
                                        s_in["unique_destinations"].add(src_pod)

                    # === Log Output ===
                    src_port = flow_data["src_port"]
                    dst_port = flow_data["dst_port"]

                    dst_display = dst_pod if dst_pod else "outside"
                    if dst_display and dst_display.startswith("coredns"):
                        dst_display = "dns-server"

                    with stats_out_lock:
                        s_out = stats_outgoing.get(src_pod, {
                            "connections": 0,
                            "unique_ports": set(),
                            "unique_destinations": set()
                        })

                    conn = s_out["connections"]
                    ports = len(s_out["unique_ports"])
                    dsts = len(s_out["unique_destinations"])

                    http = flow_data.get("http")

                    if http:
                        http_info = f" | HTTP {http['method']} {http['url']} -> {http['code']}"
                    else:
                        http_info = " | HTTP unavailable"

                    t = flow_data.get("time")
                    t_display = t[11:19] if isinstance(t, str) else "??:??:??"

                    print(
                        f"{t_display} | "
                        f"{src_pod}:{src_port} -> {dst_display}:{dst_port} | "
                        f"{flow_data['protocol']} | flags={flow_data['tcp_flags']} | "
                        f"trust={round(score,2)} | "
                        f"OUT(conn={conn}, ports={ports}, dst={dsts})"
                        f"{http_info}"
                    )

                except Exception as e:
                    print("Flow parse error:", e)
                    continue

            print("Hubble stopped, restarting in 2s...")
            time.sleep(2)

        except Exception as e:
            print("Hubble process error:", e)
            time.sleep(5)


if __name__ == "__main__":
    main()
