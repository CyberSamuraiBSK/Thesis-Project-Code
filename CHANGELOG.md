trustEngine.py
- Original Python implementation developed for the thesis project.

revisedTrustEngine.py
- Refactored version with improved code structure, readability, and documentation for public repository use.

revisedTrustEngineV2.py
- Updated version with security, stability, and performance improvements:

  - Memory Leak Resolution
    - Restructured timestamp tracking logic to always append and prune entries immediately upon matching monitored ports (dport == 80 or dport == 22).
    - Separated queue maintenance from nested signature-verification logic to ensure consistent cleanup and bounded memory usage.

  - TOCTOU (Time-of-Check to Time-of-Use) Prevention
    - Moved pod state tracking (.add(pod)) inside synchronized lock sections (redirect_lock and quarantine_lock) before invoking background workers.
    - Added safe worker wrappers (safe_redirect_worker and safe_quarantine_worker) to automatically revert state when critical kubectl orchestration failures occur.

  - Performance Enhancement
    - Removed all use of copy.deepcopy().
    - Replaced deep-copy operations with a short-duration read lock (stats_out_lock) that extracts only required primitive statistics and constructs a minimal shallow snapshot containing the specific network destinations needed for whitelist evaluation.
