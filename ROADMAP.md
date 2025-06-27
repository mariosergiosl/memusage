# Memusage Roadmap

## Overview

`memusage` is a tool for monitoring memory usage. Our goal is to enhance its functionality and performance, as well as expand its features for security analysis.

## Next Steps

### Immediate Fixes and Improvements

* **Deprecation Warning Fix:** Replace the `connections()` method with `net_connections()`.
    * **Detailed Analysis:** A deprecation warning for `connections()` was observed on Manjaro 25.0.4 Zetar with Python 3.13.3, suggesting `net_connections()` as a replacement.
    * Currently, `memusage.py` uses `process.connections()` (from `psutil`) to retrieve *per-process* network connections. The standard `psutil.net_connections()` function is for *system-wide* connections and is not a direct, like-for-like replacement for `process.connections()` to maintain the original logic.
    * As this warning does not currently prevent the tool's usage on our primary build environments (e.g., openSUSE Build Service), we will **monitor future `psutil` releases and documentation** for a clear, per-process oriented replacement for `process.connections()`. The adjustment will be made when a suitable and clear path for preserving the per-process connection analysis is available, or if the current method becomes critical to functionality.
* **Enhanced User Information:** Add details about the running user (session ID, remote status, and origin).

### Performance Optimization

* **Flexible Execution:** Implement options for "full run" or "diskless run" to reduce execution time in environments with many disks.
* **Output Formats:** Add output in JSON and TXT formats for greater flexibility and display optimization.

### Future Research and Development

* **BPF Exploration:** Investigate the use of BPF (Berkeley Packet Filter) for performance and compatibility improvements.
* **GUI and Remote Execution:** Develop a version with a graphical interface and remote execution capabilities, transforming it into a security tool.

## Contributors

Special thanks to @Mario Luz and @mauricioperez for their valuable contributions and suggestions.
