# Memusage Roadmap

## Overview

`memusage` is a tool for monitoring memory usage. Our goal is to enhance its functionality and performance, as well as expand its features for security analysis.

## Next Steps

### Immediate Fixes and Improvements

* **Deprecation Warning Fix:** Replace the `connections()` method with `net_connections()`.
* **Enhanced User Information:** Add details about the running user (session ID, remote status, and origin).

### Performance Optimization

* **Flexible Execution:** Implement options for "full run" or "diskless run" to reduce execution time in environments with many disks.
* **Output Formats:** Add output in JSON and TXT formats for greater flexibility and display optimization.

### Future Research and Development

* **BPF Exploration:** Investigate the use of BPF (Berkeley Packet Filter) for performance and compatibility improvements.
* **GUI and Remote Execution:** Develop a version with a graphical interface and remote execution capabilities, transforming it into a security tool.

## Contributors

Special thanks to @mauricioperez for their valuable contributions and suggestions.
