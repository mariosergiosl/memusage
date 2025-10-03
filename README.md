# memusage - A Swiss Army knife for comprehensive Linux process analysis

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg?logo=python&logoColor=white)](https://www.python.org/)
[![Platform: Linux](https://img.shields.io/badge/platform-linux-green.svg?logo=linux&logoColor=white)](https://www.kernel.org/)
[![GitHub Stars](https://img.shields.io/github/stars/mariosergiosl/memusage?style=social)](https://github.com/mariosergiosl/memusage/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/mariosergiosl/memusage?style=social)](https://github.com/mariosergiosl/memusage/network/members)
[![GitHub Release](https://img.shields.io/github/v/release/mariosergiosl/memusage)](https://github.com/mariosergiosl/memusage/releases)
[![Build Status](https://img.shields.io/github/actions/workflow/status/mariosergiosl/memusage/python-app.yml?branch=main)](https://github.com/mariosergiosl/memusage/actions)
[![Issues](https://img.shields.io/github/issues/mariosergiosl/memusage)](https://github.com/mariosergiosl/memusage/issues)
[![Code Size](https://img.shields.io/github/languages/code-size/mariosergiosl/memusage)](https://github.com/mariosergiosl/memusage)
[![Last Commit](https://img.shields.io/github/last-commit/mariosergiosl/memusage)](https://github.com/mariosergiosl/memusage/commits/main)
[![Downloads](https://img.shields.io/github/downloads/mariosergiosl/memusage/total?label=Downloads)](https://github.com/mariosergiosl/memusage/releases)

This tool provides deep insights into process behavior, making it invaluable for
troubleshooting and security auditing. It details:

- Memory usage (current and cumulative process tree).
- Open files, including extensive disk attributes (filesystem type, mount options,
  UUIDs, LVM, multipath, disk type, model, vendor, and persistent device aliases).
- Network connections (local/remote addresses, status).
- I/O activity (read/write bytes).
- Executable forensics (MD5 hash for integrity checks).
- Process context (full command line, security labels like AppArmor/SELinux).
- Anomaly detection via suspicious environment variables.

Designed for system administrators, security analysts, and DevOps engineers.

---

## Hands-On Lab: Troubleshooting a High I/O Scenario

Want to see `memusage.py` in action? Follow our step-by-step tutorial to simulate and diagnose a real-world disk I/O bottleneck.

**➡️ [Click here to open the Lab Instructions](./LAB.md)**

---

## Features

`memusage` gives a detailed, hierarchical view of system processes, including:

- **Memory:** Current and cumulative usage for a process and its entire child tree.
- **Open Files:** Lists open files with extensive disk attributes (filesystem, mount options, UUIDs, LVM, multipath, disk type, model, and vendor).
- **Network:** Active network connections with addresses, status, and I/O stats.
- **Disk I/O:** Cumulative read and write bytes for each process.
- **Forensics:** The MD5 hash of the process executable for integrity verification.
- **Security:** The process's security context (e.g., AppArmor/SELinux) and highlights potentially suspicious environment variables.

---

## Installation

For detailed installation instructions, please see the [INSTALL.md](./INSTALL.md) file.

---

## Running code (Not Installation)

1. Install dependency:
   ```bash
   pip3 install psutil
   ```

2. Run the script:
   ```bash
   python3 memusage.py
   ```

---

## Usage - Running code (Not Installation)

Run the script from the command line:

```bash
python3 memory_usage.py
```

---

## Usage - if installation

Run the script from the command line:

```bash
memusage
```

---

## Output

The output will show:

- Total system memory
- Free system memory
- Used system memory
- Total memory usage of the process tree
- Memory usage of each process with its PID, name, and memory consumption, color-coded by priority:
  - For each process:
    - PID
    - CMDLINE
    - Executable MD5
    - Security Context
    - Loaded Libraries (Non-System)
    - Process name
    - Memory usage
    - Open files
      - Disk Device Information
    - Network connections
    - I/O activity (read and write bytes)
    - Note: The Read bytes and Write bytes values are cumulative.
- The output is color-coded based on process priority:

| Priority | Color  | Nice Value  |
|----------|--------|-------------|
| High     | Red    | -20, -15, -10 |
| Medium   | Yellow | -5, 0, 5    |
| Low      | Green  | 10, 15, 19  |

---

## Testing Color-Coded Output

To test the color-coded output, you can run processes with different priorities using the `nice` command.

**Examples:**

- High priority:
  ```bash
  nice -n -20 yes > /dev/null &
  ```

- Medium priority:
  ```bash
  nice -n -20 yes > /dev/null &
  ```

- Low priority:
  ```bash
  nice -n -20 yes > /dev/null &
  ```

After running these commands, execute `memusage` again and observe the color-coded output.

**Priority Color Table:**

```
Priority: -20   Color:
Priority: -19   Color:
Priority: -18   Color:
Priority: -17   Color:
Priority: -16   Color:
Priority: -15   Color:
Priority: -14   Color:
Priority: -13   Color:
Priority: -12   Color:
Priority: -11   Color:
Priority: -10   Color:
Priority: -9    Color:
Priority: -8    Color:
Priority: -7    Color:
Priority: -6    Color:
Priority: -5    Color:
Priority: -4    Color:
Priority: -3    Color:
Priority: -2    Color:
Priority: -1    Color:
Priority: 0     Color:
Priority: 1     Color:
Priority: 2     Color:
Priority: 3     Color:
Priority: 4     Color:
Priority: 5     Color:
Priority: 6     Color:
Priority: 7     Color:
Priority: 8     Color:
Priority: 9     Color:
Priority: 10    Color:
Priority: 11    Color:
Priority: 12    Color:
Priority: 13    Color:
Priority: 14    Color:
Priority: 15    Color:
Priority: 16    Color:
Priority: 17    Color:
Priority: 18    Color:
Priority: 19    Color:

Total system memory: 7877.34375 MB
Free system memory: 5532.8359375 MB
Used system memory: 2344.5078125 MB

Total memory process tree: 3469.51 MB

Memory usage of each process:
PID - Process Name (Memory Usage)
1 - systemd (14.37 MB)
  - CMDLINE: /usr/lib/systemd/systemd --switched-root --system --deserialize=42
  - Executable MD5: 0d31356f9ce30df5916faa0a5b4c440a
  - Security Context: AppArmor: unconfined
  - Read bytes: 885152256
  - Write bytes: 529428480
  600 - systemd-journald (9.88 MB)
    - CMDLINE: /usr/lib/systemd/systemd-journald
    - Executable MD5: 95366e94f1ff2fec08432a507a451337
    - Security Context: AppArmor: unconfined
    - /proc/sys/kernel/hostname
    - /run/log/journal/24a550029dff4a95994d4266dd0763e7/system.journal
    - Read bytes: 225280
    - Write bytes: 0
  626 - systemd-udevd (13.00 MB)
    - CMDLINE: /usr/lib/systemd/systemd-udevd
    - Executable MD5: 7ba915087bd426a3e2a8d6d63ef6de20
    - Security Context: AppArmor: unconfined
    - /etc/udev/hwdb.bin (FSTYPE:btrfs DISK:/dev/sda DEV:sda2 ID:c929e557-b1f5-491e-9740-35c7a3d348d3 UUID:4774239a-1b39-4397-b9d6-ee8bc6315f86 DISK_TYPE:HDD MODEL: VENDOR: ALIASES:[by-path/pci-0000:00:10.0-scsi-0:0:0:0-part2])
    - Read bytes: 26279424
    - Write bytes: 0
  686 - haveged (4.86 MB)
    - CMDLINE: /usr/sbin/haveged -w 1024 -v 0 -F
    - Executable MD5: 4feb98b6eb6a768c200ac11336022f33
    - Security Context: AppArmor: unconfined
    - Read bytes: 151552
    - Write bytes: 0

... [continue]

--- End of Report ---

Notes:
 - Accessing some information - 
e.g., open files of other users, multipath, executable hash, env vars, security context
may require 'sudo' privileges.
 - Read bytes and Write bytes values are cumulative since process start.
 - 'N/A' means information could not be obtained or is not applicable.


--- Understanding Disk Identifiers in Data Centers ---
 - For enterprise storage (SAN/NAS), standard device names like /dev/sda are volatile.
 - Persistent identifiers like UUID and aliases are crucial:
   - UUID: Universal Unique Identifier of the filesystem on a partition/volume.
     Often used in /etc/fstab for consistent mounting.
   - ID (PARTUUID): Unique ID of the partition itself (if applicable).
     Distinguishes partitions on the same disk when UUIDs might conflict (e.g., after cloning).
   - ALIASES: Alternate, persistent paths to the device in /dev/disk/ by-id, by-path, by-uuid, by-label.
     - by-id/: Hardware-based IDs (manufacturer, model, serial). Highly stable.
     - by-path/: Physical path through hardware (PCI slot, HBA port, SCSI target).
       * CRUCIAL for SANs: 'by-path' (e.g., pci-0000:00:10.0-scsi-0:0:0:0-part2)
         can reveal the HBA adapter (e.g., pci-0000:00:10.0), Fibre Channel/iSCSI port,
         and LUN ID from the storage array. This allows correlation with SAN zoning/masking.
         It helps identify the physical location of the LUN within the storage infrastructure.
     - by-uuid/: Symlinks using the filesystem UUID (duplicate of the UUID field, but listed here for completeness of aliases).
     - by-label/: Symlinks using filesystem labels defined by the user.
 - LVM (Logical Volume Management): Indicates if a file resides on a logical volume.
   LVM allows flexible storage management over physical volumes.
 - Disk Type (SSD/HDD), Model, Vendor: Provide insights into disk performance characteristics.
 - Multipath (MP_ID, MP_PATHS): Shows if multiple paths exist to the same LUN for redundancy/performance.
   Common in SAN environments to avoid single points of failure.
 - Command and path limits have been applied for better readability.
```

---

## Contributing

Contributions are welcome! Please open an issue or submit a pull request if you have any suggestions or bug reports.

---

## License

This program is licensed under the GNU General Public License v2 or later.
