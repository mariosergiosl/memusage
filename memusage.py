#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright (C) 2024 Mario Luz

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License For more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

"""
memusage - A Swiss Army knife for comprehensive Linux process analysis.
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
"""

import os
import re
import socket
import subprocess
import hashlib
import sys
import datetime
from typing import Optional

import psutil

# Colors for process priority
NICE_COLORS = {
    -20: "\033[91m",  # Red
    -19: "\033[91m",  # Red
    -18: "\033[91m",  # Red
    -17: "\033[91m",  # Red
    -16: "\033[91m",  # Red
    -15: "\033[91m",  # Red
    -14: "\033[93m",  # Yellow
    -13: "\033[93m",  # Yellow
    -12: "\033[93m",  # Yellow
    -11: "\033[93m",  # Yellow
    -10: "\033[93m",  # Yellow
    -9: "\033[93m",    # Yellow
    -8: "\033[92m",    # Green
    -7: "\033[92m",    # Green
    -6: "\033[92m",    # Green
    -5: "\033[92m",    # Green
    -4: "\033[92m",    # Green
    -3: "\033[92m",    # Green
    -2: "\033[92m",    # Green
    -1: "\033[92m",    # Green
    0: "\033[92m",     # Green
    1: "\033[92m",     # Green
    2: "\033[92m",     # Green
    3: "\033[92m",     # Green
    4: "\033[92m",     # Green
    5: "\033[92m",     # Green
    6: "\033[94m",     # Blue
    7: "\033[94m",     # Blue
    8: "\033[94m",     # Blue
    9: "\033[94m",     # Blue
    10: "\033[94m",    # Blue
    11: "\033[94m",    # Blue
    12: "\033[94m",    # Blue
    13: "\033[94m",    # Blue
    14: "\033[94m",    # Blue
    15: "\033[94m",    # Blue
    16: "\033[90m",    # Grey
    17: "\033[90m",    # Grey
    18: "\033[90m",    # Grey
    19: "\033[90m",    # Grey
}

# Define ANSI colors for script use
RED_COLOR = "\033[91m"
RESET_COLOR = "\033[0m"
# Mapping for HTML conversion
ANSI_COLOR_MAP = {
    "\033[91m": '<span style="color: red;">',
    "\033[93m": '<span style="color: yellow;">',
    "\033[92m": '<span style="color: limegreen;">',
    "\033[94m": '<span style="color: dodgerblue;">',
    "\033[90m": '<span style="color: grey;">',
    "\033[0m": '</span>',
}


# Define memory and open_files thresholds from environment if available
MEMORY_THRESHOLD_MB = int(os.environ.get('MEMORY_THRESHOLD_MB', 200))
OPEN_FILES_THRESHOLD = int(os.environ.get('OPEN_FILES_THRESHOLD', 50))

# Common system library paths to filter out for 'Loaded Libraries'
COMMON_LIB_PATHS = [
    '/lib/', '/usr/lib/', '/lib64/', '/usr/lib64/',
    '/usr/local/lib/',
    '/snap/',
    '/opt/',
    '/var/lib/snapd/',
    '/usr/bin/python3',
    '/usr/bin/python',
]


# --- Functions to retrieve additional system information ---


def _run_cmd(cmd_list):
    """Helper to run subprocess commands and return stripped stdout."""
    try:
        # Use universal_newlines=True for Python < 3.7 compatibility
        return subprocess.check_output(cmd_list, universal_newlines=True, stderr=subprocess.DEVNULL).strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ""


# Cache for lsblk -P output
# This will store a dictionary for each device name
_LSBLK_CACHE_PARSED = {}


def _populate_lsblk_cache():
    """Populates the lsblk cache by parsing lsblk -P output.
    Uses only commonly supported columns for older lsblk versions, including MODEL/VENDOR and PARTUUID."""
    global _LSBLK_CACHE_PARSED
    _LSBLK_CACHE_PARSED = {}  # Clear previous cache

    try:
        # Re-added PARTUUID for disk_id, and MODEL/VENDOR
        # The list of columns used here should be broadly compatible.
        lsblk_output = _run_cmd(["lsblk", "-P", "-o", "NAME,PKNAME,FSTYPE,MOUNTPOINT,UUID,PARTUUID,ROTA,TYPE,MODEL,VENDOR,MAJ:MIN"])

        for line in lsblk_output.splitlines():
            device_info = {}
            # Parse key="value" pairs
            for match in re.finditer(r'(\w+)="([^"]*)"', line):
                key, value = match.groups()
                device_info[key.lower()] = value  # Store keys in lowercase

            if 'name' in device_info:
                _LSBLK_CACHE_PARSED[device_info['name']] = device_info
    except Exception as e:
        # print(f"DEBUG: Error populating lsblk cache: {e}")
        _LSBLK_CACHE_PARSED = {}


_LVS_CACHE = {}  # Cache for LVM Logical Volumes
_VGS_CACHE = {}  # Cache for LVM Volume Groups


def _populate_lvm_cache():
    """Populates caches for LVM Logical Volumes (LVs) and Volume Groups (VGs)."""
    global _LVS_CACHE, _VGS_CACHE
    _LVS_CACHE = {}
    _VGS_CACHE = {}

    try:
        # lvs output: LV Name, VG Name, LV Path
        lvs_output = _run_cmd(["lvs", "--noheadings", "-o", "lv_name,vg_name,lv_path"])
        for line in lvs_output.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3:
                lv_name, vg_name, lv_path = parts[0], parts[1], parts[2]
                _LVS_CACHE[lv_path] = {'lv_name': lv_name, 'vg_name': vg_name}

        # vgs output: VG Name, VG Size, VG Free (optional)
        vgs_output = _run_cmd(["vgs", "--noheadings", "-o", "vg_name,vg_size,vg_free"])
        for line in vgs_output.splitlines():
            parts = line.strip().split()
            if len(parts) >= 2:
                vg_name, vg_size = parts[0], parts[1]
                _VGS_CACHE[vg_name] = {'vg_size': vg_size, 'vg_free': parts[2] if len(parts) > 2 else 'N/A'}
    except Exception:
        # print(f"DEBUG: Error populating LVM cache: {e}")
        _LVS_CACHE = {}
        _VGS_CACHE = {}


def get_device_info_from_lsblk(device_name):
    """Retrieves detailed device info from lsblk cache."""
    return _LSBLK_CACHE_PARSED.get(device_name, None)


def get_mount_info(path):
    """
    Gets the mount point of a given path and its mount options.
    Uses 'findmnt' for robustness.
    """
    if not path or not path.startswith('/'):
        return {"mount_point": "N/A", "mount_options": "N/A"}
    try:
        # findmnt -n -o TARGET,OPTIONS <path>
        cmd = ["findmnt", "-n", "-o", "TARGET,OPTIONS", path]
        findmnt_output = _run_cmd(cmd)

        if findmnt_output:
            parts = findmnt_output.split(maxsplit=1)
            mount_point = parts[0].strip()
            mount_options = parts[1].strip() if len(parts) > 1 else "N/A"
            return {"mount_point": mount_point, "mount_options": mount_options}
        return {"mount_point": "N/A", "mount_options": "N/A"}
    except Exception:
        return {"mount_point": "N/A", "mount_options": "N/A"}


def get_disk_info(path):
    """
    Gets the primary physical disk name, Disk ID (PARTUUID), Disk UUID (FS UUID), device name,
    FSTYPE, LVM info (if available), Disk Type (SSD/HDD), MODEL, VENDOR, and device aliases for a given path.
    Uses 'df' to find the device and 'lsblk' (cached) to find the information.
    """
    info = {
        'physical_disk': "N/A",
        'disk_id': "N/A",  # This will be PARTUUID
        'disk_uuid': "N/A",  # This will be filesystem UUID
        'device_name': "N/A",  # e.g., sda2, dm-0
        'fstype': "N/A",
        'lvg_name': "N/A",  # LVM Volume Group Name
        'lvl_name': "N/A",  # LVM Logical Volume Name
        'disk_type': "N/A",  # SSD or HDD
        'model': "N/A",  # Disk model
        'vendor': "N/A",  # Disk vendor
        'aliases': "N/A",  # /dev/disk/by-id/, /dev/disk/by-path/, /dev/disk/by-uuid/, /dev/disk/by-label/
    }
    if not path:
        return info

    # 1. Get the primary block device path from the file path (e.g., /dev/sda2)
    df_cmd = ["df", "--output=source", path]
    df_output = _run_cmd(df_cmd).split('\n')
    primary_device_path = ""
    if len(df_output) > 1:
        primary_device_path = df_output[1].strip()

    # If df didn't return a device, or if the path is already a device path (e.g., /dev/dm-X, /dev/sda)
    if not primary_device_path.startswith('/dev/'):
        primary_device_path = path

    if not primary_device_path.startswith('/dev/'):
        return info  # Not a block device path

    info['device_name'] = os.path.basename(primary_device_path)

    # 2. Get detailed info from lsblk cache using the device name
    lsblk_device_info = get_device_info_from_lsblk(info['device_name'])

    if lsblk_device_info:
        # Physical Disk Name (Parent)
        if lsblk_device_info.get('pkname'):
            info['physical_disk'] = f"/dev/{lsblk_device_info['pkname']}"
        else:  # If it's a top-level device, its own name is the physical disk
            info['physical_disk'] = f"/dev/{lsblk_device_info['name']}"

        info['fstype'] = lsblk_device_info.get('fstype', 'N/A')
        info['disk_uuid'] = lsblk_device_info.get('uuid', 'N/A')
        info['disk_id'] = lsblk_device_info.get('partuuid', 'N/A')  # Use PARTUUID for disk_id
        info['model'] = lsblk_device_info.get('model', 'N/A')
        info['vendor'] = lsblk_device_info.get('vendor', 'N/A')

        # LVM Info - Attempt to get from pre-populated LVM cache
        lvm_info_from_cache = _LVS_CACHE.get(primary_device_path)
        if lvm_info_from_cache:
            info['lvl_name'] = lvm_info_from_cache.get('lv_name', 'N/A')
            info['lvg_name'] = lvm_info_from_cache.get('vg_name', 'N/A')

        # Disk Type (SSD/HDD) - ROTA is 0 for SSD, 1 for HDD
        rota = lsblk_device_info.get('rota')
        if rota is not None:
            info['disk_type'] = "HDD" if rota == "1" else "SSD" if rota == "0" else "N/A"

        # Device Aliases (/dev/disk/by-id, /dev/disk/by-path, /dev/disk/by-uuid, /dev/disk/by-label)
        aliases = []
        if primary_device_path.startswith('/dev/'):  # Only try to get aliases for real devices
            try:
                # Iterate through common alias directories. Order matters for display preference.
                for alias_dir in ['by-id', 'by-path', 'by-uuid', 'by-label']:
                    full_alias_dir = f"/dev/disk/{alias_dir}"
                    if os.path.exists(full_alias_dir):
                        for entry in os.listdir(full_alias_dir):
                            symlink_path = os.path.join(full_alias_dir, entry)
                            if os.path.islink(symlink_path):
                                symlink_target = os.path.realpath(symlink_path)
                                # Check if the symlink target points to our device
                                if symlink_target == primary_device_path:
                                    # Filter by-uuid from ALIASES if it's already shown as top-level UUID
                                    if alias_dir == 'by-uuid' and info['disk_uuid'] == entry:
                                        continue  # Skip by-uuid in aliases if UUID is already displayed explicitly
                                    aliases.append(f"{alias_dir}/{entry}")
            except Exception:
                pass  # Ignore errors listing /dev/disk/by-X
        info['aliases'] = ", ".join(aliases) if aliases else "N/A"

    return info


def get_multipath_detailed_info(device_path):
    """
    Checks if a device is multipath and, if so, lists its underlying paths,
    including the multipath ID. Requires 'multipath -ll' and sudo.
    """
    info = {
        'multipath_id': "N/A",
        'multipath_paths': "N/A"
    }
    if not device_path or not device_path.startswith("/dev/dm-"):
        return info

    multipath_output = _run_cmd(["sudo", "multipath", "-ll", device_path])
    if not multipath_output:
        return info  # Command failed or device is not multipath

    # Capture the multipath alias/ID (first line, before paths)
    id_match = re.match(r'(\S+)\s+\(.*\)', multipath_output)
    if id_match:
        info['multipath_id'] = id_match.group(1)

    # Regex to find paths in 'sdX (X:Y) [status]' format
    paths = re.findall(r'\s+(sd[a-z]+)\s+\(\d+:\d+\)\s+\[(active|ready|failed|enabled|disabled)\]', multipath_output)
    if paths:
        formatted_paths = [f"/dev/{p[0]} ({p[1]})" for p in paths]
        info['multipath_paths'] = ", ".join(formatted_paths)

    return info


def get_total_memory() -> float:
    """Returns the total system memory in MB."""
    mem = psutil.virtual_memory()
    return mem.total / (1024 * 1024)


def get_free_memory() -> float:
    """Returns the free system memory in MB."""
    mem = psutil.virtual_memory()
    return mem.available / (1024 * 1024)


def get_used_memory() -> float:
    """Returns the used system memory in MB."""
    mem = psutil.virtual_memory()
    return mem.used / (1024 * 1024)


def get_process_memory_usage(process: psutil.Process) -> int:
    """Calculates the total memory usage of a process and its children in bytes.

    Args:
        process (psutil.Process): The process to calculate memory usage for.

    Returns:
        int: Total memory usage in bytes.
    """
    try:
        total = process.memory_info().rss
        for child in process.children(recursive=True):
            total += child.memory_info().rss
        return total
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return 0


def get_open_files_enhanced(process: psutil.Process) -> list:
    """
    Retrieves a list of open files for a given process,
    enhanced with mount point, physical disk, and multipath info.
    Filters out irrelevant pseudo-filesystems.
    """
    files = []
    try:
        for file_obj in process.open_files():
            # Filter out common pseudo-files and system files not relevant to disk I/O for security
            if file_obj.path in ["/proc/swaps", "/proc/kmsg", "/proc/mtrr", "/dev/null"] or \
               re.match(r"^/proc/\d+/mountinfo$", file_obj.path) or \
               re.match(r"^/sys/devices/virtual/tty/tty\d+/active$", file_obj.path) or \
               re.match(r"^/proc/\d+/fd/\d+$", file_obj.path):
                continue
            # Filter out /dev/pts/<N> (terminal devices)
            if file_obj.path.startswith("/dev/pts/"):
                continue
            # Filter out /dev/shm/ (POSIX shared memory, which might be in open_files but is IPC)
            if file_obj.path.startswith("/dev/shm/"):
                continue

            file_info = {
                'path': file_obj.path,
                'fd': file_obj.fd,
                'position': file_obj.position,  # type: ignore
                'mode': file_obj.mode,  # type: ignore
                'flags': file_obj.flags,  # type: ignore
            }

            # Get Mount Point and Options
            mount_details = get_mount_info(file_obj.path)
            file_info['mount_point'] = mount_details['mount_point']
            file_info['mount_options'] = mount_details['mount_options']

            # Add disk information (this now uses the new _LSBLK_CACHE_PARSED)
            disk_details = get_disk_info(file_obj.path)
            file_info.update(disk_details)

            # Check multipath only if it's a /dev/dm-X device
            if file_info['device_name'].startswith('dm-'):
                multipath_details = get_multipath_detailed_info(f"/dev/{file_info['device_name']}")
                file_info['multipath_id'] = multipath_details['multipath_id']
                file_info['multipath_paths'] = multipath_details['multipath_paths']
            else:
                file_info['multipath_id'] = "N/A"
                file_info['multipath_paths'] = "N/A"

            files.append(file_info)
        return files
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return []


def get_connections(process: psutil.Process) -> list:
    """
    Retrieves a list of network connections (excluding Unix sockets) for a given process.
    """
    try:
        # Filter out Unix domain sockets here, as they are now not shown in a dedicated IPC section
        # Use socket.AF_UNIX for compatibility across psutil versions
        return [conn for conn in process.connections() if conn.family != socket.AF_UNIX]
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return []


def get_io_counters(process: psutil.Process):
    """
    Retrieves I/O counters for a given process.

    Args:
      process: The psutil.Process object.

    Returns:
      The I/O counters.
    """
    try:
        return process.io_counters()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


def get_loaded_libraries(process: psutil.Process) -> list:
    """
    Retrieves a list of loaded shared libraries (.so files) and non-system Python scripts by a process.
    Filters out common system library paths.
    """
    libraries = []
    try:
        for mmap_entry in process.memory_maps(grouped=False):
            if hasattr(mmap_entry, 'path') and mmap_entry.path:
                path = mmap_entry.path

                # Filter out common system library paths
                if any(path.startswith(prefix) for prefix in COMMON_LIB_PATHS):
                    continue

                # Filter out /proc/ and /dev/ (which are pseudo-filesystems, not real libraries)
                if path.startswith(('/proc/', '/dev/')):
                    continue

                if path.endswith('.so') or path.endswith('.so.0'):
                    libraries.append(path)
                # For Python, it might also load .pyc or .py files. Focus on non-system ones
                elif path.endswith('.py') or path.endswith('.pyc'):
                    # More specific filter for python source/bytecode
                    # Only include if path is not a system python path and not part of the script itself
                    if not any(path.startswith(prefix) for prefix in ['/usr/lib/python', '/usr/local/lib/python']) and \
                       not path.endswith(('memusage_d.py',)):
                        libraries.append(path)

        # Use a set to remove duplicates before returning
        return list(set(libraries))
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return []


def get_executable_hash(process: psutil.Process) -> str:
    """
    Calculates the MD5 hash of the process's executable file.
    """
    exe_path = "N/A"
    try:
        exe_path = process.exe()
        if not exe_path or not os.path.exists(exe_path):
            return "N/A"

        hasher = hashlib.md5()
        with open(exe_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                hasher.update(chunk)
        return hasher.hexdigest()
    except (psutil.NoSuchProcess, psutil.AccessDenied, FileNotFoundError):
        return "N/A"
    except Exception as e:
        # print(f"Error getting hash for {exe_path}: {e}")
        return "N/A"


def get_suspicious_env_vars(process: psutil.Process) -> dict:
    """
    Retrieves suspicious environment variables for a process.
    """
    susp_vars = {}
    SUSPICIOUS_ENV_KEYS = [
        'LD_PRELOAD', 'LD_LIBRARY_PATH', 'LD_AUDIT', 'LD_DEBUG',
        'PYTHONPATH', 'PERL5LIB', 'RUBYLIB',
        'PATH'
    ]
    try:
        environ = process.environ()
        for key, value in environ.items():
            if key in SUSPICIOUS_ENV_KEYS:
                if key == 'PATH' and ('.' in value.split(os.pathsep) or '/tmp' in value.split(os.pathsep)):
                    susp_vars[key] = value
                elif key != 'PATH':
                    susp_vars[key] = value
        return susp_vars
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return {}


def get_security_context(process_pid: int) -> str:
    """
    Retrieves the SELinux or AppArmor security context for a process.
    Requires parsing /proc/<pid>/attr/current or using 'ps -eo pid,label'.
    """
    context = "N/A"
    try:
        if os.path.exists(f"/proc/{process_pid}/attr/current"):
            apparmor_context = _run_cmd(["cat", f"/proc/{process_pid}/attr/current"])
            if apparmor_context and apparmor_context != "kernel":
                context = f"AppArmor: {apparmor_context}"

        if context == "N/A":
            ps_help_output = _run_cmd(["ps", "--help"])
            if "label" in ps_help_output or "LABEL" in ps_help_output:
                ps_label_output = _run_cmd(["ps", "-eo", f"pid,label", "--no-headers"])
                for line in ps_label_output.splitlines():
                    parts = line.strip().split(maxsplit=1)
                    if len(parts) == 2 and parts[0] == str(process_pid):
                        selinux_label = parts[1].strip()
                        if selinux_label and selinux_label != "unconfined_u:unconfined_r:unconfined_t:s0":
                            context = f"SELinux: {selinux_label}"
                            break
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    return context


# MODIFIED: Added displayed_pids parameter
def show_process_tree(process: psutil.Process, level=0, displayed_pids: Optional[set] = None):
    """Displays the process tree with memory usage, open files,
       network connections, and I/O counters, including enhanced file info,
       loaded libraries, executable hash, suspicious environment variables,
       security context, user info, and sudo indicator.
    """
    # Initialize displayed_pids if not provided (for the very first call)
    if displayed_pids is None:
        displayed_pids = set()

    # Mark this process as displayed
    displayed_pids.add(process.pid)

    try:
        nice_value = process.nice()
        color = NICE_COLORS.get(nice_value, RESET_COLOR)

        # Memory usage for current process
        mem_mb = process.memory_info().rss / (1024 * 1024)

        # Get Command Line
        cmdline = " ".join(process.cmdline()) if process.cmdline() else process.name()

        # --- NEW INFORMATION and Consistency ---
        username = process.username()

        # Check for sudo (heuristic)
        sudo_status_str = "N/A"
        try:
            p_uids = process.uids()
            if p_uids.effective == 0 and p_uids.real != 0:
                parent_process = process.parent()
                if parent_process and (parent_process.name() == 'sudo' or 'sudo' in " ".join(parent_process.cmdline())):
                    sudo_status_str = f"{RED_COLOR}Yes (elevated privileges){RESET_COLOR}"
                else:
                    sudo_status_str = "No (setuid/other elevation)"
            elif p_uids.effective == 0 and p_uids.real == 0:
                sudo_status_str = "No (direct root)"
            else:
                sudo_status_str = "No"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            sudo_status_str = "N/A (permission denied)"

        # Get relevant SSH environment variables
        ssh_origin_str = "N/A"
        try:
            environ = process.environ()
            if 'SSH_CONNECTION' in environ:
                ssh_conn_parts = environ['SSH_CONNECTION'].split()
                if len(ssh_conn_parts) >= 2:
                    ssh_origin_str = f"{ssh_conn_parts[0]}:{ssh_conn_parts[1]}"
            elif 'WHOAMI_SSH' in environ:
                whoami_ssh_parts = environ['WHOAMI_SSH'].split('@')
                if len(whoami_ssh_parts) > 1:
                    ssh_origin_str = whoami_ssh_parts[-1]
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            ssh_origin_str = "N/A (permission denied)"

        # Executable Hash
        executable_hash = get_executable_hash(process)

        # Security Context
        security_context = get_security_context(process.pid)

        # Main process line format
        print(f"{'  ' * level}{color}{process.pid} - {process.name()} ({mem_mb:.2f} MB){RESET_COLOR}")

        # --- Always present lines for consistency ---
        print(f"{'  ' * (level + 1)}- User: {username}")
        print(f"{'  ' * (level + 1)}- Sudo Used: {sudo_status_str}")
        print(f"{'  ' * (level + 1)}- SSH Origin: {ssh_origin_str}")
        print(f"{'  ' * (level + 1)}- CMDLINE: {cmdline}")
        print(f"{'  ' * (level + 1)}- Executable MD5: {executable_hash}")
        print(f"{'  ' * (level + 1)}- Security Context: {security_context}")

        # Suspicious Environment Variables
        suspicious_env_vars = get_suspicious_env_vars(process)
        if suspicious_env_vars:
            print(f"{'  ' * (level + 1)}- Suspicious Env Vars:")
            for key, value in suspicious_env_vars.items():
                print(f"{'  ' * (level + 2)}- {key}={value}")
        else:
            print(f"{'  ' * (level + 1)}- Suspicious Env Vars: N/A")

        # Loaded Libraries
        loaded_libraries = get_loaded_libraries(process)
        if loaded_libraries:
            print(f"{'  ' * (level + 1)}- Loaded Libraries (Non-System):")
            for lib in loaded_libraries:
                print(f"{'  ' * (level + 2)}- {lib}")
        else:
            print(f"{'  ' * (level + 1)}- Loaded Libraries (Non-System): N/A")

        # Open files (display enhanced information)
        open_files = get_open_files_enhanced(process)
        if open_files:
            print(f"{'  ' * (level + 1)}- Open Files:")
            seen_files = set()
            for file_info in open_files:
                if file_info['path'] in seen_files:
                    continue
                seen_files.add(file_info['path'])

                extended_info = []
                if file_info.get('mount_point') != "N/A":
                    extended_info.append(f"MOUNT:{file_info['mount_point']}")
                if file_info.get('mount_options') != "N/A":
                    extended_info.append(f"MNT_OPTS:{file_info['mount_options']}")
                if file_info.get('fstype') != "N/A":
                    extended_info.append(f"FSTYPE:{file_info['fstype']}")
                if file_info.get('physical_disk') != "N/A":
                    extended_info.append(f"DISK:{file_info['physical_disk']}")
                if file_info.get('device_name') != "N/A":
                    extended_info.append(f"DEV:{file_info['device_name']}")

                if file_info.get('disk_id') != "N/A":
                    extended_info.append(f"ID:{file_info['disk_id']}")
                if file_info.get('disk_uuid') != "N/A":
                    extended_info.append(f"UUID:{file_info['disk_uuid']}")

                if file_info.get('lvg_name') != "N/A" and file_info.get('lvl_name') != "N/A":
                    extended_info.append(f"LVM:{file_info['lvg_name']}/{file_info['lvl_name']}")
                elif file_info.get('lvg_name') != "N/A":
                    extended_info.append(f"LVM_VG:{file_info['lvg_name']}")
                elif file_info.get('lvl_name') != "N/A":
                    extended_info.append(f"LVM_LV:{file_info['lvl_name']}")

                if file_info.get('disk_type') != "N/A":
                    extended_info.append(f"DISK_TYPE:{file_info['disk_type']}")
                if file_info.get('model') != "N/A":
                    extended_info.append(f"MODEL:{file_info['model']}")
                if file_info.get('vendor') != "N/A":
                    extended_info.append(f"VENDOR:{file_info['vendor']}")
                if file_info.get('multipath_id') != "N/A":
                    extended_info.append(f"MP_ID:{file_info['multipath_id']}")
                if file_info.get('multipath_paths') != "N/A":
                    extended_info.append(f"MP_PATHS:[{file_info['multipath_paths']}]")
                if file_info.get('aliases') != "N/A":
                    extended_info.append(f"ALIASES:[{file_info['aliases']}]")

                extra_details_str = ""
                if extended_info:
                    extra_details_str = f" ({' '.join(extended_info)})"

                print(f"{'  ' * (level + 2)}- {file_info.get('path', 'N/A')}{extra_details_str}")
        else:
            print(f"{'  ' * (level + 1)}- Open Files: N/A")

        # Network connections (display summarized info)
        connections = get_connections(process)
        if connections:
            print(f"{'  ' * (level + 1)}- Network Connections:")
            for conn in connections:
                local_addr_str = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote_addr_str = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"

                print(f"{'  ' * (level + 2)}- Local: {local_addr_str} <-> Remote: {remote_addr_str} (Status: {conn.status})")

                if conn.status == 'ESTABLISHED' and hasattr(conn, 'bytes_sent') and hasattr(conn, 'bytes_recv'):
                    print(f"{'  ' * (level + 3)}- Sent bytes: {conn.bytes_sent}")
                    print(f"{'  ' * (level + 3)}- Received bytes: {conn.bytes_recv}")
        else:
            print(f"{'  ' * (level + 1)}- Network Connections: N/A")

        # I/O counters
        io_counters = get_io_counters(process)
        if io_counters:
            print(f"{'  ' * (level + 1)}- Read bytes: {io_counters.read_bytes}")
            print(f"{'  ' * (level + 1)}- Write bytes: {io_counters.write_bytes}")
        else:
            print(f"{'  ' * (level + 1)}- I/O Counters: N/A")

        # Children processes
        for child in process.children():
            # Pass displayed_pids to recursive calls to avoid re-printing already visited processes
            show_process_tree(child, level + 1, displayed_pids=displayed_pids)

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        # For inaccessible processes, still show PID and an error note,
        # and sub-information can be "N/A"
        print(f"{'  ' * level}{color}{process.pid} - {process.name()} (Error: Access Denied/Process Vanished){RESET_COLOR}")  # type: ignore
        print(f"{'  ' * (level + 1)}- User: N/A")
        print(f"{'  ' * (level + 1)}- Sudo Used: N/A")
        print(f"{'  ' * (level + 1)}- SSH Origin: N/A")
        print(f"{'  ' * (level + 1)}- CMDLINE: N/A")
        print(f"{'  ' * (level + 1)}- Executable MD5: N/A")
        print(f"{'  ' * (level + 1)}- Security Context: N/A")
        print(f"{'  ' * (level + 1)}- Suspicious Env Vars: N/A")
        print(f"{'  ' * (level + 1)}- Loaded Libraries (Non-System): N/A")
        print(f"{'  ' * (level + 1)}- Open Files: N/A")
        print(f"{'  ' * (level + 1)}- Network Connections: N/A")
        print(f"{'  ' * (level + 1)}- I/O Counters: N/A")


# Class to duplicate output (console and log file)
class Tee:
    """A class to redirect stdout to both console and a file."""
    def __init__(self, name, mode):
        """Initializes the Tee object to write to a file and stdout."""
        self.file = open(name, mode, encoding='utf-8')
        self.stdout = sys.stdout
        sys.stdout = self

    def write(self, data):
        """Writes data to both the file and the original stdout, if not None."""
        self.file.write(data)  # type: ignore
        if self.stdout is not None:
            self.stdout.write(data)

    def flush(self):
        """Flushes buffered data for both the file and the original stdout, if not None."""
        self.file.flush()  # type: ignore
        if self.stdout is not None:
            self.stdout.flush()

    def close(self):
        """Restores original stdout and closes the file."""
        if self.stdout is not None:
            sys.stdout = self.stdout
            self.stdout = None
        if self.file is not None:
            self.file.close()
            self.file = None


# Function to convert the log file to HTML
def convert_log_to_html(log_filepath, html_filepath):
    """
    Converts a plain text log file (with ANSI colors) into an HTML file,
    preserving formatting and colors.
    """
    try:
        with open(log_filepath, 'r', encoding='utf-8') as log_file:
            log_content = log_file.read()

        # Replaces ANSI codes with HTML tags with CSS style
        for ansi_code, html_tag in ANSI_COLOR_MAP.items():
            log_content = log_content.replace(ansi_code, html_tag)

        # Ensures all opened span tags are closed at the end of the content
        # This is a simple heuristic; complex nested ANSI might require a more robust parser.
        log_content = log_content.replace(RESET_COLOR, '</span>')
        # Add any missing closing spans if tags are left unclosed due to content ending
        open_spans_count = log_content.count('<span')
        close_spans_count = log_content.count('</span>')
        if open_spans_count > close_spans_count:
            log_content += '</span>' * (open_spans_count - close_spans_count)

        # HTML needs a basic header and body
        html_template = f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>Memusage Report</title>
    <style>
        body {{ background-color: #1e1e1e; color: #d4d4d4; font-family: 'Cascadia Code', 'Consolas', monospace; font-size: 14px; line-height: 1.4; }}
        pre {{ white-space: pre-wrap; word-wrap: break-word; }}
        /* Styles for mapped colors */
        span[style*="color: red;"] {{ color: red; }}
        span[style*="color: yellow;"] {{ color: yellow; }}
        span[style*="color: green;"] {{ color: limegreen; }}
        span[style*="color: dodgerblue;"] {{ color: dodgerblue; }}
        span[style*="color: grey;"] {{ color: grey; }}
    </style>
</head>
<body>
    <pre><code>
{log_content}
    </code></pre>
</body>
</html>
"""
        with open(html_filepath, 'w', encoding='utf-8') as html_file:
            html_file.write(html_template)

        print(f"\n--- HTML report generated at: {html_filepath} ---")

    except FileNotFoundError:
        print(f"Error: Log file not found at {log_filepath}")
    except Exception as e:
        print(f"Error converting log to HTML: {e}")


if __name__ == '__main__':
    # Generate timestamp for the log file name in international standard
    # Ex: memusage-2025-06-27_13-30-00.log
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    log_filename = f"memusage-{timestamp}.log"
    log_dir = "logs"

    # Create the logs directory if it doesn't exist
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    full_log_path = os.path.join(log_dir, log_filename)

    # Start output redirection
    original_stdout = sys.stdout
    log_tee = None
    try:
        log_tee = Tee(full_log_path, "w")
        print(f"--- Output being saved to: {full_log_path} ---")

        print("--- Memory and Resource Usage Report ---")
        print(f"Memory Threshold (MB): {MEMORY_THRESHOLD_MB}")
        print(f"Open Files Threshold: {OPEN_FILES_THRESHOLD}")
        print("---------------------------------------------")

        # Print Priority Color Table
        print("\nPriority Color Table:")
        for nice_value, color in NICE_COLORS.items():
            print(f"{color}Priority: {nice_value}\tColor: {color}{RESET_COLOR}")

        print("\nTotal system memory:", get_total_memory(), "MB")
        print("Free system memory:", get_free_memory(), "MB")
        print("Used system memory:", get_used_memory(), "MB")

        # Populate lsblk and LVM caches once at startup
        _populate_lsblk_cache()
        _populate_lvm_cache()

        print("\nMemory usage of each process:")
        print("PID - Process Name (Memory Usage)")
        print("-----------------------------------")
        print("Note: 'Sudo Used' is a heuristic based on UIDs and parent process. 'SSH Origin' is based on environment variables.")
        print("-----------------------------------")

        # Get all PIDs to iterate through, ensuring all process trees are displayed
        all_pids = set()  # Use a set to avoid duplicates and improve lookup speed
        for p_obj in psutil.process_iter(['pid']):  # Only fetch PID for efficiency
            all_pids.add(p_obj.pid)

        total_mem = 0
        # Calculate total memory of all processes
        for pid in all_pids:
            try:
                p_obj = psutil.Process(pid)
                total_mem += p_obj.memory_info().rss
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        print(f"\nTotal memory process tree: {total_mem / (1024 * 1024):.2f} MB")

        # Iterate over all PIDs to find top-level processes
        # A process is "top-level" if its parent no longer exists or is PID 1 (init)
        displayed_pids = set()  # To prevent displaying the same tree multiple times

        for pid in sorted(list(all_pids)):  # Sort PIDs for consistent output
            if pid in displayed_pids:
                continue

            try:
                p = psutil.Process(pid)
                # Check if it's a top-level process to start a new tree print
                # This condition covers init (PID 1) and orphan processes
                # For non-init processes, check if parent is not in our list of all PIDs
                # (meaning parent either doesn't exist or we haven't processed it yet as a parent of this specific sub-tree start)
                # Or if parent is init (PID 1), which is always a tree root.
                if p.ppid() == 0 or p.ppid() == 1 or p.ppid() not in all_pids:
                    # We print the tree and collect all PIDs printed in this call
                    show_process_tree(p, displayed_pids=displayed_pids)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # If we can't access a process to check its parent, it might be gone.
                # Just skip it if it's not already displayed.
                pass

    except Exception as e:
        print(f"An unexpected error occurred during report generation: {e}")

    finally:
        # Ensures original stdout is restored and log file is closed
        if log_tee is not None:
            log_tee.close()
        # Fallback to ensure sys.stdout is always restored
        if sys.stdout != original_stdout and not isinstance(sys.stdout, Tee):
            sys.stdout = original_stdout

        # Call HTML conversion after log generation
        html_filename = log_filename.replace(".log", ".html")
        full_html_path = os.path.join(log_dir, html_filename)
        convert_log_to_html(full_log_path, full_html_path)

    print("\n--- End of Report ---")
    print("\nNotes:")
    print(" - Accessing some information - ")
    print("e.g., open files of other users, multipath, executable hash, env vars, security context")
    print("may require 'sudo' privileges.")
    print(" - Read bytes and Write bytes values are cumulative since process start.")
    print(" - 'N/A' means information could not be obtained or is not applicable.")
    print(" - This tool generates human-readable text output. For structured data (JSON/HTML), a different output mode would be required.")
    print("\n\n--- Understanding Disk Identifiers in Data Centers ---")
    print(" - For enterprise storage (SAN/NAS), standard device names like /dev/sda are volatile.")
    print(" - Persistent identifiers like UUID and aliases are crucial:")
    print("    - UUID: Universal Unique Identifier of the filesystem on a partition/volume.")
    print("      Often used in /etc/fstab for consistent mounting.")
    print("    - ID (PARTUUID): Unique ID of the partition itself (if applicable).")
    print("      Distinguishes partitions on the same disk when UUIDs might conflict (e.g., after cloning).")
    print("    - ALIASES: Alternate, persistent paths to the device in /dev/disk/ by-id, by-path, by-uuid, by-label.")
    print("      - by-id/: Hardware-based IDs (manufacturer, model, serial). Highly stable.")
    print("      - by-path/: Physical path through hardware (PCI slot, HBA port, SCSI target).")
    print("          can reveal the HBA adapter (e.g., pci-0000:00:10.0), Fibre Channel/iSCSI port,")
    print("          and LUN ID from the storage array. This allows correlation with SAN zoning/masking.")
    print("          It helps identify the physical location of the LUN within the storage infrastructure.")
    print("      - by-uuid/: Symlinks using the filesystem UUID (duplicate of the UUID field, but listed here for completeness of aliases).")
    print("      - by-label/: Symlinks using filesystem labels defined by the user.")
    print(" - LVM (Logical Volume Management): Indicates if a file resides on a logical volume.")
    print("    LVM allows flexible storage management over physical volumes.")
    print(" - Disk Type (SSD/HDD), Model, Vendor: Provide insights into disk performance characteristics.")
    print(" - Multipath (MP_ID, MP_PATHS): Shows if multiple paths exist to the same LUN for redundancy/performance.")
    print("    Common in SAN environments to avoid single points of failure.")
    print(" - Command and path limits have been applied for better readability.")
