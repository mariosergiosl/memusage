#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright (c) Mario Luz [2024].
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 2 of the License, or (at your
# option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

"""
memusage - a tool to display memory usage of processes on a Linux system.
"""

import psutil

# Colors for process priority
NICE_COLORS = {
    -20: "\033[91m",  # Red
    -15: "\033[91m",  # Red
    -10: "\033[93m",  # Yellow
     -5: "\033[93m",  # Yellow
      0: "\033[92m",  # Green
      5: "\033[92m",  # Green
     10: "\033[94m",  # Blue
     15: "\033[94m",  # Blue
     19: "\033[90m",  # Grey
}

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
        print(f"Error accessing process {process.pid}")  # Removido 'as e'
        return 0

def show_process_memory_usage(process: psutil.Process, level=0):
    """Displays the memory usage of a process and its children recursively.

    Args:
        process (psutil.Process): The process to display memory usage for.
        level (int, optional): The indentation level. Defaults to 0.
    """

    try:
        nice_value = process.nice()
        color = NICE_COLORS.get(nice_value, "\033[0m")  # Default color if not found
        print(f"  " * level + f"{color}{process.pid} - {process.name()} ({process.memory_info().rss / (1024 * 1024):.2f} MB)\033[0m")
        for child in process.children():
            show_process_memory_usage(child, level + 1)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        print("  " * level + "Error accessing process {process.pid}")


if __name__ == '__main__':
    main_process = psutil.Process(1)

    print("\nPriority Color Table:")
    for nice_value, color in NICE_COLORS.items():
        print(f"{color}Priority: {nice_value}\tColor: {color}{color}\033[0m")

    print("Total system memory:", get_total_memory(), "MB")
    print("Free system memory:", get_free_memory(), "MB")
    print("Used system memory:", get_used_memory(), "MB")

    print("\nTotal memory usage of the process tree:", get_process_memory_usage(main_process) / (1024 * 1024), "MB")

    print("\nMemory usage of each process:")
    print("PID - Process Name (Memory Usage)")
    show_process_memory_usage(main_process)
