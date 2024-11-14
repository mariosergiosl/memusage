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

import psutil

def get_total_memory() -> float:
    """Returns the total system memory in MB.

    Returns:
        float: Total system memory in MB.
    """
    mem = psutil.virtual_memory()
    return mem.total / (1024 * 1024)

def get_free_memory() -> float:
    """Returns the free system memory in MB.

    Returns:
        float: Free system memory in MB.
    """
    mem = psutil.virtual_memory()
    return mem.available / (1024 * 1024)

def get_used_memory() -> float:
    """Returns the used system memory in MB.

    Returns:
        float: Used system memory in MB.
    """
    mem = psutil.virtual_memory()
    return mem.used / (1024 * 1024)

def get_process_memory_usage(process: psutil.Process) -> int:
    """Calculates the total memory usage of a process and its children in bytes.

    Args:
        process (psutil.Process): The process to calculate memory usage for.

    Returns:
        int: Total memory usage in bytes.
    """
    total = process.memory_info().rss
    for child in process.children(recursive=True):
        total += child.memory_info().rss
    return total

def show_process_memory_usage(process: psutil.Process, level=0):
    """Displays the memory usage of a process and its children recursively.

    Args:
        process (psutil.Process): The process to display memory usage for.
        level (int, optional): The indentation level. Defaults to 0.
    """
    print("  " * level + f"{process.pid} - {process.name()} ({process.memory_info().rss / (1024 * 1024):.2f} MB)")
    for child in process.children():
        show_process_memory_usage(child, level + 1)

if __name__ == '__main__':
    main_process = psutil.Process(1)

    print("Total system memory:", get_total_memory(), "MB")
    print("Free system memory:", get_free_memory(), "MB")
    print("Used system memory:", get_used_memory(), "MB")

    print("\nTotal memory usage of the process tree:", get_process_memory_usage(main_process) / (1024 * 1024), "MB")

    print("\nMemory usage of each process:")
    print("PID - Process Name (Memory Usage)")
    show_process_memory_usage(main_process)
