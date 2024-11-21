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
    -9: "\033[93m",  # Yellow
    -8: "\033[92m",  # Green
    -7: "\033[92m",  # Green
    -6: "\033[92m",  # Green
    -5: "\033[92m",  # Green
    -4: "\033[92m",  # Green
    -3: "\033[92m",  # Green
    -2: "\033[92m",  # Green
    -1: "\033[92m",  # Green
    0: "\033[92m",  # Green
    1: "\033[92m",  # Green
    2: "\033[92m",  # Green
    3: "\033[92m",  # Green
    4: "\033[92m",  # Green
    5: "\033[92m",  # Green
    6: "\033[94m",  # Blue
    7: "\033[94m",  # Blue
    8: "\033[94m",  # Blue
    9: "\033[94m",  # Blue
    10: "\033[94m",  # Blue
    11: "\033[94m",  # Blue
    12: "\033[94m",  # Blue
    13: "\033[94m",  # Blue
    14: "\033[94m",  # Blue
    15: "\033[94m",  # Blue
    16: "\033[90m",  # Grey
    17: "\033[90m",  # Grey
    18: "\033[90m",  # Grey
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
        print(f"Error accessing process {process.pid}")
        return 0


def get_open_files(process: psutil.Process) -> list:
    """
    Retrieves a list of open files for a given process.

    Args:
      process: The psutil.Process object.

    Returns:
      A list of open files.
    """
    try:
        return process.open_files()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return []


def get_connections(process: psutil.Process) -> list:
    """
    Retrieves a list of network connections for a given process.

    Args:
      process: The psutil.Process object.

    Returns:
      A list of network connections.
    """
    try:
        return process.connections()
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


def show_process_tree(process: psutil.Process, level=0):
    """Displays the process tree with memory usage, open files,
       network connections, and I/O counters.
    """
    try:
        nice_value = process.nice()
        color = NICE_COLORS.get(nice_value, "\033[0m")
        # Usando f-strings aninhadas para interpolar as variáveis 'color' e 'level'
        print(f"  " * level + f"{color}{process.pid} - {process.name()} ({process.memory_info().rss / (1024 * 1024):.2f} MB)\033[0m")

        # Open files (removendo duplicatas)
        open_files = list(set(get_open_files(process)))
        if open_files:
            for file in open_files:
                print(f"{'  ' * (level + 1)}- {file.path}")

        # Network connections (exibindo informações resumidas)
        connections = get_connections(process)
        if connections:
            for conn in connections:
                # Indentação e títulos para informações de rede
                print(f"{'  ' * (level + 1)}  - Local Address: {conn.laddr}")
                print(f"{'  ' * (level + 1)}  - Remote Address: {conn.raddr}")
                print(f"{'  ' * (level + 1)}  - Status: {conn.status}")
                # Exibe bytes enviados e recebidos apenas para conexões estabelecidas
                if conn.status == 'ESTABLISHED' and hasattr(conn, 'sent_bytes') and hasattr(conn, 'recv_bytes'):
                    print(f"{'  ' * (level + 2)}- Sent bytes: {conn.sent_bytes}")
                    print(f"{'  ' * (level + 2)}- Received bytes: {conn.recv_bytes}")

        # I/O counters
        io_counters = get_io_counters(process)
        if io_counters:
            print(f"{'  ' * (level + 1)}- Read bytes: {io_counters.read_bytes}")
            print(f"{'  ' * (level + 1)}- Write bytes: {io_counters.write_bytes}")

        for child in process.children():
            show_process_tree(child, level + 1)

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        # Usando string literal, pois não há interpolação de variáveis
        print("  " * level + "Error accessing process {process.pid}")


if __name__ == '__main__':
    main_process = psutil.Process(1)

    # Print Priority Color Table
    print("\nPriority Color Table:")
    for nice_value, color in NICE_COLORS.items():
        # Using f-string to interpolate color variable and print colored output
        print(f"{color}Priority: {nice_value}\tColor: {color}{color}\033[0m")  

    print("Total system memory:", get_total_memory(), "MB")
    print("Free system memory:", get_free_memory(), "MB")
    print("Used system memory:", get_used_memory(), "MB")

    print("\nTotal mem. process tree:", get_process_memory_usage(main_process) / (1024 * 1024), "MB")

    print("\nMemory usage of each process:")
    print("PID - Process Name (Memory Usage)")
    show_process_tree(main_process)

    # Mensagem sobre valores cumulativos de E/S
    print("\nRead bytes and Write bytes - These values are cumulative.")
