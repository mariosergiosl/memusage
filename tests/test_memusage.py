#!/usr/bin/python3
# -*- coding: utf-8 -*-

# Copyright (C) 2024 Mario Luz

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# tests/test_memusage.py

"""
Test suite for the memusage module.
"""

import sys
import os
import psutil
import memusage

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))


def test_get_total_memory():
    """Tests the get_total_memory function."""
    total_memory = memusage.get_total_memory()
    assert total_memory > 0, "Total memory should be greater than zero"


def test_get_free_memory():
    """Tests the get_free_memory function."""
    free_memory = memusage.get_free_memory()
    assert free_memory > 0, "Free memory should be greater than zero"


def test_get_used_memory():
    """Tests the get_used_memory function."""
    used_memory = memusage.get_used_memory()
    assert used_memory > 0, "Used memory should be greater than zero"


def test_get_process_memory_usage():
    """Tests the get_process_memory_usage function."""
    process = memusage.psutil.Process()
    memory_usage = memusage.get_process_memory_usage(process)
    assert memory_usage > 0, "Process memory usage should be greater than zero"


def test_show_process_memory_usage():
    """Tests the show_process_memory_usage function."""
    # This function prints to the console, so we can't directly assert its output.
    # Instead, we can check if it runs without errors.
    try:
        process = memusage.psutil.Process()
        memusage.show_process_tree(process)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        assert False, f"show_process_memory_usage raised an exception: {e}"
