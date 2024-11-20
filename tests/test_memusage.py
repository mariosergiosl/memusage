# tests/test_memusage.py

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
        memusage.show_process_memory_usage(process)
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess) as e:
        assert False, f"show_process_memory_usage raised an exception: {e}"
