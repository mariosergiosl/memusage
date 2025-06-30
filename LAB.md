# Memusage Lab: Troubleshooting a High I/O Scenario

## 1. Objective

This lab simulates a common real-world performance issue where a critical application (in this case, a DB2 database running in a container) is experiencing slowdowns. The root cause is a "rogue" process generating a heavy, unpredictable disk I/O load on one of the available storage devices.

**Your mission is to act as a system or support engineer.** You will use the `memusage.py` diagnostic script to analyze the environment, identify the process causing the disk bottleneck, and pinpoint the specific underlying block device that is being impacted.

This exercise is designed to teach and reinforce the critical skill of correlating process activity with specific hardware resource utilization.

## 2. Prerequisites

* A Linux host system with **Podman** installed.
* **Sudo** (administrator) privileges.
* An active internet connection.

## 3. Environment Setup

The setup is divided into two parts: commands executed on your **Host System** to prepare the infrastructure, and commands executed **Inside the Container** to run the simulation and analysis.

### Part 1: Host System Preparation

These commands prepare the virtual disks and launch the DB2 container.

```bash
# 1. Create a dedicated directory for our virtual disks.
mkdir /opt/ibmdb2_disk
cd /opt/ibmdb2_disk

# 2. Create two 10GB sparse files to act as our virtual disk images.
fallocate -l 10G disk1.img
fallocate -l 10G disk2.img

# 3. Associate these image files with loopback block devices.
# We now have two virtual disks: /dev/loop0 and /dev/loop1.
sudo losetup /dev/loop0 disk1.img
sudo losetup /dev/loop1 disk2.img

# 4. Format both virtual disks with an ext4 filesystem.
# This step is done on the host to simplify the container setup.
sudo mkfs.ext4 /dev/loop0
sudo mkfs.ext4 /dev/loop1

# 5. Run the DB2 container.
# We pass both loop devices into the container so it can see and use them.
# The --dns flag is included for environments that may require a public DNS resolver.
podman run -itd --name mydb2 --privileged=true --dns=8.8.8.8 -p 50000:50000 -e LICENSE=accept -e DB2INST1_PASSWORD=db2senha -e DBNAME=testdb -v /opt/db2_database:/database:Z --device=/dev/loop0 --device=/dev/loop1 ibmcom/db2

# 6. Get an interactive shell inside the running container for the next steps.
podman exec -it mydb2 /bin/bash
```

### Part 2: Container Setup & Test Execution

All subsequent commands are to be run inside the container's shell.

```bash
# 1. Create mount points for our two virtual disks.
mkdir -p /mnt/test_disk
mkdir -p /mnt/test_disk1

# 2. Mount the devices.
mount /dev/loop0 /mnt/test_disk
mount /dev/loop1 /mnt/test_disk1

# 3. Prepare the environment for installing tools.
# This may be necessary if the container's default repositories are not working.
# mv /etc/yum.repos.d/centos.repo.disabled /etc/yum.repos.d/centos.repo
# yum clean all

# 4. Install necessary tools: wget for downloading, and python3/pip for the script.
yum install -y wget python3 python3-pip

# 5. Install the psutil library, a dependency for memusage.py.
pip3 install psutil

# 6. Download the memusage.py script.
mkdir -p /opt/memusage
cd /opt/memusage
wget -O memusage.py [https://raw.githubusercontent.com/mariosergiosl/memusage/main/memusage.py](https://raw.githubusercontent.com/mariosergiosl/memusage/main/memusage.py)

# 7. Start the I/O load generator in the background.
# This loop will randomly pick one of the two disks and write 512MB of data,
# then pause for 15 seconds before repeating. The process is silent.
# The PID of the background loop is saved to a file for easy cleanup later.
TARGETS=(/mnt/test_disk /mnt/test_disk1); while true; do RANDOM_INDEX=$((RANDOM % 2)); TARGET_DIR=${TARGETS[$RANDOM_INDEX]}; dd if=/dev/urandom of="${TARGET_DIR}/my_test_file" bs=1M count=512 2>/dev/null; sleep 15; done & echo $! > /tmp/dd_loop.pid

# 8. Run the diagnostic script to analyze the system while the load is active.
# This is where you will perform your analysis.
python3 /opt/memusage/memusage.py
```

## 4. The Challenge: What to Look For

After running memusage.py, your goal is to inspect its output to find:

1. The Process: Look for a dd process.
2. The I/O Load: Check the Write bytes for that process. It should be a very large number.
3. The Root Cause (The Flag!): Examine the Open Files section for the dd process. It will show you the exact file path being written to and, most importantly, the underlying device in the format (FSTYPE:... DEV:loopX ...). The name of that device (loop0 or loop1) is the answer to the mystery.

### Stuck?

If you are having trouble identifying which disk is being used, you can use a "louder" version of the I/O generator loop that explicitly prints its target to the screen before each run. This tells you the answer directly, but it's a great way to verify that the lab is working as expected.

```bash
# This version includes an 'echo' command to announce which disk it's writing to.
TARGETS=(/mnt/test_disk /mnt/test_disk1); while true; do RANDOM_INDEX=$((RANDOM % 2)); TARGET_DIR=${TARGETS[$RANDOM_INDEX]}; echo "Generating I/O on: ${TARGET_DIR}"; dd if=/dev/urandom of="${TARGET_DIR}/my_test_file" bs=1M count=512 status=progress 2>/dev/null; sleep 15; done & echo $! > /tmp/dd_loop.pid
```

## Stopping and Cleaning Up

Once you have completed your analysis, you can stop the background I/O generator and clean up the environment.

### Inside the Container

```bash
# Use the saved PID to stop the background loop and its dd child process.
kill -9 $(cat /tmp/dd_loop.pid)
```

### On the Host System

```bash
# Stop and remove the container.
podman stop mydb2
podman rm mydb2

# Detach the loopback devices.
sudo losetup -d /dev/loop0
sudo losetup -d /dev/loop1

# You can now safely remove the /opt/ibmdb2_disk directory if desired.
# sudo rm -rf /opt/ibmdb2_disk
```


