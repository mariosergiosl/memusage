# Memory Usage Tool

This tool displays the memory usage of processes on a Linux system.

## Features

* Shows total system memory, free memory, and used memory.
* Displays process information in a hierarchical tree format.
* Calculates the total memory usage of a process and its children.
* Shows open files for each process.
* Displays network connections for each process, including:
    * Local and remote addresses
    * Status
    * Sent and received bytes (for established connections)
* Shows I/O activity for each process, including read and write bytes.
* Color-coded output based on process priority.

## Installation

For detailed installation instructions, please see the [INSTALL.md](INSTALL.md) file.


## Running code (Not Installation)

1.  Install the `psutil` package: `pip install psutil`
2.  Save the `memory_usage.py` script to your system.

## Usage - Running code (Not Installation)

Run the script from the command line:

```bash
python3 memory_usage.py
```

## Usage - if installation 

Run the script from the command line:

```bash
memusage
```

## Output
The output will show:

* Total system memory
* Free system memory
* Used system memory
* Total memory usage of the process tree
* Memory usage of each process with its PID, name, and memory consumption, color-coded by priority:
* For each process:
    * PID
    * Process name
    * Memory usage
    * Open files
    * Network connections
    * I/O activity (read and write bytes)
    * Note: The Read bytes and Write bytes values are cumulative.

* The output is color-coded based on process priority:

| Priority   | Color     |  Nice Value  |
|------------|-----------|--------------|
| High       | Red       | -20          |
|            |           | -15          | 
|            |           | -10          |
| Medium     | Yellow    | -5           |
|            |           | 0            |
|            |           | 5            |
| Low        | Green     | 10           |
|            |           | 15           |
|            |           | 19           |

## Testing Color-Coded Output

To test the color-coded output, you can run processes with different priorities using the `nice` command.

**Examples:**

* **High priority:**
```bash
  nice -n -20 yes > /dev/null &
```
* **Medium priority:**
```bash
  nice -n -20 yes > /dev/null &
```
* **Low priority:**
```bash
  nice -n -20 yes > /dev/null &
```
After running these commands, execute memusage again and observe the color-coded output.


```bash
Priority Color Table:
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
Total system memory: 7877.39453125 MB
Free system memory: 7270.83203125 MB
Used system memory: 606.5625 MB

Total mem. process tree: 577.58203125 MB

Memory usage of each process:
PID - Process Name (Memory Usage)
1 - systemd (13.69 MB)
  - /proc/swaps
  - /proc/1/mountinfo
  - Read bytes: 247741952
  - Write bytes: 164270080
  643 - systemd-journald (9.38 MB)
    - /proc/sys/kernel/hostname
    - /run/log/journal/24a550029dff4a95994d4266dd0763e7/system.journal
    - Read bytes: 225280
    - Write bytes: 0
  669 - systemd-udevd (12.88 MB)
    - /etc/udev/hwdb.bin
    - Read bytes: 26705408
    - Write bytes: 0
  747 - haveged (4.99 MB)
    - Read bytes: 135168
    - Write bytes: 0
  864 - auditd (3.76 MB)
    - /var/log/audit/audit.log
    - Read bytes: 4096
    - Write bytes: 393216
  871 - avahi-daemon (3.25 MB)
      - Local Address: addr(ip='0.0.0.0', port=51517)
      - Remote Address: ()
      - Status: NONE
      - Local Address: addr(ip='::', port=5353)
      - Remote Address: ()
      - Status: NONE
      - Local Address: addr(ip='0.0.0.0', port=5353)
      - Remote Address: ()
      - Status: NONE
      - Local Address: addr(ip='::', port=37507)
      - Remote Address: ()
      - Status: NONE
    - Read bytes: 565248
    - Write bytes: 0
  872 - dbus-daemon (5.43 MB)
    - Read bytes: 1236992
    - Write bytes: 0
  878 - irqbalance (5.25 MB)
    - Read bytes: 323584
    - Write bytes: 0
  884 - polkitd (7.70 MB)
    - Read bytes: 3407872
    - Write bytes: 0
  889 - VGAuthService (10.38 MB)
    - /var/log/vmware-vgauthsvc.log.0
    - /var/log/vmware-vgauthsvc.log.0
    - Read bytes: 3911680
    - Write bytes: 8192
  898 - wickedd-auto4 (5.75 MB)
    - Read bytes: 462848
    - Write bytes: 0
  899 - wickedd-dhcp4 (6.12 MB)
      - Local Address: addr(ip='0.0.0.0', port=68)
      - Remote Address: ()
      - Status: NONE
    - Read bytes: 1843200
    - Write bytes: 3788800
  900 - wickedd-dhcp6 (6.12 MB)
    - Read bytes: 454656
    - Write bytes: 0
  910 - vmware-vmblock-fuse (3.39 MB)
    - Read bytes: 0
    - Write bytes: 0
  926 - nscd (4.41 MB)
    - /var/lib/nscd/services
    - /var/lib/nscd/services
    - /var/lib/nscd/netgroup
    - /var/lib/nscd/passwd
    - /var/lib/nscd/netgroup
    - /var/lib/nscd/passwd
    - /var/lib/nscd/group
    - /var/lib/nscd/group
    - Read bytes: 73728
    - Write bytes: 1200128
  997 - systemd-logind (8.50 MB)
    - /sys/devices/virtual/tty/tty0/active
    - Read bytes: 282624
    - Write bytes: 0
  999 - wickedd (6.25 MB)
    - Read bytes: 380928
    - Write bytes: 1798144
  1000 - ModemManager (13.40 MB)
    - Read bytes: 10084352
    - Write bytes: 0
  1004 - vmtoolsd (10.98 MB)
    - /var/log/vmware-vmsvc-root.log
    - /run/vmtoolsd.pid
    - Read bytes: 2834432
    - Write bytes: 69632
  1007 - wickedd-nanny (6.38 MB)
    - Read bytes: 69632
    - Write bytes: 0
  1488 - cupsd (9.75 MB)
      - Local Address: addr(ip='127.0.0.1', port=631)
      - Remote Address: ()
      - Status: LISTEN
      - Local Address: addr(ip='::1', port=631)
      - Remote Address: ()
      - Status: LISTEN
    - Read bytes: 6889472
    - Write bytes: 4096
  1498 - rsyslogd (7.12 MB)
    - /var/log/messages
    - /var/log/warn
    - /proc/kmsg
    - Read bytes: 1036288
    - Write bytes: 1093632
  1503 - sshd (9.12 MB)
      - Local Address: addr(ip='0.0.0.0', port=22)
      - Remote Address: ()
      - Status: LISTEN
      - Local Address: addr(ip='::', port=22)
      - Remote Address: ()
      - Status: LISTEN
    - Read bytes: 0
    - Write bytes: 0
    1808 - sshd (10.62 MB)
      - /proc/sys/crypto/fips_enabled
        - Local Address: addr(ip='192.168.111.128', port=22)
        - Remote Address: addr(ip='192.168.111.1', port=11923)
        - Status: ESTABLISHED
      - Read bytes: 36864
      - Write bytes: 8192
      1824 - sshd (6.64 MB)
        - /proc/sys/crypto/fips_enabled
          - Local Address: addr(ip='::1', port=6010)
          - Remote Address: ()
          - Status: LISTEN
          - Local Address: addr(ip='127.0.0.1', port=6010)
          - Remote Address: ()
          - Status: LISTEN
          - Local Address: addr(ip='192.168.111.128', port=22)
          - Remote Address: addr(ip='192.168.111.1', port=11923)
          - Status: ESTABLISHED
        - Read bytes: 16384
        - Write bytes: 0
        1825 - bash (5.38 MB)
          - Read bytes: 204935168
          - Write bytes: 72761344
          22008 - python3 (12.00 MB)
            - Read bytes: 0
            - Write bytes: 0
    1811 - sshd (10.62 MB)
      - /proc/sys/crypto/fips_enabled
        - Local Address: addr(ip='192.168.111.128', port=22)
        - Remote Address: addr(ip='192.168.111.1', port=11925)
        - Status: ESTABLISHED
      - Read bytes: 638976
      - Write bytes: 0
      1839 - sshd (6.38 MB)
        - /proc/sys/crypto/fips_enabled
          - Local Address: addr(ip='192.168.111.128', port=22)
          - Remote Address: addr(ip='192.168.111.1', port=11925)
          - Status: ESTABLISHED
        - Read bytes: 16384
        - Write bytes: 0
        1874 - sftp-server (4.25 MB)
          - /proc/sys/crypto/fips_enabled
          - Read bytes: 864256
          - Write bytes: 0
  1505 - chronyd (5.48 MB)
      - Local Address: addr(ip='::1', port=323)
      - Remote Address: ()
      - Status: NONE
      - Local Address: addr(ip='127.0.0.1', port=323)
      - Remote Address: ()
      - Status: NONE
    - Read bytes: 0
    - Write bytes: 798720
  1621 - lightdm (8.36 MB)
    - /var/log/lightdm/lightdm.log
    - Read bytes: 26759168
    - Write bytes: 20480
    1627 - X (83.46 MB)
      - /var/log/Xorg.0.log
      - /proc/mtrr
      - /proc/mtrr
      - /var/log/lightdm/x-0.log
      - /var/log/lightdm/x-0.log
      - Read bytes: 156753920
      - Write bytes: 98304
    1742 - lightdm (13.52 MB)
      - /var/log/lightdm/seat0-greeter.log
      - Read bytes: 1445888
      - Write bytes: 53248
      1765 - lightdm-gtk-greeter (110.25 MB)
        - /var/log/lightdm/seat0-greeter.log
        - Read bytes: 32845824
        - Write bytes: 4739072
    1803 - lightdm (7.62 MB)
      - Read bytes: 0
      - Write bytes: 0
  1629 - accounts-daemon (8.89 MB)
    - Read bytes: 253952
    - Write bytes: 0
  1630 - agetty (2.38 MB)
    - Read bytes: 163840
    - Write bytes: 4096
  1707 - master (5.03 MB)
    - /var/spool/postfix/pid/master.pid
    - /var/lib/postfix/master.lock
      - Local Address: addr(ip='::1', port=25)
      - Remote Address: ()
      - Status: LISTEN
      - Local Address: addr(ip='127.0.0.1', port=25)
      - Remote Address: ()
      - Status: LISTEN
    - Read bytes: 61440
    - Write bytes: 8192
    1709 - qmgr (8.50 MB)
      - /etc/postfix/relay.lmdb
      - Read bytes: 192512
      - Write bytes: 0
    20189 - pickup (8.50 MB)
      - Read bytes: 0
      - Write bytes: 0
  1730 - cron (2.62 MB)
    - /run/cron.pid
    - Read bytes: 176128
    - Write bytes: 1196032
  1755 - systemd (11.75 MB)
    - /proc/1755/mountinfo
    - /proc/swaps
    - Read bytes: 655360
    - Write bytes: 0
    1756 - (sd-pam) (5.91 MB)
      - Read bytes: 0
      - Write bytes: 0
    1767 - dbus-daemon (4.50 MB)
      - Read bytes: 217088
      - Write bytes: 0
    1770 - gvfsd (8.97 MB)
      - Read bytes: 1482752
      - Write bytes: 0
    1776 - gvfsd-fuse (10.38 MB)
      - Read bytes: 94208
      - Write bytes: 0
  1814 - systemd (12.00 MB)
    - /proc/1814/mountinfo
    - /proc/swaps
    - Read bytes: 0
    - Write bytes: 0
    1815 - (sd-pam) (5.91 MB)
      - Read bytes: 0
      - Write bytes: 0
    16842 - dbus-daemon (4.38 MB)
      - Read bytes: 0
      - Write bytes: 0
    16844 - gvfsd (9.01 MB)
      - Read bytes: 0
      - Write bytes: 0
    16850 - gvfsd-fuse (10.38 MB)
      - Read bytes: 0
      - Write bytes: 0

Read bytes and Write bytes - These values are cumulative.

```
## Contributing
Contributions are welcome! Please open an issue or submit a pull request if you have any suggestions or bug reports.

## License
This program is licensed under the GNU General Public License v2 or later.
