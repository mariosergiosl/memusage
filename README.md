# Memory Usage Tool

This tool displays the memory usage of processes on a Linux system.

## Features

* Shows total system memory, free memory, and used memory.
* Displays the memory usage of each process in a hierarchical tree format.
* Calculates the total memory usage of a process and its children.
* **Color-coded output based on process priority.**

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
memusage
Total system memory: 7877.40234375 MB
Free system memory: 6951.796875 MB
Used system memory: 925.60546875 MB

Total memory usage of the process tree: 1229.4296875 MB

Memory usage of each process:
PID - Process Name (Memory Usage)
1 - systemd (14.53 MB)
  646 - systemd-journald (10.50 MB)
  672 - systemd-udevd (12.95 MB)
  744 - haveged (4.99 MB)
  861 - auditd (3.76 MB)
  868 - avahi-daemon (3.50 MB)
  869 - dbus-daemon (5.94 MB)
  873 - irqbalance (5.32 MB)
  880 - polkitd (11.45 MB)
  883 - VGAuthService (10.12 MB)
  890 - nscd (4.63 MB)
  892 - wickedd-auto4 (5.88 MB)
  896 - vmware-vmblock-fuse (5.41 MB)
  898 - wickedd-dhcp4 (6.38 MB)
  902 - wickedd-dhcp6 (6.38 MB)
  992 - systemd-logind (8.50 MB)
  994 - wickedd (6.25 MB)
  995 - ModemManager (13.81 MB)
  999 - vmtoolsd (15.29 MB)
  1003 - wickedd-nanny (6.12 MB)
  1434 - cupsd (10.25 MB)
  1443 - rsyslogd (5.50 MB)
  1449 - chronyd (6.16 MB)
  1454 - sshd (9.25 MB)
    44959 - sshd (10.50 MB)
      44963 - sshd (6.75 MB)
        44964 - bash (5.25 MB)
          45317 - vim (11.88 MB)
    44961 - sshd (10.75 MB)
      45012 - sshd (6.50 MB)
        45013 - sftp-server (4.50 MB)
    45328 - sshd (10.75 MB)
      45332 - sshd (6.77 MB)
        45333 - bash (5.25 MB)
          45410 - memusage (12.25 MB)
    45330 - sshd (10.62 MB)
      45381 - sshd (6.38 MB)
        45382 - sftp-server (4.38 MB)
  1560 - lightdm (10.76 MB)
    1567 - X (138.99 MB)
    1751 - lightdm (11.82 MB)
      1792 - lxsession (17.95 MB)
        1845 - ssh-agent (1.70 MB)
        1846 - gpg-agent (2.50 MB)
        1870 - openbox (25.73 MB)
        1871 - lxpolkit (16.29 MB)
        1873 - lxpanel (42.46 MB)
          2135 - lxterminal (55.01 MB)
            2139 - bash (5.25 MB)
        1875 - pcmanfm (54.72 MB)
        1876 - xscreensaver (3.31 MB)
          1893 - xscreensaver-systemd (3.88 MB)
          45113 - xscreensaver-gfx (5.10 MB)
        1878 - lxclipboard (14.93 MB)
  1575 - accounts-daemon (7.18 MB)
  1576 - agetty (2.38 MB)
  1647 - master (5.05 MB)
    1649 - qmgr (9.00 MB)
    44329 - pickup (8.62 MB)
  1670 - cron (2.75 MB)
  1776 - systemd (12.12 MB)
    1777 - (sd-pam) (5.97 MB)
    1803 - dbus-daemon (4.62 MB)
    1854 - gvfsd (7.12 MB)
      2105 - gvfsd-trash (11.82 MB)
    1860 - gvfsd-fuse (10.59 MB)
    1995 - gvfs-udisks2-volume-monitor (14.95 MB)
    2020 - gvfs-goa-volume-monitor (8.16 MB)
    2025 - goa-daemon (41.04 MB)
    2027 - xdg-desktop-portal (22.74 MB)
    2033 - xdg-document-portal (11.21 MB)
      2044 - fusermount3 (1.75 MB)
    2037 - xdg-permission-store (10.68 MB)
    2058 - goa-identity-service (13.59 MB)
    2060 - gvfs-afc-volume-monitor (10.21 MB)
    2072 - gvfs-mtp-volume-monitor (10.16 MB)
    2079 - xdg-desktop-portal-gtk (22.58 MB)
    2080 - gvfs-gphoto2-volume-monitor (8.63 MB)
    2097 - pipewire (7.88 MB)
    2098 - wireplumber (13.54 MB)
    44729 - gnome-keyring-daemon (10.86 MB)
  1880 - agent (5.88 MB)
  1882 - ssh-agent (1.59 MB)
  1900 - nm-applet (38.25 MB)
  1907 - pk-update-icon (16.75 MB)
  1914 - vmtoolsd (44.95 MB)
  1923 - parcellite (18.91 MB)
  1927 - applet.py (32.33 MB)
  1930 - xfce4-power-manager (23.02 MB)
  1975 - menu-cached (5.90 MB)
  1985 - upowerd (11.05 MB)
  2004 - udisksd (16.44 MB)
  2050 - rtkit-daemon (3.38 MB)
```
## Contributing
Contributions are welcome! Please open an issue or submit a pull request if you have any suggestions or bug reports.

## License
This program is licensed under the GNU General Public License v2 or later.
