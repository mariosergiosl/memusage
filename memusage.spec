Name:            memusage
Version:         0.2
Release:         1%{?dist}
Summary:         A Swiss Army knife for comprehensive Linux process analysis.
BuildArch:       noarch
License:         GPL-2.0-only
URL:             https://github.com/mariosergiosl/memusage
Source0:         %{name}-0.2.tar.xz
Group:           System/Management

BuildRequires:   python3
BuildRequires:   python3-psutil

%description
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

%prep
%setup -q

%build
# No build steps required for Python script

%install
install -Dm 0755 %{name}.py %{buildroot}%{_bindir}/%{name}

%files
%{_bindir}/%{name}

%changelog
* Fri Jun 13 2025 Mario Luz <mario.mssl[at]google.com> - 0.2
- Updated to version 0.2 with enhanced features for disk, security, and Pylint fixes.