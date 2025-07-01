Name:            memusage
Version:         0.3.1
Release:         1%{?dist}
Summary:         A Swiss Army knife for comprehensive Linux process analysis.

BuildArch:       noarch
License:         GPL-2.0-only
URL:             https://github.com/mariosergiosl/memusage
Source0:         %{name}-%{version}.tar.gz
# Source0:         %{name}.tar.xz
Group:           System/Management


BuildRequires:   python3
BuildRequires:   python3-setuptools
BuildRequires:   python3-pip
BuildRequires:   python3-psutil

%description
This tool provides deep insights into process behavior, making it invaluable for
troubleshooting and security auditing.
It details:
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
# %setup -q -n %{name}-%{version}
# %setup -q -n memusage-main
# %setup -q
# %autosetup -p1 -n %{name}-%{version}
find . -maxdepth 2 -print -exec ls -ld {} \;
%autosetup -p1

%build
# %pip install --prefix=%{buildroot}%{_prefix} .

%install
# install -Dm 0755 %{_builddir}/%{name}-main/%{name}.py %{buildroot}%{_bindir}/%{name}
install -Dm 0755 %{name}.py %{buildroot}%{_bindir}/%{name}

%files
%{_bindir}/%{name}

%changelog
* %{_current_date} Mario Luz <mario.mssl[at]google.com> - 0.3.1
- Initial package release based on tag v0.3.1.