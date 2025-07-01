Name:           memusage
Version:        0.0.0
Release:        1%{?dist}
Summary:        A Swiss Army knife for comprehensive Linux process analysis.

BuildArch:      noarch
License:        GPL-3.0-or-later
URL:            https://github.com/mariosergiosl/memusage
Source0:        %{name}-%{version}.tar.xz
Group:          System/Management


BuildRequires:  python3
BuildRequires:  python3-setuptools
BuildRequires:  python3-pip
BuildRequires:  python3-psutil

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
%setup -q

%build
%pip install --prefix=%{buildroot}%{_prefix} .

%install
# The %pip install in %build handles installation into %{buildroot}.
# This line is typically not needed if setup.py defines entry_points.
# # install -Dm 0755 %{name}.py %{buildroot}%{_bindir}/%{name}

%files
# List files to be included in the RPM package.
# %{_bindir}/%{name} comes from setup.py entry_points
%attr(0755, -, -) %{_bindir}/%{name}
%{python3_sitelib}/%{name}.py

%changelog
* %{_current_date} Mario Luz <mario.mssl[at]google.com> - %{version}
- Updated package to version %{version} with enhanced features for disk, security, and Pylint fixes.
