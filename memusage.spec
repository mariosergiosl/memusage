Name:           memusage
Version:        1.0
Release:        1%{?dist}
Summary:        Display memory usage of processes

License:        GPL-2.0-only
URL:            https://github.com/mariosergiosl/memusage
Source0:        %{name}-%{version}.tar.xz

BuildRequires:  python3
BuildRequires:  python3-psutil

%description
This tool displays the memory usage of processes on a Linux system, 
including total system memory, free memory, and used memory. 
It also shows the memory usage of each process in a hierarchical tree format.

%prep
%setup -q

%build
# No build steps required for Python script

%install
install -Dm 0755 %{name}.py %{buildroot}%{_bindir}/%{name}

%files
%{_bindir}/%{name}

%changelog
* Tue Nov 14 2024 Mario Luz - 1.0-1
- Initial package release.
