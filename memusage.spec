#
# spec file for package memusage
#
# Copyright (c) 2024 SUSE LLC
#
# All modifications and additions to the file contributed by third parties
# remain the property of their copyright owners, unless otherwise agreed
# upon. The license for this file, and modifications and additions to the
# file, is the same license as for the pristine package itself (unless the
# license for the pristine package is not an Open Source License, in which
# case the license is the MIT License). An "Open Source License" is a
# license that conforms to the Open Source Definition (Version 1.9)
# published by the Open Source Initiative.

# Please submit bugfixes or comments via https://bugs.opensuse.org/
#


Name:           memusage
Version:        1.0
Release:        1%{?dist}
Summary:        Display memory usage of processes

License:        GPL-2.0-only
URL:            https://github.com/seunome/memusage  # Substitua pelo seu repositório
Source0:        %{name}-%{version}.tar.gz

BuildRequires:  python3
BuildRequires:  python3-psutil

%description
This tool displays the memory usage of processes on a Linux system, 
including total system memory, free memory, and used memory. 
It also shows the memory usage of each process in a hierarchical tree format.

%prep
%setup -q

%build
# Nenhum passo de build necessário para script Python

%install
install -Dm 0755 %{name}.py %{buildroot}%{_bindir}/%{name}

%check
# %make_build check

%files
%{_bindir}/%{name}

%changelog
* Tue Nov 14 2024 Mario Luz <seuemail@example.com> - 1.0-1
- Initial package release.
