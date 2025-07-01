Name:            memusage
Version:         0.1
Release:         1%{?dist}
Summary:         A Swiss Army knife for comprehensive Linux process analysis. # Descrição atualizada

BuildArch:       noarch
License:         GPL-2.0-only
URL:             https://github.com/mariosergiosl/memusage
# Source0: Aponta para o link direto de download do tarball do branch 'main' do GitHub.
# Este arquivo contém o memusage.py na raiz após a extração.
Source0:         %{url}/archive/main.tar.gz 
Group:           System/Management


BuildRequires:   python3
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
# Extrai o tarball do repositório Git completo (Source0).
# GitHub's main.tar.gz geralmente extrai para uma pasta nomeada como 'memusage-main'.
%setup -q -n %{name}-main 

# Não precisamos de %build complexo, pois o %install copia diretamente o script.

%install
# Copia manualmente o script 'memusage.py' do diretório fonte extraído.
# O diretório fonte após %prep será %{_builddir}/%{name}-main/
install -Dm 0755 %{_builddir}/%{name}-main/%{name}.py %{buildroot}%{_bindir}/%{name}

%files
%{_bindir}/%{name} # Inclui apenas o executável no RPM, como na versão funcional

%changelog
* %{_current_date} Mario Luz <mario.mssl[at]google.com> - 0.1
- Initial package release.