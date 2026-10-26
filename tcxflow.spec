# SPDX-License-Identifier: GPL-2.0-or-later
# Copyright (C) 2026 Dirk Nehring <dnehring@gmx.net>
#
# RPM spec for tcxflow
# Build directly from tarball: rpmbuild -ta tcxflow-<version>.tar.gz

Name:           tcxflow
Version:        1.2.0
Release:        1%{?dist}
Summary:        Lightweight eBPF-based IPFIX flow accounting

License:        GPL-2.0-or-later
URL:            https://github.com/dnehring7/tcxflow
Source0:        %{url}/archive/refs/tags/v%{version}.tar.gz#/%{name}-%{version}.tar.gz
ExclusiveArch:  x86_64

# One package for every x86-64 CPU: EL 10 builds for x86-64-v3 by default (AVX2), Fedora for the baseline.
%global __cflags_arch_x86_64_level %{nil}

BuildRequires:  bpftool
BuildRequires:  clang >= 19
BuildRequires:  gcc >= 14
BuildRequires:  make
BuildRequires:  pkgconfig(libbpf) >= 1.5
BuildRequires:  systemd-rpm-macros

%description
tcxflow meters the traffic of selected network interfaces with a small eBPF
program on the kernel's tcx hook and exports the flows as IPFIX (RFC 7011) to
one or more collectors.

It replaces ipt_NETFLOW on modern systems: no out-of-tree kernel module, no
iptables or nftables rules, and it works on routers whose interfaces live in a
separate network namespace.

%prep
%autosetup

%build
%make_build

%install
%make_install PREFIX=%{_prefix} SBINDIR=%{_sbindir} UNITDIR=%{_unitdir}

%check
make test
./tcxflow --version

%post
%systemd_post tcxflow.service

%preun
%systemd_preun tcxflow.service

%postun
%systemd_postun_with_restart tcxflow.service

%files
%license LICENSE
%doc README.md
%{_sbindir}/tcxflow
%{_unitdir}/tcxflow.service
%dir %{_sysconfdir}/tcxflow
%config(noreplace) %{_sysconfdir}/tcxflow/tcxflow.conf

%changelog
