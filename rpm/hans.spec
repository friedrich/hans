########################################################################################

%define _posixroot        /
%define _root             /root
%define _bin              /bin
%define _sbin             /sbin
%define _srv              /srv
%define _home             /home
%define _opt              /opt
%define _lib32            %{_posixroot}lib
%define _lib64            %{_posixroot}lib64
%define _libdir32         %{_prefix}%{_lib32}
%define _libdir64         %{_prefix}%{_lib64}
%define _logdir           %{_localstatedir}/log
%define _rundir           %{_localstatedir}/run
%define _lockdir          %{_localstatedir}/lock/subsys
%define _cachedir         %{_localstatedir}/cache
%define _spooldir         %{_localstatedir}/spool
%define _crondir          %{_sysconfdir}/cron.d
%define _loc_prefix       %{_prefix}/local
%define _loc_exec_prefix  %{_loc_prefix}
%define _loc_bindir       %{_loc_exec_prefix}/bin
%define _loc_libdir       %{_loc_exec_prefix}/%{_lib}
%define _loc_libdir32     %{_loc_exec_prefix}/%{_lib32}
%define _loc_libdir64     %{_loc_exec_prefix}/%{_lib64}
%define _loc_libexecdir   %{_loc_exec_prefix}/libexec
%define _loc_sbindir      %{_loc_exec_prefix}/sbin
%define _loc_bindir       %{_loc_exec_prefix}/bin
%define _loc_datarootdir  %{_loc_prefix}/share
%define _loc_includedir   %{_loc_prefix}/include
%define _loc_mandir       %{_loc_datarootdir}/man
%define _rpmstatedir      %{_sharedstatedir}/rpm-state
%define _pkgconfigdir     %{_libdir}/pkgconfig
%define __sysctl          %{_bindir}/systemctl

########################################################################################

%define __ln              %{_bin}/ln
%define __touch           %{_bin}/touch
%define __service         %{_sbin}/service
%define __chkconfig       %{_sbin}/chkconfig
%define __ldconfig        %{_sbin}/ldconfig
%define __groupadd        %{_sbindir}/groupadd
%define __useradd         %{_sbindir}/useradd

########################################################################################

Summary:        IP over ICMP tool
Name:           hans
Version:        1.0
Release:        0%{?dist}
License:        GPLv3
Group:          Development/Libraries
URL:            https://github.com/friedrich/hans

Source0:        https://github.com/friedrich/%{name}/archive/v%{version}.tar.gz
Source1:        %{name}.sysconfig
Source2:        %{name}.service

%if 0%{?rhel} >= 7
Requires:       systemd
%endif

BuildRequires:  gcc gcc-c++ glibc-devel make

BuildRoot:      %{_tmppath}/%{name}-%{version}

Provides:       %{name} = %{version}-%{release}

########################################################################################

%description
Hans makes it possible to tunnel IPv4 through ICMP echo packets, so you could call it
a ping tunnel. This can be useful when you find yourself in the situation that your
Internet access is firewalled, but pings are allowed.

########################################################################################

%prep
%setup -qn %{name}-%{version}

%clean
%{__rm} -rf %{buildroot}

%build
%{__make} %{?_smp_mflags}

%install
%{__rm} -rf %{buildroot}

install -dm 755 %{buildroot}
install -dm 755 %{buildroot}%{_bindir}
install -dm 755 %{buildroot}%{_initrddir}

install -dm 755 %{buildroot}%{_sysconfdir}/sysconfig

install -pm 644 %{SOURCE1} \
                %{buildroot}%{_sysconfdir}/sysconfig/%{name}

cp -ap %{name} %{buildroot}%{_bindir}/%{name}

%if 0%{?rhel} >= 7
install -dm 755 %{buildroot}%{_unitdir}
install -pm 644 %{SOURCE2} %{buildroot}%{_unitdir}/
%endif

%preun
%if 0%{?systemd_preun:1}
  %systemd_preun %{name}.service
%else
if [[ $1 -eq 0 ]] ; then
  %{__sysctl} --no-reload disable %{name}.service > /dev/null 2>&1 || :
  %{__sysctl} stop %{name}.service &>/dev/null || :
fi
%endif

%post
%if 0%{?systemd_post:1}
  %systemd_post %{name}.service
%else
  %{__sysctl} daemon-reload &>/dev/null || :
%endif

########################################################################################

%files
%defattr(-,root,root,-)
%{_bindir}/%{name}
%config(noreplace) %{_sysconfdir}/sysconfig/%{name}
%if 0%{?rhel} >= 7
%{_unitdir}/%{name}.service
%endif

########################################################################################

%changelog
* Tue Jun 20 2017 Hans Team <hans@schoeller.se> - 1.0-0
- Initial build.

