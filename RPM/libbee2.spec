%global commit			7afea8b3778b5501e5ccb1ab0b9d4ef6d8773e35
%global shortcommit		%(c=%{commit}; echo ${c:0:7})
%global snapshotdate	20200706

Summary:		Cryptographic library
Name:			libbee2
Version:		2.0.5
Release:		9.%{snapshotdate}git%{shortcommit}%{?dist}
License:		GPLv3
Url:			http://apmi.bsu.by/resources/tools.html
Source0:		https://github.com/agievich/bee2/archive/%{commit}/bee2-%{shortcommit}.zip
BuildRequires:	cmake, gcc

%description
Bee2 is a cryptographic library which implements cryptographic 
algorithms and protocols standardized in Belarus. Additionally, Bee2 
implements digital signature algorithms standardized in Russia and 
Ukraine.

%package		devel
Summary:		Files for development of applications which will use bee2
Requires:		%{name}%{?_isa} = %{version}-%{release}
%description	devel
Bee2 is a cryptographic library which implements cryptographic 
algorithms and protocols standardized in Belarus. The bee2-devel package
contains files needed to develop applications which support these 
cryptographic algorithms and protocols.

%package	-n bsum
Summary:	Calculation and verification of hash values using the STB 34.101.31 and STB 34.101.77 algorithms
%description -n bsum
Bsum implements calculation and verification of hash values using the 
algorithms STB 34.101.31 (belt-hash) and STB 34.101.77 (bash32, bash64, 
..., bash512). The command-line interface of the utility is as close as 
possible to the interfaces of similar sha1sum and sha256sum utilities.

#------------------------------------------------------------------

%prep
%autosetup -n bee2-%{commit} -p 1

%build

%if 0%{?fedora}
%cmake -S %{_vpath_srcdir} -B %{_vpath_builddir}
%else
%cmake
%endif

%if 0%{?fedora}
%make_build -C %{_vpath_builddir}
%else
%make_build
%endif

%install

%if 0%{?fedora}
%make_install -C %{_vpath_builddir}
%else
%make_install
%endif

%{__rm} -rf %{buildroot}%{_libdir}/libbee2_static.a

%check

%if 0%{?fedora}
%make_build -C %{_vpath_builddir} test
%else
%make_build test
%endif

%files

%{_libdir}/libbee2.so.2.0
%{_libdir}/libbee2.so.2.0.5

%license LICENSE
%doc AUTHORS.md README.md

%files devel

%{_includedir}/bee2/
%{_libdir}/libbee2.so

%files -n bsum

%{_bindir}/bsum

%changelog
* Sun Jul 12 2020 Yury Kashcheyeu <kashcheyeu@tiksi.ru> - 2.0.5-9
- Initial RPM release
