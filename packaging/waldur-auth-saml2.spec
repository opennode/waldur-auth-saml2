%define __conf_dir %{_sysconfdir}/waldur/saml2
%define __conf_file %{_sysconfdir}/waldur/saml2.conf.py.example
%define __cert_file %{__conf_dir}/sp.crt
%define __key_file %{__conf_dir}/sp.pem

Name: waldur-auth-saml2
Summary: SAML2 plugin for Waldur
Group: Development/Libraries
Version: 0.8.8
Release: 1.el7
License: MIT
Url: http://waldur.com
Source0: %{name}-%{version}.tar.gz

# openssl package is needed to generate SAML2 keys during plugin install
# xmlsec1-openssl package is needed for SAML2 features to work
Requires: waldur-core >= 0.151.0
Requires: openssl
Requires: python-django-saml2 = 0.16.9
Requires: xmlsec1-openssl

BuildArch: noarch
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot

BuildRequires: python-setuptools

Obsoletes: nodeconductor-saml2

%description
SAML2 plugin for Waldur.

%prep
%setup -q -n %{name}-%{version}

%build
python setup.py build

%install
rm -rf %{buildroot}
python setup.py install --single-version-externally-managed -O1 --root=%{buildroot} --record=INSTALLED_FILES

mkdir -p %{buildroot}%{__conf_dir}
echo "%{__conf_dir}" >> INSTALLED_FILES

cp -r attribute-maps %{buildroot}%{__conf_dir}/

cp packaging%{__conf_file} %{buildroot}%{__conf_file}
echo "%{__conf_file}" >> INSTALLED_FILES

cat INSTALLED_FILES | sort | uniq > INSTALLED_FILES_CLEAN

%clean
rm -rf %{buildroot}

%files -f INSTALLED_FILES_CLEAN
%defattr(-,root,root)

%post
if [ "$1" = 1 ]; then
    # This package is being installed for the first time
    echo "[%{name}] Generating SAML2 keypair..."
    if [ ! -f %{__cert_file} -a ! -f %{__key_file} ]; then
        openssl req -batch -newkey rsa:2048 -new -x509 -days 3652 -nodes -out %{__cert_file} -keyout %{__key_file}
    fi
fi

%changelog
* Tue Feb 13 2018 Jenkins <jenkins@opennodecloud.com> - 0.8.8-1.el7
- New upstream release

* Mon Feb 12 2018 Jenkins <jenkins@opennodecloud.com> - 0.8.7-1.el7
- New upstream release

* Sun Feb 11 2018 Jenkins <jenkins@opennodecloud.com> - 0.8.6-1.el7
- New upstream release

* Mon Jan 29 2018 Jenkins <jenkins@opennodecloud.com> - 0.8.5-1.el7
- New upstream release

* Fri Dec 1 2017 Jenkins <jenkins@opennodecloud.com> - 0.8.4-1.el7
- New upstream release

* Wed Nov 29 2017 Jenkins <jenkins@opennodecloud.com> - 0.8.3-1.el7
- New upstream release

* Wed Nov 1 2017 Jenkins <jenkins@opennodecloud.com> - 0.8.2-1.el7
- New upstream release

* Tue Sep 19 2017 Jenkins <jenkins@opennodecloud.com> - 0.8.1-1.el7
- New upstream release

* Tue Sep 19 2017 Jenkins <jenkins@opennodecloud.com> - 0.8.0-1.el7
- New upstream release

* Mon Jul 3 2017 Jenkins <jenkins@opennodecloud.com> - 0.7.3-1.el7
- New upstream release
