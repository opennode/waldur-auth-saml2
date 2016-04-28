%define __conf_dir %{_sysconfdir}/nodeconductor/saml2
%define __conf_file %{_sysconfdir}/nodeconductor/nodeconductor_saml2.py.example
%define __cert_file %{__conf_dir}/dummy.crt
%define __key_file %{__conf_dir}/dummy.pem

Name: nodeconductor-saml2
Summary: SAML2 plugin for NodeConductor
Group: Development/Libraries
Version: 0.1.4
Release: 1.el7
License: Copyright 2015 OpenNode LLC.  All rights reserved.
Url: http://nodeconductor.com
Source0: %{name}-%{version}.tar.gz

# openssl package is needed to generate SAML2 keys during plugin install
# xmlsec1-openssl package is needed for SAML2 features to work
Requires: nodeconductor >= 0.78.0
Requires: openssl
Requires: python-django-saml2 = 0.13.0
Requires: xmlsec1-openssl

BuildArch: noarch
BuildRoot: %{_tmppath}/%{name}-%{version}-%{release}-buildroot

BuildRequires: python-setuptools

%description
SAML2 plugin for NodeConductor.

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
* Thu Apr 28 2016 Jenkins <jenkins@opennodecloud.com> - 0.1.4-1.el7
- New upstream release

* Sun Nov 22 2015 Jenkins <jenkins@opennodecloud.com> - 0.1.3-1.el7
- New upstream release

* Fri Oct 30 2015 Juri Hudolejev <juri@opennodecloud.com> - 0.1.1-2.el7
- New upstream release: 0.1.2

* Thu Oct 29 2015 Juri Hudolejev <juri@opennodecloud.com> - 0.1.1-1.el7
- New upstream release: 0.1.1

* Tue Oct 20 2015 Victor Mireyev <victor@opennodecloud.com> - 0.1.0-1.el7
- Initial version of the package
