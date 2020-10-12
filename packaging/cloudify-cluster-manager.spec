%define __python /opt/cfy_cluster_manager/bin/python
%define _venv /opt/cfy_cluster_manager

Name:           cloudify-cluster-manager
Version:        %{CLOUDIFY_VERSION}
Release:        %{CLOUDIFY_PACKAGE_RELEASE}%{?dist}
Summary:        Cloudify Cluster Installer
Group:          Applications/Multimedia
License:        Apache 2.0
URL:            https://github.com/cloudify-cosmo/cloudify-cluster-manager
Vendor:         Cloudify Platform Ltd.
Packager:       Cloudify Platform Ltd.

BuildRequires: python3 >= 3.6
Requires: python3 >= 3.6


%description
Cloudify Cluster Installer.


%prep

%build
python3 -m venv %_venv
%_venv/bin/pip install -r "${RPM_SOURCE_DIR}/dev-requirements.txt"
%_venv/bin/pip install "${RPM_SOURCE_DIR}"


%install
mkdir -p %{buildroot}/opt
mkdir -p %{buildroot}/usr/bin
mv %_venv %{buildroot}%_venv
ln -s %_venv/bin/cfy_cluster_manager %{buildroot}/usr/bin/cfy_cluster_manager

%files
/opt/cfy_cluster_manager
/usr/bin/cfy_cluster_manager
