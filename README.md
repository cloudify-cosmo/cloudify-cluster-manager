# Cloudify Cluster Manager
The purpose of the Cloudify Cluster Manager package is to automate the procedure of installing a Cloudify
cluster on existing VMs. The following article will guide you through the different steps of
easily installing a Cloudify cluster on either three or nine VMs.

&nbsp;
## Table of Contents
* [Installation](#installation)
    * [Choosing a cluster configuration](#choosing-a-cluster-configuration)
    * [Installing the Cloudify Cluster Manager package](#installing-the-cloudify-cluster-manager-package)
        * [Installing using an RPM](#installing-using-an-rpm)
        * [Installing using pip install](#installing-using-pip-install)
* [Using the Cloudify Cluster Manager package](#using-the-cloudify-cluster-manager-package)
    * [Generating a configuration file](#generating-a-configuration-file)
    * [Filling in the configuration file](#filling-in-the-configuration-file)
    * [Installing a Cloudify cluster](#installing-a-cloudify-cluster)
    * [Removing a Cloudify cluster](#removing-a-cloudify-cluster)
    * [Upgrading a Cloudify cluster](#upgrading-a-cloudify-cluster)
* [Fault tolerance mechanisms](#fault-tolerance-mechanisms)

&nbsp;
## Installation

### Choosing a cluster configuration
Before using the Cloudify Cluster Manager package you must prepare a set of VMs for your cluster.
The Cloudify Cluster Manager package supports all cloud providers and the following configurations:
* Nine VMs.
* Three VMs.
* Six VMs with an external DB.
* Three VMs with an external DB.

Please follow the [prerequisites and sizing guidelines on Cloudify documentation](https://docs.cloudify.co/latest/install_maintain/installation/prerequisites/#cloudify-cluster)
and generate the required number of VMs according to the mentioned spec. You should also prepare a load balancer to distribute the load over the managers.

---
**NOTE**

1. The Cloudify Cluster Manager package is currently supported over CentOS or RHEL OS.
2. A load-balancer is required for load distribution over the managers.
The setup will expect a load balancer address. The Cloudify Cluster Manager package does not install the load balancer.
---

&nbsp;
### Installing the Cloudify Cluster Manager package
You can run the Cloudify Cluster Manager package from one of the cluster's VMs, or from a different host in the
cluster network. You can install the package either by using an RPM or by using `pip install`:

#### Installing using an RPM
Run the following command:
```bash
sudo yum install -y http://repository.cloudifysource.org/cloudify/cloudify-cluster-manager/1.1.7/ga-release/cloudify-cluster-manager-1.1.7-ga.el7.x86_64.rpm

# Installing haveged to avoid hanging executions
curl https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm -o epel-release-latest-7.noarch.rpm
sudo yum install -y epel-release-latest-7.noarch.rpm
sudo yum install -y haveged
sudo systemctl start haveged
```

**NOTE:** On RHEL 8, install haveged as follows instead:
```bash
curl https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm -o epel-release-latest-8.noarch.rpm
sudo yum install -y epel-release-latest-8.noarch.rpm
sudo yum install -y haveged
sudo systemctl start haveged
```

#### Installing using pip install
```bash
pip install cloudify-cluster-manager

# Installing haveged to avoid hanging executions
curl https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm -o epel-release-latest-7.noarch.rpm
sudo yum install -y epel-release-latest-7.noarch.rpm
sudo yum install -y haveged
sudo systemctl start haveged
```


&nbsp;
## Using the Cloudify Cluster Manager package
Once the VMs are ready, using the Cloudify Cluster Manager package to build the cluster consists of three steps:

1. Generating a cluster configuration file template based on the cluster topology you wish to deploy.
2. Filling in the generated file with the relevant information.
3. Running the cluster installation based on the completed configuration file.

&nbsp;
### Generating a configuration file
Generating the configuration file is done using the command:

```bash
cfy_cluster_manager generate-config [OPTIONS]
```

#### Options
* `-o, --output-path` - The local path to save the cluster install configuration file to.
                        Default: ./cfy_cluster_config.yaml

* `--three-nodes` - Using a three nodes cluster.

* `--nine-nodes` - Using a nine nodes cluster. In case of using an
                   external DB, Only 6 nodes will need to be provided.

* `--external-db` - Using an external DB.

* `-v, --verbose` - Show verbose output.

* `-h, --help` - Show this help message and exit.

**NOTE:** `--three-nodes` or `--nine-nodes` must be specified, and they cannot be specified together.

&nbsp;
### Filling in the configuration file

#### General Note
Fill in the information according to the comments in the file itself.
**NOTE!** Do not delete anything from the file.
**NOTE!** On RHEL 8, make sure to use the `.el8` RPM for the `manager_rpm_path`.

#### Load-balancer
As mentioned before, a load-balancer is not installed as part of the cluster installation.
The `load_balancer_ip` value is used in the different config.yaml files for the instances' connection.

#### Certificates
* If you wish to use your own certificates:
    * Fill in the `ca_cert_path` value and the `cert_path` and `key_path` values for each VM (all of them).
    * In case that a VM's certificate's SAN includes the VM host-name, please specify this host-name as the value
      of the `hostname` key.

* Otherwise: Cloudify signed certificates will be generated and used automatically.

#### config.yaml files
* If you wish to use your own config.yaml files for the different instances, you may
do so by specifying their path as the value of the `config_path` in each one of the instances (all of them).

* Otherwise, preconfigured config.yaml files will be generated and used automatically.

* **Note**: If you use your own config files, you cannot specify the certificates' paths for the different instances.
Moreover, the ldap, external_db, and credentials sections in the configuration file will be ignored.

#### Credentials
* If you wish to use your own credentials, you can specify them in the `credentials` section.

* Unfilled credentials will be generated and used by the Cloudify Cluster Manager package. The generated credentials
are random.

* The PostgreSQL password must start with a *letter* (i.e. a password `12345678` will cause an error during PostgreSQL installation).

* **WARNING:** At the end of the installation, a file named `secret_credentials_file.yaml` will be created in the current directory.
This file includes the credentials in clear text. Please, remove it after reviewing it or store it in a safe location.   

&nbsp;
### Installing a Cloudify cluster
Now that the configuration file is completed, we can move on to the cluster installation using the
following command:

```bash
cfy_cluster_manager install [OPTIONS]
```

#### Options
* `--config-path` - The completed cluster configuration file path.
                     Default: ./cfy_cluster_config.yaml

* `--override` - If specified, any previous installation of Cloudify on
                 the instances will be removed.

* `--validate` - Validate the provided configuration file.

* `-v, --verbose` - Show verbose output.

* `-h, --help` - Show this help message and exit.

**NOTE:** On RHEL 8, *before* installing the cluster, add the following required 
packages on each machine of the cluster, since the VMs may come without them:
```bash
sudo yum install -y https://repository.cloudifysource.org/cloudify/components/libnsl-2.28-189.el8.x86_64.rpm \
https://repository.cloudifysource.org/cloudify/components/glibc-2.28-189.el8.x86_64.rpm \
https://repository.cloudifysource.org/cloudify/components/glibc-common-2.28-189.el8.x86_64.rpm \
https://repository.cloudifysource.org/cloudify/components/glibc-langpack-en-2.28-189.el8.x86_64.rpm \
https://repository.cloudifysource.org/cloudify/components/glibc-locale-source-2.28-189.el8.x86_64.rpm --allowerasing
```

&nbsp;
### Removing a Cloudify cluster
The created Cloudify cluster can be removed using the following command:

```bash
cfy_cluster_manager remove [OPTIONS]
```

#### Options
* `--config-path` - The completed cluster configuration file path.
                     Default: ./cfy_cluster_config.yaml

* `-v, --verbose` - Show verbose output.

* `-h, --help` - Show this help message and exit.

&nbsp;
### Upgrading a Cloudify cluster
The Cloudify cluster can be upgraded from v5.1.0 to any minor version (5.1.x) using the following command:

```bash
cfy_cluster_manager upgrade [OPTIONS]
```

#### Options
* `--config-path` - The completed cluster configuration file path.
                     Default: ./cfy_cluster_config.yaml

* `--upgrade-rpm` - Path to a cloudify-manager-install RPM. This can be either a local or remote path.  
                    Default: http://repository.cloudifysource.org/cloudify/5.1.3/ga-release/cloudify-manager-install-5.1.3-ga.el7.x86_64.rpm

* `-v, --verbose` - Show verbose output.

* `-h, --help` - Show this help message and exit.

&nbsp;
## Fault tolerance mechanisms
The Cloudify Cluster Manager package has a few mechanisms to handle errors:

* The configuration file is validated before it is being used.

* The connection to each instance is tested before the installation starts.

* The `cfy_manager install` command is run using `systemd-run` on the different instances. I.e. if the SSH connection
is interrupted, the installation keeps on running because it's configured as a child process of the init process.

* In case of a recoverable error during the installation, you can just run the `cfy_cluster_manager install` command again.
The installation process would:

    1. Go over the instances and check if they were installed successfully.
    2. Once it gets to the failed instance, it would remove the failed installation, and continue the installation from there.

* In case of an unrecoverable error during the installation, you can run it again using: `cfy_manager install --override`.  
This command would:

    1. Go over the instances and remove Cloudify from them (including the RPM).
    2. Run the installation process from the start.
