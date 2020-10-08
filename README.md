# cloudify-cluster-manager
> Installing a Cloudify cluster using existing VMs

&nbsp;
## Table of Contents
* [Installation](#installation)
    * [Choosing a cluster configuration](#choosing-a-cluster-configuration)
    * [Installing required packages](#installing-required-packages)
* [Usage](#usage)
    * [Generating a configuration file](#generating-a-configuration-file)
    * [Filling in the configuration file](#filling-in-the-configuration-file)
    * [Installing a Cloudify cluster](#installing-a-cloudify-cluster)
* [Fault tolerance mechanisms](#fault-tolerance-mechanisms)

&nbsp;
## Installation 

### Choosing a cluster configuration
In order to use the cloudify-cluster-manager package you would have to prepare your cluster 
environment in advance. The code supports all cloud providers and the following configurations:
* Nine VMs. 
* Three VMs. 
* Six VMs with an external DB. 
* Three VMs with an external DB.

Please follow the [prerequisites and sizing guidelines on Cloudify documentation](https://docs.cloudify.co/latest/install_maintain/installation/prerequisites/#cloudify-cluster)
for further instructions.

---
**NOTE**
1. The code currently works only with CentOS or RHEL OS.
2. You may use a load-balancer in the cluster configuration, but it **won't** be installed 
as part of the cluster installation.
---

&nbsp;
### Installing required packages
You can run the code from one of the cluster's VMs, or from a different host in the 
cluster network. Please run the following commands on the host you chose:

```bash
# Cloning this repo
sudo yum install -y git
git clone https://github.com/cloudify-cosmo/cloudify-cluster-manager.git

# Installing python3 and creating a virtual environment
sudo yum install -y python3
python3 -m venv python3-virtualenv
source python3-virtualenv/bin/activate

# Installing pip and setuptools
sudo yum install -y epel-release
sudo yum install -y python-pip
sudo pip install --upgrade pip
sudo pip install --upgrade setuptools

# Installing cloudify-cluster-manager
pip install -e cloudify-cluster-manager

# Installing haveged to avoid hanging executions
sudo yum install -y haveged 
sudo systemctl start haveged
```

Once you're done running the commands above, make sure you are on the python3-virtualenv. 
If not, you can run:
 
```bash
source python3-virtualenv/bin/activate
```

&nbsp;
## Usage
There are three steps in running the code:
1. Generating a cluster configuration file based on the cluster configuration.
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

* `-h, --help` - Show this help message and exit`

**NOTE:** `--three-nodes` or `--nine-nodes` must be specified, and they cannot be specified together.

&nbsp;
### Filling in the configuration file 

#### General Note
Fill in the information according to the comments in the file itself. Please, do not
delete anything from it.

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
    
#### Credentials
* If you wish to use your own credentials, you can specify them in the `credentials` section.

* Unfilled credentials will be generated and used by the code. The generated credentials 
are random. 

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
* `-- config-path` - The completed cluster install configuration file path. 
                     Default: ./cfy_cluster_config.yaml

* `--override` - If specified, any previous installation of Cloudify on 
                 the instances will be removed.

* `--validate` - Validate the provided configuration file.

* `-v, --verbose` - Show verbose output.

* `-h, --help` - Show this help message and exit`

&nbsp;
## Fault tolerance mechanisms
The code has a few mechanisms to handle errors:
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
