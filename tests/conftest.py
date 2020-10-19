from os.path import dirname, join

import yaml
import pytest


@pytest.fixture(autouse=True)
def config_dir(tmp_path):
    config_dir = tmp_path / 'config'
    config_dir.mkdir()
    return config_dir


@pytest.fixture(autouse=True)
def cluster_manager_dir(tmp_path):
    cluster_manager_dir = tmp_path / 'cloudify_cluster_manager'
    cluster_manager_dir.mkdir()
    return cluster_manager_dir


@pytest.fixture(autouse=True)
def ssh_key_path(config_dir):
    ssh_key_path = config_dir / 'key_file.pem'
    ssh_key_path.write_text(u'test_key_path')
    return str(ssh_key_path)


@pytest.fixture(autouse=True)
def license_path(config_dir):
    license_path = config_dir / 'license.yaml'
    license_path.write_text(u'test_license_path')
    return str(license_path)


@pytest.fixture(autouse=True)
def basic_config_dict(ssh_key_path, license_path):
    return {
        'ssh_key_path': ssh_key_path,
        'ssh_user': 'centos',
        'cloudify_license_path': license_path
    }


@pytest.fixture()
def tmp_certs_dir(tmp_path):
    tmp_certs_dir = tmp_path / 'tmp_certs'
    tmp_certs_dir.mkdir()
    return tmp_certs_dir


@pytest.fixture()
def tmp_config_files_dir(tmp_path):
    dir_path = tmp_path / 'config_files'
    dir_path.mkdir()
    return dir_path


@pytest.fixture()
def ca_path(tmp_certs_dir):
    ca_path = tmp_certs_dir / 'ca.pem'
    ca_path.write_text(u'test_ca_path')
    return str(ca_path)


@pytest.fixture()
def ldap_ca_path(tmp_certs_dir):
    ldap_ca_path = tmp_certs_dir / 'ldap_ca.pem'
    ldap_ca_path.write_text(u'test_ldap_ca_path')
    return str(ldap_ca_path)


@pytest.fixture()
def external_db_ca_path(tmp_certs_dir):
    external_db_ca_path = tmp_certs_dir / 'external_db_ca.pem'
    external_db_ca_path.write_text(u'test_external_db_ca_path')
    return str(external_db_ca_path)


@pytest.fixture()
def three_nodes_config_dict(basic_config_dict):
    return _get_config_dict('three_nodes_config.yaml', basic_config_dict)


@pytest.fixture()
def three_nodes_external_db_config_dict(basic_config_dict):
    return _get_config_dict('three_nodes_external_db_config.yaml',
                            basic_config_dict)


@pytest.fixture()
def nine_nodes_config_dict(basic_config_dict):
    return _get_config_dict('nine_nodes_config.yaml', basic_config_dict)


def _get_config_dict(config_file_name, basic_config_dict):
    resources_path = join(dirname(__file__), 'resources')
    completed_config_path = join(resources_path, config_file_name)
    with open(completed_config_path) as config_path:
        config_dict = yaml.load(config_path, yaml.Loader)

    config_dict.update(basic_config_dict)
    return config_dict
