from os.path import dirname, join

import yaml
import pytest

from cfy_cluster_manager.main import validate_config
from cfy_cluster_manager.utils import ClusterInstallError


@pytest.fixture(autouse=True)
def config_dir(tmp_path):
    config_dir = tmp_path / 'config'
    config_dir.mkdir()
    return config_dir


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
def ca_path(config_dir):
    ca_path = config_dir / 'ca.pem'
    ca_path.write_text(u'test_ca_path')
    return str(ca_path)


@pytest.fixture(autouse=True)
def basic_config_dict(ssh_key_path, license_path):
    return {
        'ssh_key_path': ssh_key_path,
        'ssh_user': 'centos',
        'cloudify_license_path': license_path
    }


def _get_config_dict(config_file_name, basic_config_dict):
    resources_path = join(dirname(__file__), 'resources')
    completed_config_path = join(resources_path, config_file_name)
    with open(completed_config_path) as config_path:
        config_dict = yaml.load(config_path, yaml.Loader)

    config_dict.update(basic_config_dict)
    return config_dict


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


def test_validate_provided_paths(three_nodes_config_dict):
    # It's enough to test it only on the three nodes config, sice this section
    # is generic to all config files.
    three_nodes_config_dict.update({
        'ssh_key_path': '',
        'ssh_user': '',
        'cloudify_license_path': 'not_exist',
        'manager_rpm_download_link': ''
    })
    with pytest.raises(ClusterInstallError) as excinfo:
        validate_config(config=three_nodes_config_dict,
                        using_three_nodes_cluster=True,
                        override=False)

    assert all(path_key in str(excinfo.value) for path_key in
               ['ssh_key_path', 'ssh_user', 'cloudify_license_path',
                'manager_rpm_download_link'])


def test_validate_three_nodes_config_paths(three_nodes_config_dict):
    three_nodes_config_dict['existing_vms']['node-1']['config_path'][
        'manager_config_path'] = 'not_exist'
    three_nodes_config_dict['existing_vms']['node-2']['config_path'][
        'manager_config_path'] = 'not_exist'
    with pytest.raises(ClusterInstallError) as excinfo:
        validate_config(config=three_nodes_config_dict,
                        using_three_nodes_cluster=True,
                        override=False)

    assert ('You must provide the config.yaml file for all '
            'instances or none of them.' in str(excinfo.value))


def test_validate_nine_nodes_config_paths(nine_nodes_config_dict):
    nine_nodes_config_dict['existing_vms']['manager-1'][
        'config_path'] = 'not_exist'
    nine_nodes_config_dict['existing_vms']['manager-2'][
        'config_path'] = 'not_exist'

    with pytest.raises(ClusterInstallError) as excinfo:
        validate_config(config=nine_nodes_config_dict,
                        using_three_nodes_cluster=False,
                        override=False)

    assert ('You must provide the config.yaml file for all '
            'instances or none of them.' in str(excinfo.value))


def test_vms_not_duplicated(three_nodes_config_dict):
    # It's enough to test it only on the three nodes config, since the nine
    # nodes config uses the same logic.
    three_nodes_config_dict['existing_vms']['node-1']['private_ip'] = \
        three_nodes_config_dict['existing_vms']['node-2']['private_ip']
    with pytest.raises(ClusterInstallError) as excinfo:
        validate_config(config=three_nodes_config_dict,
                        using_three_nodes_cluster=True,
                        override=False)

    assert ('The private_ips of node-1 and node-2 are the same.'
            in str(excinfo.value))


def test_certificates_provided(config_dir, three_nodes_config_dict, ca_path):
    # It's enough to test it only on the three nodes config, since the nine
    # nodes config uses the same logic.
    three_nodes_config_dict['ca_cert_path'] = ca_path
    with pytest.raises(ClusterInstallError) as excinfo:
        validate_config(config=three_nodes_config_dict,
                        using_three_nodes_cluster=True,
                        override=False)

    for path_name in 'cert_path', 'key_path':
        for num in [1, 2, 3]:
            assert '{0} is not provided for instance node-{1}'.format(
                path_name, num) in str(excinfo.value)


def test_validate_external_db_paths(three_nodes_external_db_config_dict):
    # It's enough to test it only on the three nodes external db config,
    # since the nine nodes external db config uses the same logic.
    with pytest.raises(ClusterInstallError) as excinfo:
        validate_config(config=three_nodes_external_db_config_dict,
                        using_three_nodes_cluster=True,
                        override=False)

    external_db_keys = three_nodes_external_db_config_dict[
        'external_db_configuration'].keys()
    for path_key in external_db_keys:
        assert(path_key in str(excinfo.value))


def test_validate_ldaps_and_not_ca(three_nodes_config_dict):
    # It's enough to test it only on the three nodes external db config,
    # since the nine nodes external db config uses the same logic.
    three_nodes_config_dict['ldap']['server'] = 'ldaps://192.0.2.45:636'
    with pytest.raises(ClusterInstallError) as excinfo:
        validate_config(config=three_nodes_config_dict,
                        using_three_nodes_cluster=True,
                        override=False)

    assert('When using ldaps a CA certificate must be provided.'
           in str(excinfo.value))


def test_validate_not_ldaps_and_ca(three_nodes_config_dict, ca_path):
    # It's enough to test it only on the three nodes external db config,
    # since the nine nodes external db config uses the same logic.
    three_nodes_config_dict['ldap']['server'] = 'ldap://192.0.2.1:389'
    three_nodes_config_dict['ldap']['ca_cert'] = ca_path
    with pytest.raises(ClusterInstallError) as excinfo:
        validate_config(config=three_nodes_config_dict,
                        using_three_nodes_cluster=True,
                        override=False)

    assert('When not using ldaps a CA certificate must not be provided.'
           in str(excinfo.value))


def test_validate_ldaps_and_ca(three_nodes_config_dict, ca_path):
    # It's enough to test it only on the three nodes external db config,
    # since the nine nodes external db config uses the same logic.
    three_nodes_config_dict['ldap']['server'] = 'ldaps://192.0.2.45:636'
    three_nodes_config_dict['ldap']['ca_cert'] = ca_path
    validate_config(config=three_nodes_config_dict,
                    using_three_nodes_cluster=True,
                    override=False)
