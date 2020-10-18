import copy
import mock
import filecmp

import yaml
import pytest

import cfy_cluster_manager
from cfy_cluster_manager.main import (_generate_general_cluster_dict,
                                      _generate_three_nodes_cluster_dict,
                                      _handle_certificates,
                                      _populate_credentials,
                                      _prepare_config_files)


@pytest.fixture(autouse=True)
def mock_test_connection():
    cfy_cluster_manager.main.CfyNode.test_connection = mock.Mock(
        return_value=None)


@pytest.fixture(autouse=True)
def mock_generate_certs():
    cfy_cluster_manager.main._generate_certs = mock.Mock(return_value=None)


@pytest.fixture()
def cluster_manager_certs_dir(cluster_manager_dir):
    return cluster_manager_dir / cfy_cluster_manager.main.CERTS_DIR_NAME


@pytest.fixture()
def config_files_dir(cluster_manager_dir):
    return cluster_manager_dir / cfy_cluster_manager.main.CONFIG_FILES


def test_three_nodes_using_provided_certificates(three_nodes_config_dict,
                                                 cluster_manager_certs_dir,
                                                 tmp_certs_dir,
                                                 ca_path):
    """Testing if the install code uses the provided certificates.

    In case certificates were provided for all existing_vms, the install code
    would copy the certificates to the CERTS_DIR with their appropriate name.
    This test verifies this behavior for the three nodes cluster use case.
    """
    three_nodes_config_dict['ca_cert_path'] = ca_path
    for node_name, node_dict in three_nodes_config_dict[
            'existing_vms'].items():
        node_num = node_name.split('-')[1]
        for service in 'postgresql', 'rabbitmq', 'manager':
            cert_path = (tmp_certs_dir /
                         '{0}-{1}_{2}.pem'.format(service, node_num, 'cert'))
            key_path = (tmp_certs_dir /
                        '{0}-{1}_{2}.pem'.format(service, node_num, 'key'))
            cert_path.write_text(u'manager-{0}_{1}'.format(node_num, 'cert'))
            key_path.write_text(u'manager-{0}_{1}'.format(node_num, 'key'))

        node_dict['cert_path'] = str(cert_path)
        node_dict['key_path'] = str(key_path)

    with mock.patch('cfy_cluster_manager.main.CERTS_DIR',
                    str(cluster_manager_certs_dir)):
        _generate_three_nodes_cluster_dict(three_nodes_config_dict)

    with mock.patch('cfy_cluster_manager.main.CA_PATH',
                    str(cluster_manager_certs_dir / 'ca.pem')):
        _handle_certificates(three_nodes_config_dict, None)

    _assert_created_certs(tmp_certs_dir, cluster_manager_certs_dir)


def test_nine_nodes_using_provided_certificates(nine_nodes_config_dict,
                                                cluster_manager_certs_dir,
                                                tmp_certs_dir,
                                                ca_path):
    """Testing if the install code uses the provided certificates.

    In case certificates were provided for all existing_vms, the install code
    would copy the certificates to the CERTS_DIR with their appropriate name.
    This test verifies this behavior for the nine nodes cluster use case.
    """
    nine_nodes_config_dict['ca_cert_path'] = ca_path
    for node_name, node_dict in nine_nodes_config_dict['existing_vms'].items():
        for val in 'key', 'cert':
            val_path = tmp_certs_dir / '{0}_{1}.pem'.format(node_name, val)
            val_path.write_text(u'{0}_{1}'.format(node_name, val))
            node_dict['{0}_path'.format(val)] = str(val_path)

    with mock.patch('cfy_cluster_manager.main.CERTS_DIR',
                    str(cluster_manager_certs_dir)):
        _generate_general_cluster_dict(nine_nodes_config_dict)

    with mock.patch('cfy_cluster_manager.main.CA_PATH',
                    str(cluster_manager_certs_dir / 'ca.pem')):
        _handle_certificates(nine_nodes_config_dict, None)

    _assert_created_certs(tmp_certs_dir, cluster_manager_certs_dir)


def test_credentials_randomly_generated(three_nodes_config_dict):
    """Test if the credentials are randomly generated and populated.

    In order to test this, we first set the value of arbitrary keys to a
    fixed value. Then, we test if these keys kept their value and if all other
    values were populated.
    """
    # In this case, The three nodes and nine nodes logic is the same
    fixed_value = 'fixed_value'
    chosen_keys = [
        ('rabbitmq', 'username'),
        ('postgresql', 'cluster', 'etcd', 'cluster_token'),
        ('postgresql', 'db_monitoring', 'username'),
        ('prometheus', 'password')
    ]
    credentials_dict = three_nodes_config_dict.get('credentials')
    _iterate_nested_dict(credentials_dict, chosen_keys, fixed_value)
    _populate_credentials(credentials_dict)
    _assert_dict_values_not_none(credentials_dict)
    _iterate_nested_dict(credentials_dict, chosen_keys, fixed_value, True)


def test_config_files_credentials(three_nodes_config_dict, config_files_dir):
    """Test the credentials in the config files are populated correctly."""
    # In this case, The three nodes and nine nodes logic is the same
    credentials_dict = three_nodes_config_dict.get('credentials')
    _populate_credentials(credentials_dict)
    _create_config_files(three_nodes_config_dict, config_files_dir,
                         credentials_dict)
    _assert_manager_config_credentials(config_files_dir, credentials_dict)
    _assert_postgresql_config_credentials(config_files_dir, credentials_dict)
    _assert_rabbitmq_config_credentials(config_files_dir, credentials_dict)


def test_ldap_in_config_file(three_nodes_config_dict,
                             config_files_dir,
                             ldap_ca_path,
                             tmp_certs_dir,
                             cluster_manager_certs_dir):
    """Test if LDAP is configured properly in the manager config.yaml file."""
    # In this case, The three nodes and nine nodes logic is the same
    cluster_manager_ldap_ca = str(cluster_manager_certs_dir / 'ldap_ca.pem')
    ldap_dict = {
        'server': 'ldaps://192.0.2.12',
        'domain': 'test_domain',
        'is_active_directory': True,
        'ca_cert': ldap_ca_path,
        'username': 'test_username',
        'password': 'test_password',
        'dn_extra': 'test_dn_extra'
    }
    three_nodes_config_dict.update({'ldap': copy.deepcopy(ldap_dict)})

    with mock.patch('cfy_cluster_manager.main.LDAP_CA_PATH',
                    cluster_manager_ldap_ca):
        _handle_certificates(three_nodes_config_dict, None)
        _create_config_files(three_nodes_config_dict, config_files_dir)
    manager_config = _get_instance_config('manager', config_files_dir)

    ldap_dict['ca_cert'] = cluster_manager_ldap_ca
    assert manager_config['restservice']['ldap'] == ldap_dict
    _assert_created_certs(tmp_certs_dir, cluster_manager_certs_dir)


def test_extrnal_db_in_config_file(three_nodes_external_db_config_dict,
                                   config_files_dir,
                                   external_db_ca_path,
                                   tmp_certs_dir,
                                   cluster_manager_certs_dir):
    """
    Test if the external_db is configured properly in the manager
    config.yaml file.
    """
    # In this case, The three nodes and nine nodes logic is the same
    cluster_manager_external_db_ca = str(
        cluster_manager_certs_dir / 'external_db_ca.pem')
    external_db_config = {
        'host': 'user.postgres.database.azure.example',
        'ca_path': external_db_ca_path,
        'server_db_name': 'postgres',
        'server_username': 'user@user',
        'server_password': 'strongpassword',
        'cloudify_db_name': 'cloudify_db',
        'cloudify_username': 'cloudify@user',
        'cloudify_password': 'cloudify'
    }
    three_nodes_external_db_config_dict.update(
        {'external_db_configuration': copy.deepcopy(external_db_config)})

    with mock.patch('cfy_cluster_manager.main.EXTERNAL_DB_CA_PATH',
                    cluster_manager_external_db_ca):
        _handle_certificates(three_nodes_external_db_config_dict, None)
        _create_config_files(three_nodes_external_db_config_dict,
                             config_files_dir)
    manager_config = _get_instance_config('manager', config_files_dir)

    external_db_config.update({'ssl_client_verification': False,
                               'ca_path': cluster_manager_external_db_ca})
    assert manager_config['postgresql_client'] == external_db_config
    _assert_created_certs(tmp_certs_dir, cluster_manager_certs_dir)


def _assert_manager_config_credentials(config_files_dir, credentials):
    manager_config = _get_instance_config('manager', config_files_dir)

    assert (manager_config['manager']['security']['admin_username'] ==
            credentials['manager']['admin_username'])

    assert (manager_config['manager']['security']['admin_password'] ==
            credentials['manager']['admin_password'])

    assert (manager_config['postgresql_server']['postgres_password'] ==
            credentials['postgresql']['postgres_password'])

    assert (manager_config['rabbitmq']['username'] ==
            credentials['rabbitmq']['username'])

    assert (manager_config['rabbitmq']['password'] ==
            credentials['rabbitmq']['password'])

    assert (manager_config['prometheus']['credentials']['username'] ==
            credentials['prometheus']['username'])

    assert (manager_config['prometheus']['credentials']['password'] ==
            credentials['prometheus']['password'])


def _assert_postgresql_config_credentials(config_files_dir, credentials):
    postgresql_config = _get_instance_config('postgresql', config_files_dir)

    assert (postgresql_config['postgresql_server']['postgres_password'] ==
            credentials['postgresql']['postgres_password'])

    assert (credentials['postgresql']['cluster'].items() <=
            postgresql_config['postgresql_server']['cluster'].items())

    assert (credentials['postgresql']['db_monitoring'].items() <=
            postgresql_config['postgresql_server']['db_monitoring'].items())

    assert (postgresql_config['prometheus']['credentials']['username'] ==
            credentials['prometheus']['username'])

    assert (postgresql_config['prometheus']['credentials']['password'] ==
            credentials['prometheus']['password'])


def _assert_rabbitmq_config_credentials(config_files_dir, credentials):
    rabbitmq_config = _get_instance_config('rabbitmq', config_files_dir)

    assert (rabbitmq_config['rabbitmq']['username'] ==
            credentials['rabbitmq']['username'])

    assert (rabbitmq_config['rabbitmq']['password'] ==
            credentials['rabbitmq']['password'])

    assert (rabbitmq_config['prometheus']['credentials']['username'] ==
            credentials['prometheus']['username'])

    assert (rabbitmq_config['prometheus']['credentials']['password'] ==
            credentials['prometheus']['password'])


def _get_instance_config(instance, config_files_dir):
    with open(
            str(config_files_dir / '{}-1_config.yaml'.format(instance)), 'r') \
            as instance_config:
        return yaml.load(instance_config, yaml.Loader)


def _create_config_files(config_dict, config_files_dir, credentials=None):
    if not credentials:
        credentials = config_dict.get('credentials')
        _populate_credentials(credentials)
    instnaces_dict = _generate_three_nodes_cluster_dict(config_dict)
    with mock.patch('cfy_cluster_manager.main.CONFIG_FILES_DIR',
                    str(config_files_dir)):
        _prepare_config_files(instnaces_dict, credentials, config_dict)


def _iterate_nested_dict(original_dict,
                         keys_tuples_list,
                         fixed_value,
                         test=False):
    tmp_dict = original_dict
    for keys_tuple in keys_tuples_list:
        for i, key in enumerate(keys_tuple):
            if i + 1 < len(keys_tuple):
                tmp_dict = tmp_dict[key]
            else:
                if test:
                    assert tmp_dict[key] == fixed_value
                else:
                    tmp_dict[key] = fixed_value
        tmp_dict = original_dict


def _assert_dict_values_not_none(tested_dict):
    for key, value in tested_dict.items():
        if isinstance(value, dict):
            _assert_dict_values_not_none(value)
        else:
            assert value is not None


def _assert_created_certs(tmp_certs_dir, cluster_manager_certs_dir):
    for original_path in tmp_certs_dir.iterdir():
        tested_path = cluster_manager_certs_dir / original_path.name
        assert filecmp.cmp(str(original_path), str(tested_path))
