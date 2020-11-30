import pytest

from cfy_cluster_manager.main import validate_config
from cfy_cluster_manager.utils import ClusterInstallError


def test_validate_provided_paths(three_nodes_config_dict):
    # It's enough to test it only on the three nodes config, since this section
    # is generic to all config files.
    three_nodes_config_dict.update({
        'ssh_key_path': '',
        'ssh_user': '',
        'cloudify_license_path': 'not_exist',
        'manager_rpm_path': ''
    })
    with pytest.raises(ClusterInstallError) as excinfo:
        validate_config(config=three_nodes_config_dict,
                        using_three_nodes_cluster=True,
                        override=False)

    assert all(path_key in str(excinfo.value) for path_key in
               ['ssh_key_path', 'ssh_user', 'cloudify_license_path',
                'manager_rpm_path'])


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
    with pytest.raises(ClusterInstallError,
                       match='.*private_ips.*node-1.*node-2.*same.*'):
        validate_config(config=three_nodes_config_dict,
                        using_three_nodes_cluster=True,
                        override=False)


def test_certificates_provided(three_nodes_config_dict, ca_path):
    # It's enough to test it only on the three nodes config, since the nine
    # nodes config uses the same logic.
    three_nodes_config_dict['ca_cert_path'] = ca_path
    with pytest.raises(ClusterInstallError) as excinfo:
        validate_config(config=three_nodes_config_dict,
                        using_three_nodes_cluster=True,
                        override=False)

    for path_name in 'cert_path', 'key_path':
        for num in [1, 2, 3]:
            assert excinfo.match('.*{0}.*not provided.*node-{1}.*'.format(
                path_name, num))


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
        assert excinfo.match('.*{0}.*'.format(path_key))


def test_validate_success_external_db(three_nodes_external_db_config_dict,
                                      external_db_ca_path):
    # It's enough to test it only on the three nodes external db config,
    # since the nine nodes external db config uses the same logic.
    three_nodes_external_db_config_dict['external_db_configuration'] = {
        'host': 'user.postgres.database.azure.com',
        'ca_path': external_db_ca_path,
        'server_db_name': 'postgres',
        'server_username': 'user@user',
        'server_password': 'strongpassword',
        'cloudify_db_name': 'cloudify_db',
        'cloudify_username': 'cloudify@user',
        'cloudify_password': 'cloudify'
    }
    validate_config(config=three_nodes_external_db_config_dict,
                    using_three_nodes_cluster=True,
                    override=False)


def test_validate_ldaps_and_not_ca(three_nodes_config_dict):
    # It's enough to test it only on the three nodes external db config,
    # since the nine nodes external db config uses the same logic.
    three_nodes_config_dict['ldap']['server'] = 'ldaps://192.0.2.45:636'
    with pytest.raises(ClusterInstallError,
                       match='.*ldaps.*certificate must be provided.*'):
        validate_config(config=three_nodes_config_dict,
                        using_three_nodes_cluster=True,
                        override=False)


def test_validate_not_ldaps_and_ca(three_nodes_config_dict, ca_path):
    # It's enough to test it only on the three nodes external db config,
    # since the nine nodes external db config uses the same logic.
    three_nodes_config_dict['ldap']['server'] = 'ldap://192.0.2.1:389'
    three_nodes_config_dict['ldap']['ca_cert'] = ca_path
    with pytest.raises(
            ClusterInstallError,
            match='.*not using ldaps.*certificate must not be provided.*'):
        validate_config(config=three_nodes_config_dict,
                        using_three_nodes_cluster=True,
                        override=False)


def test_validate_ldaps_and_ca(three_nodes_config_dict, ca_path):
    # It's enough to test it only on the three nodes external db config,
    # since the nine nodes external db config uses the same logic.
    three_nodes_config_dict['ldap']['server'] = 'ldaps://192.0.2.45:636'
    three_nodes_config_dict['ldap']['ca_cert'] = ca_path
    validate_config(config=three_nodes_config_dict,
                    using_three_nodes_cluster=True,
                    override=False)


def test_config_files_and_certificates(three_nodes_config_dict,
                                       tmp_certs_dir,
                                       tmp_config_files_dir):
    """
    Tests the validation that if config files were provided,
    no certificates were provided also.
    """
    for i in range(1, 4):
        node_name = 'node-{0}'.format(i)
        config_file = tmp_config_files_dir / node_name
        config_file.write_text(u'{0}'.format(node_name))
        for service in 'manager', 'postgresql', 'rabbitmq':
            three_nodes_config_dict['existing_vms'][node_name]['config_path'][
                service+'_config_path'] = str(config_file)

    cert_path = tmp_certs_dir / 'node-1_cert.pem'
    cert_path.write_text(u'node-1_cert')
    three_nodes_config_dict['existing_vms']['node-1']['cert_path'] = \
        str(cert_path)

    with pytest.raises(ClusterInstallError,
                       match='.*Certificate can not be specified.*config '
                             'path was specified.*'):
        validate_config(config=three_nodes_config_dict,
                        using_three_nodes_cluster=True,
                        override=False)


def test_ssh_password_key_path_mutually_exc(three_nodes_config_dict):
    validate_config(config=three_nodes_config_dict,
                    using_three_nodes_cluster=True,
                    override=False)

    three_nodes_config_dict['ssh_password'] = 'test'
    with pytest.raises(ClusterInstallError, match='.*only one of.*'):
        validate_config(config=three_nodes_config_dict,
                        using_three_nodes_cluster=True,
                        override=False)

    three_nodes_config_dict.pop('ssh_key_path')
    validate_config(config=three_nodes_config_dict,
                    using_three_nodes_cluster=True,
                    override=False)

    three_nodes_config_dict.pop('ssh_password')
    with pytest.raises(ClusterInstallError, match='.*only one of.*'):
        validate_config(config=three_nodes_config_dict,
                        using_three_nodes_cluster=True,
                        override=False)
