import os
import sys
import time
import shutil
import string
import random
import argparse
from getpass import getuser
from traceback import format_exception
from collections import OrderedDict
from os.path import exists, expanduser, isdir, join

import pkg_resources
from jinja2 import Environment, FileSystemLoader

from .logger import get_cfy_cluster_manager_logger, setup_logger
from .utils import (check_cert_key_match, check_cert_path, check_san,
                    check_signed_by, cloudify_rpm_is_installed,
                    ClusterInstallError, copy, get_dict_from_yaml, move,
                    raise_errors_list, run, sudo, VM,
                    write_dict_to_yaml_file, yum_is_present)

logger = get_cfy_cluster_manager_logger()

CERTS_DIR_NAME = 'certs'
CFY_CERTS_PATH = '{0}/.cloudify-test-ca'.format(expanduser('~'))
CONFIG_FILES = 'config_files'
DIR_NAME = 'cloudify_cluster_manager'
RPM_NAME = 'cloudify-manager-install.rpm'
UPGRADE_RPM_NAME = 'upgrade-cloudify-manager-install'
TOP_DIR = '/tmp'

CLUSTER_INSTALL_DIR = join(TOP_DIR, DIR_NAME)
RPM_PATH = join(CLUSTER_INSTALL_DIR, RPM_NAME)
CERTS_DIR = join(CLUSTER_INSTALL_DIR, CERTS_DIR_NAME)
CONFIG_FILES_DIR = join(CLUSTER_INSTALL_DIR, CONFIG_FILES)

CA_PATH = join(CERTS_DIR, 'ca.pem')
CA_KEY_PATH = join(CERTS_DIR, 'ca.key')
EXTERNAL_DB_CA_PATH = join(CERTS_DIR, 'external_db_ca.pem')
LDAP_CA_PATH = join(CERTS_DIR, 'ldap_ca.pem')

CREDENTIALS_FILE_PATH = join(os.getcwd(), 'secret_credentials.yaml')
CLUSTER_CONFIG_FILES_DIR = pkg_resources.resource_filename(
    'cfy_cluster_manager', 'cfy_cluster_config_files')
CLUSTER_CONFIG_FILE_NAME = 'cfy_cluster_config.yaml'
CLUSTER_INSTALL_CONFIG_PATH = join(os.getcwd(), CLUSTER_CONFIG_FILE_NAME)

SYSTEMD_RUN_UNIT_NAME = 'cfy_cluster_manager_{}'
BASE_CFY_DIR = '/etc/cloudify/'
INITIAL_INSTALL_DIR = join(BASE_CFY_DIR, '.installed')

DEFAULT_RPM = 'https://repository.cloudifysource.org/cloudify/5.2.1/ga-release/cloudify-manager-install-5.2.1-ga.el7.x86_64.rpm'  # NOQA


class CfyNode(VM):
    def __init__(self,
                 private_ip,
                 public_ip,
                 key_file_path,
                 username,
                 password,
                 node_name,
                 hostname,
                 cert_path,
                 key_path,
                 config_file_path):
        super(CfyNode, self).__init__(private_ip, public_ip,
                                      key_file_path, username, password)
        self.name = node_name
        self.hostname = hostname
        self.provided_cert_path = expanduser(cert_path) if cert_path else None
        self.provided_key_path = expanduser(key_path) if key_path else None
        self.cert_path = join(CERTS_DIR, node_name + '_cert.pem')
        self.key_path = join(CERTS_DIR, node_name + '_key.pem')
        self.type, self.number = node_name.split('-')
        self.installed = False
        self.provided_config_path = (expanduser(config_file_path) if
                                     config_file_path else None)
        self.config_path = join(
            BASE_CFY_DIR, '{}_config.yaml'.format(node_name))
        self.unit_name = SYSTEMD_RUN_UNIT_NAME.format(self.type)

    def get_version(self):
        # You need to verify cloudify-manager-install is installed
        cfy_version_res = self.run_command(
            'rpm --queryformat "%{VERSION}" -q cloudify-manager-install',
            hide_stdout=True)
        return cfy_version_res.stdout


def _exception_handler(type_, value, traceback):
    error = type_.__name__
    if str(value):
        error = '{0}: {1}'.format(error, str(value))
    logger.error(error)
    debug_traceback = ''.join(format_exception(type_, value, traceback))
    logger.debug(debug_traceback)


sys.excepthook = _exception_handler


def _generate_instance_certificate(instance):
    run(['cfy_manager', 'generate-test-cert', '-s',
         instance.private_ip + ',' + instance.public_ip])
    move(join(CFY_CERTS_PATH, instance.private_ip + '.crt'),
         join(CFY_CERTS_PATH, instance.name + '_cert.pem'))
    new_key_path = join(CFY_CERTS_PATH, instance.name + '_key.pem')
    move(join(CFY_CERTS_PATH, instance.private_ip + '.key'), new_key_path)
    sudo(['chmod', '444', new_key_path])


def _generate_certs(instances_dict):
    logger.info('Generating certificates')
    for instances_list in instances_dict.values():
        for instance in instances_list:
            _generate_instance_certificate(instance)
    copy(join(CFY_CERTS_PATH, 'ca.crt'), join(CFY_CERTS_PATH, 'ca.pem'))
    if not exists(CERTS_DIR):
        os.mkdir(CERTS_DIR)
    copy(join(CFY_CERTS_PATH, '.'), CERTS_DIR)
    shutil.rmtree(CFY_CERTS_PATH)


def _get_postgresql_cluster_members(postgresql_instances):
    return {
        postgresql_instance.name:
            {'ip': postgresql_instance.private_ip}
        for postgresql_instance in postgresql_instances
    }


def _get_rabbitmq_cluster_members(rabbitmq_instances, load_balance_ip):
    return {
        rabbitmq_instance.name: {
            'networks':
                ({'default': rabbitmq_instance.private_ip,
                  'load_balancer': load_balance_ip} if load_balance_ip else
                 {'default': rabbitmq_instance.private_ip})
        } for rabbitmq_instance in rabbitmq_instances
    }


def _prepare_postgresql_config_files(template,
                                     postgresql_instances,
                                     credentials):
    logger.info('Preparing PostgreSQL config files')
    postgresql_cluster = _get_postgresql_cluster_members(postgresql_instances)
    for node in postgresql_instances:
        if node.provided_config_path:
            _create_config_file(node)
            continue
        rendered_data = template.render(node=node,
                                        creds=credentials,
                                        ca_path=CA_PATH,
                                        postgresql_cluster=postgresql_cluster)
        _create_config_file(node, rendered_data)


def _prepare_rabbitmq_config_files(template,
                                   rabbitmq_instances,
                                   credentials,
                                   load_balancer_ip):
    logger.info('Preparing RabbitMQ config files')
    rabbitmq_cluster = _get_rabbitmq_cluster_members(
        rabbitmq_instances, load_balancer_ip)
    for i, node in enumerate(rabbitmq_instances):
        if node.provided_config_path:
            _create_config_file(node)
            continue
        join_cluster = rabbitmq_instances[0].name if i > 0 else None
        rendered_data = template.render(node=node,
                                        creds=credentials,
                                        ca_path=CA_PATH,
                                        join_cluster=join_cluster,
                                        rabbitmq_cluster=rabbitmq_cluster,
                                        load_balancer_ip=load_balancer_ip)
        _create_config_file(node, rendered_data)


def _prepare_manager_config_files(template,
                                  instances_dict,
                                  credentials,
                                  load_balancer_ip,
                                  external_db_config,
                                  ldap_configuration,
                                  ssl_enabled):
    logger.info('Preparing Manager config files')
    if external_db_config:
        external_db_config.update({'ssl_client_verification': False,
                                   'ca_path': EXTERNAL_DB_CA_PATH})
    if ldap_configuration:
        ldap_configuration.update({'ca_cert': LDAP_CA_PATH})

    for node in instances_dict['manager']:
        if node.provided_config_path:
            _create_config_file(node)
            continue
        rendered_data = template.render(
            node=node,
            creds=credentials,
            ca_path=CA_PATH,
            ca_key_path=CA_KEY_PATH,
            license_path=join(CLUSTER_INSTALL_DIR, 'license.yaml'),
            load_balancer_ip=load_balancer_ip,
            rabbitmq_cluster=_get_rabbitmq_cluster_members(
                instances_dict['rabbitmq'], load_balancer_ip),
            postgresql_cluster={} if external_db_config else
            _get_postgresql_cluster_members(instances_dict['postgresql']),
            external_db_configuration=external_db_config,
            ldap_configuration=ldap_configuration,
            ssl_enabled=ssl_enabled
        )

        _create_config_file(node, rendered_data)


def _create_config_file(node, rendered_data=None):
    config_path = join(CONFIG_FILES_DIR, '{0}_config.yaml'.format(node.name))
    if rendered_data:
        with open(config_path, 'w') as config_file:
            config_file.write(rendered_data)
    else:
        copy(node.provided_config_path, config_path)


def _prepare_config_files(instances_dict, credentials, config):
    os.mkdir(CONFIG_FILES_DIR)
    templates_env = Environment(
        loader=FileSystemLoader(pkg_resources.resource_filename(
            'cfy_cluster_manager', 'config_files_templates')))
    raw_ldap_configuration = config.get('ldap', {})
    ldap_configuration = (raw_ldap_configuration if
                          raw_ldap_configuration.get('server') else None)

    external_db_config = _get_external_db_config(config)
    if not external_db_config:
        _prepare_postgresql_config_files(
            templates_env.get_template('postgresql_config.yaml'),
            instances_dict['postgresql'],
            credentials)

    _prepare_rabbitmq_config_files(
        templates_env.get_template('rabbitmq_config.yaml'),
        instances_dict['rabbitmq'],
        credentials,
        config.get('load_balancer_ip'))

    _prepare_manager_config_files(
        templates_env.get_template('manager_config.yaml'),
        instances_dict,
        credentials,
        config.get('load_balancer_ip'),
        external_db_config,
        ldap_configuration,
        config.get('ssl_enabled', True)
    )


def _install_cloudify_remotely(instance):
    logger.info('Installing Cloudify RPM on %s', instance.name)
    instance.run_command(
        'yum install -y {}'.format(RPM_PATH), use_sudo=True, hide_stdout=True)


def _get_service_status_code(instance):
    """Checking the status code of the cfy_manager_install_<type> service."""
    result = instance.run_command(
        'systemctl status {}'.format(instance.unit_name),
        use_sudo=True, hide_stdout=True, ignore_failure=True)
    return result.return_code


def _wait_for_cloudify_current_installation(instance):
    logger.info(
        'Waiting for current installation of %s to finish', instance.name)
    status_code = 0
    retry_count = 0
    while status_code == 0 and retry_count <= 600:
        if retry_count % 20 == 0:
            logger.info('Waiting for current installation of %s to finish',
                        instance.name)
        time.sleep(1)
        retry_count += 1
        status_code = _get_service_status_code(instance)

    if retry_count > 600:
        raise ClusterInstallError(
            'Got a time out while waiting for the current installation of '
            '%s to finish', instance.name)


def _rpm_was_installed(instance):
    logger.debug(
        'Checking if Cloudify RPM was installed on %s', instance.private_ip)
    result = instance.run_command('rpm -qi cloudify-manager-install',
                                  hide_stdout=True, ignore_failure=True)

    return not result.failed


def _verify_service_installed(instance):
    """Checking if the instance type .installed file was created."""
    logger.info('Verifying that %s (%s) was installed successfully',
                instance.name, instance.private_ip)
    names_mapping = {'postgresql': 'database_service',
                     'rabbitmq': 'queue_service',
                     'manager': 'manager_service'}
    return instance.file_exists(
        join(INITIAL_INSTALL_DIR, names_mapping[instance.type]))


def _cloudify_was_previously_installed_successfully(instance):
    """Checking if the previous installation finished successfully.

    We can check if the previous installation of Cloudify on this instance
    finished successfully by inspecting the status of the
    `cfy_manager_install_<type>` service:
        status_code == 0: The `cfy_manager install` command is currently
                          running on the instance, so we need to wait until
                          it finishes, and then check if it succeeded.
        status_code == 3: The service failed, so we need to remove it
                          and return False.
        status_code == 4: The service is not present. It can be either
                          because the installation finished successfully
                          or because it was never running. This is checked by
                          `_verify_service_installed`.
        Any other code is not being taken care of.
    """
    status_code = _get_service_status_code(instance)
    if status_code == 0:
        _wait_for_cloudify_current_installation(instance)
        return _verify_cloudify_installed_successfully(instance)
    elif status_code == 3:
        instance.run_command(
            'systemctl reset-failed {}'.format(instance.unit_name),
            use_sudo=True, hide_stdout=True)
        return False
    elif status_code == 4:
        return _verify_service_installed(instance)
    else:
        raise ClusterInstallError(
            'Service {} status is unknown'.format(instance.unit_name))


def _verify_cloudify_installed_successfully(instance):
    status_code = _get_service_status_code(instance)
    if status_code == 3:
        raise ClusterInstallError(
            'Failed installing Cloudify on instance {}.'.format(
                instance.private_ip))
    elif status_code == 4:
        return _verify_service_installed(instance)
    else:
        raise ClusterInstallError(
            'Service {} status is unknown'.format(instance.unit_name))


def _install_instances(instances_dict, verbose):
    for i, instance_type in enumerate(instances_dict):
        logger.info('installing %s instances', instance_type)
        for instance in instances_dict[instance_type]:
            if instance.installed:
                logger.info('Already installed %s (%s)',
                            instance.name, instance.private_ip)
                continue

            logger.info('Installing %s', instance.name)
            instance.put_dir(CLUSTER_INSTALL_DIR, CLUSTER_INSTALL_DIR)

            if not _rpm_was_installed(instance):
                _install_cloudify_remotely(instance)

            instance.run_command('cp {0} {1}'.format(
                join(CONFIG_FILES_DIR, '{}_config.yaml'.format(instance.name)),
                instance.config_path), use_sudo=True)

            install_cmd = (
                'systemd-run -t --unit {unit_name} --uid {user_name} '
                'cfy_manager install -c {config} {verbose}'.format(
                    config=instance.config_path, unit_name=instance.unit_name,
                    user_name=getuser(), verbose='-v' if verbose else ''))

            instance.run_command(install_cmd, use_sudo=True)
            _verify_cloudify_installed_successfully(instance)
            instance.run_command('cp {0} {1}'.format(
                '/etc/cloudify/config.yaml', instance.config_path),
                use_sudo=True)


def _sort_instances_dict(instances_dict):
    for _, instance_items in instances_dict.items():
        if len(instance_items) > 1:
            instance_items.sort(key=lambda x: int(x.name.rsplit('-', 1)[1]))


def _using_provided_certificates(config):
    return config.get('ca_cert_path')


def _get_external_db_config(config):
    return config.get('external_db_configuration')


def _get_cfy_node(config, node_dict, node_name, config_path,
                  validate_connection=True):
    new_vm = CfyNode(node_dict.get('private_ip'),
                     node_dict.get('public_ip'),
                     config.get('ssh_key_path'),
                     config.get('ssh_user'),
                     config.get('ssh_password'),
                     node_name,
                     node_dict.get('hostname'),
                     cert_path=node_dict.get('cert_path'),
                     key_path=node_dict.get('key_path'),
                     config_file_path=config_path)
    if validate_connection:
        logger.debug('Testing connection to %s', new_vm.private_ip)
        new_vm.test_connection()

    return new_vm


def _get_instances_ordered_dict(config):
    """Return the instances ordered dictionary template.

    After being filled by `_generate_three_nodes_cluster_dict` or
    `_generate_general_cluster_dict`, the instances ordered dictionary
    will have the following form:
        (('postgresql': [postgresql-1, postgresql-2, postgresql-3]),
         ('rabbitmq': [rabbitmq-1, rabbitmq-2, rabbitmq-3]),
         ('manager': [manager-1, manager-2, manager-3]))
    If using an external DB, the 'postgresql' key is popped.
    """
    instances_dict = OrderedDict(
        (('postgresql', []), ('rabbitmq', []), ('manager', [])))
    if _get_external_db_config(config):
        instances_dict.pop('postgresql')
    return instances_dict


def _generate_three_nodes_cluster_dict(config):
    """Going over the existing_vms list and "replicating" each instance X3."""
    instances_dict = _get_instances_ordered_dict(config)
    raw_existing_nodes_list = sorted(config.get('existing_vms').items(),
                                     key=lambda x: x[0])
    existing_nodes_list = [node[1] for node in raw_existing_nodes_list]
    validate_connection = True
    for node_type in instances_dict:
        for i, node_dict in enumerate(existing_nodes_list):
            new_vm = _get_cfy_node(config,
                                   node_dict,
                                   node_name=(node_type + '-' + str(i + 1)),
                                   config_path=node_dict['config_path'].get(
                                       node_type + '_config_path'),
                                   validate_connection=validate_connection)
            instances_dict[node_type].append(new_vm)
        validate_connection = False
    return instances_dict


def _generate_general_cluster_dict(config):
    instances_dict = _get_instances_ordered_dict(config)
    for node_name, node_dict in config.get('existing_vms').items():
        new_vm = _get_cfy_node(config, node_dict, node_name,
                               node_dict.get('config_path'))
        instances_dict[new_vm.type].append(new_vm)

    _sort_instances_dict(instances_dict)
    return instances_dict


def _create_cluster_install_directory():
    logger.info('Creating `{0}` directory'.format(DIR_NAME))
    if exists(CLUSTER_INSTALL_DIR):
        new_dirname = (time.strftime('%Y%m%d-%H%M%S_') + DIR_NAME)
        move(CLUSTER_INSTALL_DIR, join(TOP_DIR, new_dirname))

    os.mkdir(CLUSTER_INSTALL_DIR)


def _random_credential_generator():
    return ''.join(random.choice(string.ascii_lowercase + string.digits)
                   for _ in range(40))


def _populate_credentials(credentials):
    """Generating random credentials for the ones that weren't provided."""
    for key, value in credentials.items():
        if isinstance(value, dict):
            _populate_credentials(value)
        else:
            if not value:
                credentials[key] = _random_credential_generator()


def _handle_credentials(credentials):
    _populate_credentials(credentials)
    write_dict_to_yaml_file(credentials, CREDENTIALS_FILE_PATH)
    return credentials


def _log_managers_connection_strings(manager_nodes):
    managers_str = ''
    for manager in manager_nodes:
        managers_str += '{0}: {1}@{2}\n'.format(manager.name,
                                                manager.username,
                                                manager.public_ip)
    logger.info('In order to connect to one of the managers, use one of the '
                'following connection strings:\n%s', managers_str)


def _print_success_message(start_time, msg='installed'):
    running_time = time.time() - start_time
    m, s = divmod(running_time, 60)
    logger.info('Cloudify cluster was successfully {0} in '
                '{1} minutes and {2} seconds'.format(msg, int(m), int(s)))
    if msg != 'removed':
        logger.info(
            'Please run `cfy cluster status` to verify the cluster status '
            'is healthy. It might take up to a minute for it to stabilize')


def _install_cloudify_locally(rpm_path):
    if cloudify_rpm_is_installed():
        logger.info('Cloudify RPM is already installed')
    expanded_rpm_path = expanduser(rpm_path)
    if exists(expanded_rpm_path):
        copy(expanded_rpm_path, RPM_PATH)
    else:
        logger.info('Downloading Cloudify RPM from %s', rpm_path)
        run(['curl', '-o', RPM_PATH, rpm_path])

    logger.info('Installing Cloudify RPM')
    sudo(['yum', 'install', '-y', RPM_PATH])


def _check_path(dictionary, key, errors_list, vm_name=None):
    if _check_value_provided(dictionary, key, errors_list, vm_name):
        expanded_path = expanduser(dictionary.get(key))
        if not exists(expanded_path):
            suffix = ' for instance {0}'.format(vm_name) if vm_name else ''
            errors_list.append('Path {0} for key {1} does not '
                               'exist{2}'.format(expanded_path, key, suffix))
            return False

        dictionary[key] = expanded_path
        return True

    return False


def _check_value_provided(dictionary, key, errors_list, vm_name=None):
    if not dictionary.get(key):
        suffix = ' for instance {0}'.format(vm_name) if vm_name else ''
        errors_list.append('{0} is not provided{1}'.format(key, suffix))
        return False
    return True


def _validate_config_path(vm_name, config_path, errors_list):
    expanded_path = expanduser(config_path)
    if exists(expanded_path):
        return expanded_path
    else:
        errors_list.append('The config path {0} of {1} does not '
                           'exist.'.format(expanded_path, vm_name))


def _validate_config_paths(existing_vms_dict, using_three_nodes, errors_list):
    if using_three_nodes:
        config_paths = [config_path for vm_dict in existing_vms_dict.values()
                        for config_path in vm_dict['config_path'].values()]
    else:
        config_paths = [vm_dict.get('config_path') for vm_dict in
                        existing_vms_dict.values()]

    if all(config_paths):
        for vm_name, vm_dict in existing_vms_dict.items():
            if vm_dict.get('cert_path') or vm_dict.get('key_path'):
                errors_list.append(
                    'Certificate can not be specified for {0} because a '
                    'config path was specified for it. If you wish to use '
                    'your own config path, please make sure the relevant '
                    'certificates are on each VM.'.format(vm_name))
            if using_three_nodes:
                for config_name, config_path in vm_dict['config_path'].items():
                    vm_dict['config_path'][config_name] = \
                        _validate_config_path(vm_name,
                                              config_path,
                                              errors_list)

            else:
                config_path = vm_dict.get('config_path')
                vm_dict['config_path'] = \
                    _validate_config_path(vm_name, config_path, errors_list)

    elif any(config_paths):
        errors_list.append('You must provide the config.yaml file for '
                           'all instances or none of them.')


def _validate_vms_not_duplicated(existing_vms_dict, errors_list):
    existing_vms_ips = set()
    for vm_name, vm_dict in existing_vms_dict.items():
        vm_private_ip = vm_dict.get('private_ip')
        if not vm_private_ip:
            errors_list.append(
                'private_ip should be provided for {0}'.format(vm_name))
            continue
        for vm in existing_vms_ips:
            if vm_private_ip == vm[1]:
                errors_list.append(
                    'The private_ips of {0} and {1} are the same. '
                    'Please ensure all provided VMs have different '
                    'IPs.'.format(vm[0], vm_name))
                break

        existing_vms_ips.add((vm_name, vm_private_ip))


def _validate_existing_vms(config, using_three_nodes, errors_list):
    existing_vms_dict = config.get('existing_vms')
    _validate_config_paths(existing_vms_dict, using_three_nodes, errors_list)
    _validate_vms_not_duplicated(existing_vms_dict, errors_list)
    ca_path_exists = (bool(_using_provided_certificates(config)) and
                      _check_path(config, 'ca_cert_path', errors_list))
    ca_key_path_exists = (bool(config.get('ca_key_path')) and
                          _check_path(config, 'ca_key_path', errors_list))
    if ca_path_exists != ca_key_path_exists:
        errors_list.append('Either both ca_cert_path and ca_key_path must '
                           'be provided, or neither.')
    for vm_name, vm_dict in existing_vms_dict.items():
        logger.info('Validating %s', vm_name)
        if ca_path_exists:
            ca_cert_path = config.get('ca_cert_path')
            key_path_exists = _check_path(vm_dict, 'key_path',
                                          errors_list, vm_name)
            if _check_path(vm_dict, 'cert_path', errors_list, vm_name):
                cert_path = vm_dict.get('cert_path')
                if check_cert_path(cert_path, errors_list):
                    if key_path_exists:
                        key_path = vm_dict.get('key_path')
                        check_cert_key_match(cert_path, key_path, errors_list)

                    check_signed_by(ca_cert_path, cert_path, errors_list)
                    check_san(vm_name, vm_dict, cert_path, errors_list)


def _validate_external_db_config(config, override, errors_list):
    external_db_config = _get_external_db_config(config)
    if external_db_config:
        if override:
            logger.warning('The installation process does not override the '
                           'external DB')
    else:
        return

    for key, value in external_db_config.items():
        _check_value_provided(external_db_config, key, errors_list)
        if 'key' == 'ca_path':
            _check_path(external_db_config, 'ca_path', errors_list)


def _validate_ldap_certificate_setting(config, errors_list):
    """Confirm that if using ldaps we have the required ca cert."""
    ldaps = config['ldap']['server'].startswith('ldaps://')
    ca_cert = config['ldap']['ca_cert']

    if ldaps and not ca_cert:
        errors_list.append(
            'When using ldaps a CA certificate must be provided.')
    elif ca_cert and not ldaps:
        errors_list.append(
            'When not using ldaps a CA certificate must not be provided.')
    if ca_cert and ldaps:
        _check_path(config.get('ldap'), 'ca_cert', errors_list)


def _validate_ssh_config(config, errors_list):
    ssh_key_path = config.get('ssh_key_path')
    ssh_password = config.get('ssh_password')
    if (not ssh_key_path and not ssh_password) or \
            (ssh_key_path and ssh_password):
        errors_list.append(
            'Please provide only one of ssh_key_path or ssh_password')
    if config.get('ssh_key_path'):
        _check_path(config, 'ssh_key_path', errors_list)
    _check_value_provided(config, 'ssh_user', errors_list)


def _validate_ssl_enabled_boolean_value(config, errors_list):
    ssl_enabled = config.get('ssl_enabled')
    if (ssl_enabled is not None) and (not isinstance(ssl_enabled, bool)):
        errors_list.append('`ssl_enabled` must be true or false')


def validate_config(config, using_three_nodes_cluster, override):
    errors_list = []
    _validate_ssh_config(config, errors_list)
    _check_path(config, 'cloudify_license_path', errors_list)
    _check_value_provided(config, 'manager_rpm_path', errors_list)
    _validate_existing_vms(config, using_three_nodes_cluster, errors_list)
    _validate_external_db_config(config, override, errors_list)
    _validate_ldap_certificate_setting(config, errors_list)
    _validate_ssl_enabled_boolean_value(config, errors_list)

    if errors_list:
        raise_errors_list(errors_list)


def _handle_cluster_config_file(cluster_config_file_name, output_path):
    cluster_config_files_env = Environment(
        loader=FileSystemLoader(CLUSTER_CONFIG_FILES_DIR))
    template = cluster_config_files_env.get_template(cluster_config_file_name)
    rendered_data = template.render(
        credentials_file_path=CREDENTIALS_FILE_PATH)
    with open(output_path, 'w') as output_file:
        output_file.write(rendered_data)


def generate_config(output_path,
                    using_three_nodes,
                    using_nine_nodes,
                    using_external_db):
    output_path = output_path or CLUSTER_INSTALL_CONFIG_PATH

    if (not using_nine_nodes) and (not using_three_nodes):
        raise ClusterInstallError(
            'Please specify `--three-nodes` or `--nine-nodes`.')

    if exists(output_path):
        override_file = input('The path {} already exists, would you like '
                              'to override it? (yes/no) '.format(output_path))
        if override_file.lower() not in ('yes', 'y', 'no', 'n'):
            raise ClusterInstallError('Please respond with a yes or no')
        if override_file.lower() in ('no', 'n'):
            logger.info('Please provide a different path to the configuration '
                        'file using the `--output` flag. Exiting..')
            exit(1)

    if isdir(output_path):
        output_path = join(output_path, CLUSTER_CONFIG_FILE_NAME)

    if using_nine_nodes:
        if using_external_db:
            _handle_cluster_config_file(
                'cfy_nine_nodes_external_db_cluster_config.yaml', output_path)
        else:
            _handle_cluster_config_file(
                'cfy_nine_nodes_cluster_config.yaml', output_path)

    elif using_three_nodes:
        if using_external_db:
            _handle_cluster_config_file(
                'cfy_three_nodes_external_db_cluster_config.yaml', output_path)
        else:
            _handle_cluster_config_file(
                'cfy_three_nodes_cluster_config.yaml', output_path)

    logger.info('Created the cluster install configuration file %s',
                output_path)


def _using_provided_config_files(instances_dict):
    """This function checks if config.yaml files were provided.

    This function returns True if the first instance has a config.yaml file
    provided, therefore it should be used only after the validations.
    """
    for instances_list in instances_dict.values():
        for instance in instances_list:
            return True if instance.provided_config_path else False  # explicit


def _handle_certificates(config, instances_dict):
    if _using_provided_certificates(config):
        copy(expanduser(config.get('ca_cert_path')), CA_PATH)
        copy(expanduser(config.get('ca_key_path')), CA_KEY_PATH)
        for instances_list in instances_dict.values():
            for instance in instances_list:
                copy(instance.provided_cert_path, instance.cert_path)
                copy(instance.provided_key_path, instance.key_path)
    else:
        _generate_certs(instances_dict)

    external_db_config = _get_external_db_config(config)
    if external_db_config:
        copy(external_db_config.get('ca_path'), EXTERNAL_DB_CA_PATH)

    ldap_ca = config['ldap'].get('ca_cert')
    if ldap_ca:
        copy(ldap_ca, LDAP_CA_PATH)


def _previous_installation(instances_dict):
    """Checks if there was a previous cluster installation on these instances.

    We check if Cloudify RPM was installed on the instance. If yes, it means
    that there was a previous installation, otherwise there wasn't (unless
    the user messed with it).
    """
    logger.info('Checking for a previous installation')
    first_instance = (
        instances_dict['postgresql'][0] if 'postgresql' in instances_dict
        else instances_dict['rabbitmq'][0])
    return _rpm_was_installed(first_instance)


def _create_installation_files(instance, verbose):
    """Updating the .installed/components.yaml and packages.yaml files.

    Due to a bug during the installation process of v5.1, we need to update
    these files "manually" in order for the remove process to work.
    """
    scripts = pkg_resources.resource_filename('cfy_cluster_manager', 'scripts')
    script_path = join(scripts, 'create_installation_files.py')
    instance.put_file(script_path, '/tmp')
    instance.run_command(
        '{cfy_manager_venv} {script} -c {config_path} {verbose}'.format(
            cfy_manager_venv='/opt/cloudify/cfy_manager/bin/python',
            script='/tmp/create_installation_files.py',
            config_path=instance.config_path,
            verbose='-v' if verbose else ''), use_sudo=True)


def _are_any_services_installed(instance):
    """Checking if there are any services installed on this instance.

    We're checking the /etc/cloudify/<service-name>_config.yaml files,
    because, unlike the .installed/<service-name> files, these will be created
    even if there was a failed installation of one of the services.

    To complete this logic, in case we remove a service from an instance,
    we make sure to remove its config.yaml file from /etc/cloudify
    """
    suffix = '-' + instance.number + '_config.yaml'
    return any(instance.file_exists(config_path) for config_path in
               [join(BASE_CFY_DIR, service_name + suffix) for
                service_name in ['postgresql', 'rabbitmq', 'manager']])


def _remove_cloudify_installation(instance, verbose):
    instance.run_command(
        'cfy_manager remove -c {config_path} {verbose}'.format(
            config_path=instance.config_path, verbose='-v' if verbose else ''))

    instance.run_command(
        'rm -f {0}'.format(instance.config_path), use_sudo=True)

    if '5.1.0' in instance.get_version() and instance.type == 'manager':
        certs_paths_list = [
            'cloudify_external_cert.pem', 'cloudify_external_key.pem',
            'cloudify_internal_ca_cert.pem', 'cloudify_external_ca_cert.pem',
            'cloudify_internal_cert.pem', 'cloudify_internal_key.pem']

        timestamp = time.strftime('%Y%m%d-%H%M%S_')
        certs_dir_path = join(BASE_CFY_DIR, 'ssl')
        for cert_path in certs_paths_list:
            full_path = join(certs_dir_path, cert_path)
            if instance.file_exists(full_path):
                new_path = join(certs_dir_path, timestamp + cert_path)
                instance.run_command(
                    'mv {0} {1}'.format(full_path, new_path), use_sudo=True)

    if not _are_any_services_installed(instance):
        instance.run_command(
            'yum remove -y cloudify-manager-install', use_sudo=True)

    instance.run_command('rm -rf {}'.format(CLUSTER_INSTALL_DIR))

    instance.installed = False


def _get_reversed_instances_dict(instances_dict):
    reversed_instances_dict = OrderedDict(reversed(
        list(instances_dict.items())))
    for instance_type, instances in reversed_instances_dict.items():
        reversed_instances_dict[instance_type] = list(reversed(instances))

    return reversed_instances_dict


def _handle_installed_instances(instances_dict, override, verbose):
    """Checking which instances were installed in the previous installation.

    This function goes over each instance in the ordered instances dictionary,
    and checks if a previous cluster installation ran on it. It does so by
    checking if its config path, `/etc/cloudify/<instance-name>_config.yaml`,
    exists.

    If it exists,it checks if the previous installation finished successfully.
    If it did, then the instance.installed attribute is set to True.

    Otherwise, the failed installation is removed and the instance.installed
    attribute is set to False (this is also the default setting).

    If override is specified, the function would go over all instances,
    remove failed and successful installations, and set the installed attribute
    to false on all of them.

    Otherwise, the function will return once it got to a failed instance and
    removed its installation. This is the useful if the user wants to continue
    the installation from where it previously stopped.
    """
    logger.info('{0} previously installed instances'.format(
        'Overriding' if override else 'Handling'))
    reversed_instances_dict = _get_reversed_instances_dict(instances_dict)
    for instance_type, instances_list in reversed_instances_dict.items():
        for instance in instances_list:
            logger.info('Checking if %s was installed', instance.name)
            if instance.file_exists(instance.config_path):
                instance.installed = \
                    _cloudify_was_previously_installed_successfully(instance)
                if instance.installed:
                    logger.info('%s was previously installed successfully',
                                instance.name)
                    if override:
                        logger.info('Removing Cloudify from %s', instance.name)
                        _remove_cloudify_installation(instance, verbose)
                else:
                    logger.info('Previous Cloudify installation of %s failed',
                                instance.name)
                    if '5.1.0' in instance.get_version():
                        _create_installation_files(instance, verbose)

                    logger.info('Removing failed Cloudify installation '
                                'from %s', instance.name)
                    _remove_cloudify_installation(instance, verbose)
                    if override:
                        continue

                    return


def install(config_path, override, only_validate, verbose):
    if not yum_is_present():
        raise ClusterInstallError('Yum is not present.')

    credentials = None
    start_time = time.time()
    logger.info('Validating the configuration file' if only_validate else
                'Installing a Cloudify cluster')
    config_path = config_path or CLUSTER_INSTALL_CONFIG_PATH
    config = get_dict_from_yaml(config_path)
    using_three_nodes_cluster = (len(config.get('existing_vms')) == 3)
    validate_config(config, using_three_nodes_cluster, override)
    if only_validate:
        logger.info('The configuration file at %s was validated '
                    'successfully.', config_path)
        return
    instances_dict = (_generate_three_nodes_cluster_dict(config)
                      if using_three_nodes_cluster else
                      _generate_general_cluster_dict(config))

    previous_installation = _previous_installation(instances_dict)
    if previous_installation:
        logger.info('Cloudify cluster was previously installed')
        _handle_installed_instances(instances_dict, override, verbose)
    if (not previous_installation) or override:
        logger.info('Preparing cluster manager files')
        _create_cluster_install_directory()
        copy(config.get('cloudify_license_path'),
             join(CLUSTER_INSTALL_DIR, 'license.yaml'))
        _install_cloudify_locally(config.get('manager_rpm_path'))
        if not _using_provided_config_files(instances_dict):
            _handle_certificates(config, instances_dict)
            credentials = _handle_credentials(config.get('credentials'))
        _prepare_config_files(instances_dict, credentials, config)

    _install_instances(instances_dict, verbose)
    _log_managers_connection_strings(instances_dict['manager'])
    if credentials:
        logger.warning('The credentials file was saved to %s. '
                       'The credentials are written there in plain text. '
                       'Please remove it after reviewing it.',
                       CREDENTIALS_FILE_PATH)
    _print_success_message(start_time)


def remove(config_path, verbose):
    if not yum_is_present():
        raise ClusterInstallError('Yum is not present.')

    start_time = time.time()
    logger.info('Removing Cloudify cluster')
    config_path = config_path or CLUSTER_INSTALL_CONFIG_PATH
    config = get_dict_from_yaml(config_path)
    using_three_nodes_cluster = (len(config.get('existing_vms')) == 3)
    instances_dict = (_generate_three_nodes_cluster_dict(config)
                      if using_three_nodes_cluster else
                      _generate_general_cluster_dict(config))

    if _previous_installation(instances_dict):
        _handle_installed_instances(instances_dict, True, verbose)
        _print_success_message(start_time, 'removed')
    else:
        logger.info('No previous installation of a Cloudify cluster was '
                    'detected. Nothing to remove.')


def _upgrade_cluster(instances_dict, verbose, upgrade_rpm_path,
                     using_three_nodes_cluster):
    instances_list = instances_dict['manager']
    if not using_three_nodes_cluster:
        instances_list += (instances_dict['rabbitmq'] +
                           instances_dict['postgresql'])

    _install_upgrade_rpm_on_nodes(instances_list, upgrade_rpm_path)

    for instance_type, instances_list in instances_dict.items():
        for instance in instances_list:
            logger.info('Upgrading %s', instance.name)
            logger.info('Running upgrade command on %s', instance.name)
            instance.run_command(
                'cfy_manager upgrade -c {config} {verbose}'.format(
                    config=instance.config_path,
                    verbose='-v' if verbose else '')
            )


def _install_upgrade_rpm_on_nodes(instances_list, upgrade_rpm_path):
    rpm_file_name = time.strftime('%Y%m%d-%H%M%S_') + UPGRADE_RPM_NAME + '.rpm'
    tmp_upgrade_rpm_path = join('/tmp', rpm_file_name)
    expanded_rpm_path = expanduser(upgrade_rpm_path)
    if exists(expanded_rpm_path):
        copy(expanded_rpm_path, tmp_upgrade_rpm_path)
    else:
        logger.info('Downloading Cloudify RPM from %s', expanded_rpm_path)
        run(['curl', '-o', tmp_upgrade_rpm_path, expanded_rpm_path])

    for instance in instances_list:
        logger.info('Installing upgrade RPM on %s', instance.private_ip)
        instance.put_file(tmp_upgrade_rpm_path, tmp_upgrade_rpm_path)
        instance.run_command(
            'yum install -y {} --disablerepo=*'.format(tmp_upgrade_rpm_path),
            use_sudo=True, hide_stdout=True)


def _verify_cloudify_installed(instances_dict, using_three_nodes_cluster):
    logger.info(
        'Verifying cloudify-manager-install is installed on all instances')
    for instance_type, instances_list in instances_dict.items():
        for instance in instances_list:
            logger.debug('Verifying instance %s', instance.private_ip)
            if not _rpm_was_installed(instance):
                raise ClusterInstallError(
                    'cloudify-manager-install is not installed on '
                    '{0}'.format(instance.private_ip))
        if using_three_nodes_cluster:  # One iteration goes through all nodes
            return


def upgrade(config_path, verbose, upgrade_rpm_path):
    if not yum_is_present():
        raise ClusterInstallError('Yum is not present.')

    start_time = time.time()
    logger.info('Upgrading Cloudify cluster')
    config_path = config_path or CLUSTER_INSTALL_CONFIG_PATH
    config = get_dict_from_yaml(config_path)
    using_three_nodes_cluster = (len(config.get('existing_vms')) == 3)
    instances_dict = (_generate_three_nodes_cluster_dict(config)
                      if using_three_nodes_cluster else
                      _generate_general_cluster_dict(config))

    _verify_cloudify_installed(instances_dict, using_three_nodes_cluster)
    _upgrade_cluster(instances_dict, verbose, upgrade_rpm_path,
                     using_three_nodes_cluster)
    _print_success_message(start_time, 'upgraded')


def add_verbose_arg(parser):
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        default=False,
        help='Show verbose output'
    )


def add_config_arg(parser):
    parser.add_argument(
        '--config-path',
        action='store',
        help='The completed cluster configuration file. Default: '
             './{0}'.format(CLUSTER_CONFIG_FILE_NAME)
    )


def main():
    parser = argparse.ArgumentParser(
        description='Setting up a Cloudify cluster')

    subparsers = parser.add_subparsers(help='Cloudify cluster manager action',
                                       dest='action')

    generate_config_args = subparsers.add_parser(
        'generate-config',
        help='Generate the cluster install configuration file')

    generate_config_args.add_argument(
        '-o', '--output',
        action='store',
        help='The local path to save the cluster install configuration file '
             'to. Default: ./{0}'.format(CLUSTER_CONFIG_FILE_NAME))

    exclusive_options = generate_config_args.add_mutually_exclusive_group()

    exclusive_options.add_argument(
        '--three-nodes',
        action='store_true',
        default=False,
        help='Using a three nodes cluster')

    exclusive_options.add_argument(
        '--nine-nodes',
        action='store_true',
        default=False,
        help='Using a nine nodes cluster. In case of using an external DB, '
             'Only 6 nodes will need to be provided')

    generate_config_args.add_argument(
        '--external-db',
        action='store_true',
        default=False,
        help='Using an external DB')

    add_verbose_arg(generate_config_args)

    install_args = subparsers.add_parser(
        'install',
        help='Install a Cloudify cluster based on the cluster install '
             'configuration file')

    add_config_arg(install_args)

    install_args.add_argument(
        '--override',
        action='store_true',
        default=False,
        help='If specified, any previous installation of Cloudify on the '
             'instances will be removed'
    )

    install_args.add_argument(
        '--validate',
        action='store_true',
        default=False,
        help='Validate the provided configuration file'
    )

    add_verbose_arg(install_args)

    remove_args = subparsers.add_parser(
        'remove',
        help='Remove a Cloudify cluster based on the specified '
             'configuration file')

    add_config_arg(remove_args)
    add_verbose_arg(remove_args)

    upgrade_args = subparsers.add_parser(
        'upgrade',
        help='Upgrade a v5.1.0 Cloudify cluster to v5.1.1')

    add_config_arg(upgrade_args)
    upgrade_args.add_argument(
        '--upgrade-rpm',
        action='store',
        default=DEFAULT_RPM,
        help='Path to an upgrade cloudify-manager-install RPM. '
             'This can be either a local or remote path. '
             'Default: {0}'.format(DEFAULT_RPM)
    )

    add_verbose_arg(upgrade_args)

    args = parser.parse_args()

    if hasattr(args, 'verbose'):
        setup_logger(args.verbose)

    if args.action == 'generate-config':
        generate_config(args.output, args.three_nodes, args.nine_nodes,
                        args.external_db)

    elif args.action == 'install':
        install(args.config_path, args.override, args.validate, args.verbose)

    elif args.action == 'remove':
        remove(args.config_path, args.verbose)

    elif args.action == 'upgrade':
        upgrade(args.config_path, args.verbose, args.upgrade_rpm)

    else:
        raise RuntimeError('Invalid action specified in parser.')


if __name__ == "__main__":
    main()
