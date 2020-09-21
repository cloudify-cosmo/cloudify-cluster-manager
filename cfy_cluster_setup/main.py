import os
import sys
import time
import shutil
import string
import random
import argparse
from traceback import format_exception
from collections import OrderedDict
from os.path import (basename, dirname, exists, expanduser, isdir, join,
                     splitext)

import yaml
from jinja2 import Environment, FileSystemLoader

from .logger import get_cfy_cluster_setup_logger, setup_logger
from .utils import (check_cert_key_match, check_cert_path, check_san,
                    check_signed_by, cloudify_is_installed,
                    ClusterInstallError, copy, current_host_ip,
                    raise_errors_list, get_dict_from_yaml, move, run,
                    sudo, VM, yum_is_present)


logger = get_cfy_cluster_setup_logger()

CERTS_DIR_NAME = 'certs'
CFY_CERTS_PATH = '{0}/.cloudify-test-ca'.format(expanduser('~'))
CONFIG_FILES = 'config_files'
DIR_NAME = 'cloudify_cluster_setup'
RPM_NAME = 'cloudify-manager-install.rpm'
TOP_DIR = '/tmp'

RPM_PATH = join(TOP_DIR, RPM_NAME)
CLUSTER_INSTALL_DIR = join(TOP_DIR, DIR_NAME)
CERTS_DIR = join(CLUSTER_INSTALL_DIR, CERTS_DIR_NAME)
CONFIG_FILES_DIR = join(CLUSTER_INSTALL_DIR, CONFIG_FILES)

CA_PATH = join(CERTS_DIR, 'ca.pem')

CREDENTIALS_FILE_PATH = join(os.getcwd(), 'secret_credentials.yaml')
CLUSTER_CONFIG_FILES_DIR = join(dirname(__file__), 'cfy_cluster_config_files')
THREE_NODES_CLUSTER_CONFIG_FILE_NAME = 'cfy_three_nodes_cluster_config.yaml'
CLUSTER_CONFIG_FILE_NAME = 'cfy_cluster_config.yaml'
CLUSTER_INSTALL_CONFIG_PATH = join(os.getcwd(), CLUSTER_CONFIG_FILE_NAME)


class CfyNode(VM):
    def __init__(self,
                 private_ip,
                 public_ip,
                 key_file_path,
                 username,
                 node_name,
                 hostname,
                 cert_path,
                 key_path):
        super(CfyNode, self).__init__(private_ip, public_ip,
                                      key_file_path, username)
        self.name = node_name
        self.hostname = hostname
        self.cert_path = cert_path
        self.key_path = key_path


def _exception_handler(type_, value, traceback):
    exception_traceback = ''.join(format_exception(type_, value, traceback))
    logger.exception(exception_traceback)


sys.excepthook = _exception_handler


def _generate_instance_certificate(instance):
    run(['cfy_manager', 'generate-test-cert', '-s',
         instance.private_ip+','+instance.public_ip])
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
        postgresql_instances[j].name:
            {'ip': postgresql_instances[j].private_ip}
        for j in range(len(postgresql_instances))}


def _get_rabbitmq_cluster_members(rabbitmq_instances):
    return {
        rabbitmq_instances[j].name: {
            'networks': {'default': rabbitmq_instances[j].private_ip}
        } for j in range(len(rabbitmq_instances))}


def _prepare_postgresql_config_files(template,
                                     postgresql_instances,
                                     credentials):
    logger.info('Preparing PostgreSQL config files')
    postgresql_cluster = _get_postgresql_cluster_members(postgresql_instances)
    for node in postgresql_instances:
        rendered_data = template.render(node=node,
                                        creds=credentials,
                                        ca_path=CA_PATH,
                                        postgresql_cluster=postgresql_cluster)
        _create_config_file(rendered_data, node.name)


def _prepare_rabbitmq_config_files(template, rabbitmq_instances, credentials):
    logger.info('Preparing RabbitMQ config files')
    rabbitmq_cluster = _get_rabbitmq_cluster_members(rabbitmq_instances)
    for i, node in enumerate(rabbitmq_instances):
        join_cluster = rabbitmq_instances[0].name if i > 0 else None
        rendered_data = template.render(node=node,
                                        creds=credentials,
                                        ca_path=CA_PATH,
                                        join_cluster=join_cluster,
                                        rabbitmq_cluster=rabbitmq_cluster)
        _create_config_file(rendered_data, node.name)


def _prepare_manager_config_files(template,
                                  instances_dict,
                                  credentials,
                                  load_balancer_ip):
    logger.info('Preparing Manager config files')
    license_path = join(CLUSTER_INSTALL_DIR, 'license.yaml')
    postgresql_cluster = _get_postgresql_cluster_members(
        instances_dict['postgresql'])
    rabbitmq_cluster = _get_rabbitmq_cluster_members(
        instances_dict['rabbitmq'])
    for node in instances_dict['manager']:
        rendered_data = template.render(node=node,
                                        creds=credentials,
                                        ca_path=CA_PATH,
                                        license_path=license_path,
                                        load_balancer_ip=load_balancer_ip,
                                        rabbitmq_cluster=rabbitmq_cluster,
                                        postgresql_cluster=postgresql_cluster)
        _create_config_file(rendered_data, node.name)


def _create_config_file(rendered_data, node_name):
    config_path = join(CONFIG_FILES_DIR, '{0}_config.yaml'.format(node_name))
    with open(config_path, 'w') as config_file:
        config_file.write(rendered_data)


def _prepare_config_files(instances_dict, credentials, load_balancer_ip):
    os.mkdir(join(CLUSTER_INSTALL_DIR, 'config_files'))
    templates_env = Environment(
        loader=FileSystemLoader(
            join(dirname(__file__), 'config_files_templates')))

    _prepare_postgresql_config_files(
        templates_env.get_template('postgresql_config.yaml'),
        instances_dict['postgresql'],
        credentials)

    _prepare_rabbitmq_config_files(
        templates_env.get_template('rabbitmq_config.yaml'),
        instances_dict['rabbitmq'],
        credentials)

    _prepare_manager_config_files(
        templates_env.get_template('manager_config.yaml'),
        instances_dict,
        credentials,
        load_balancer_ip)


def _install_cloudify_remotely(instance, rpm_download_link):
    rpm_name = splitext(basename(rpm_download_link))[0]
    try:
        instance.run_command('rpm -qa | grep {0}'.format(rpm_name),
                             hide_stdout=True)
        logger.info('Cloudify RPM is already installed on %s',
                    instance.name)
    except ClusterInstallError:
        # If cloudify is not installed, an error is raised
        logger.info('Downloading Cloudify RPM on %s from %s',
                    instance.name, rpm_download_link)
        instance.run_command('curl -o {0} {1}'.format(
            RPM_PATH, rpm_download_link))
        logger.info('Installing Cloudify RPM on %s', instance.name)
        instance.run_command(
            'yum install -y {}'.format(RPM_PATH), use_sudo=True)


def _install_instances(instances_dict, using_three_nodes,
                       rpm_download_link, verbose):
    for i, instance_type in enumerate(instances_dict):
        logger.info('installing %s instances', instance_type)
        three_nodes_first_round = using_three_nodes and i == 0
        for instance in instances_dict[instance_type]:
            logger.info('Installing %s', instance.name)
            if (instance.private_ip == current_host_ip() or
                    not three_nodes_first_round):
                logger.info('Already installed Cloudify RPM on this instance')
            else:
                logger.info('Copying the %s directory to %s',
                            CLUSTER_INSTALL_DIR, instance.name)
                instance.put_dir(CLUSTER_INSTALL_DIR,
                                 CLUSTER_INSTALL_DIR,
                                 override=True)
                _install_cloudify_remotely(instance, rpm_download_link)

            instance_config = '{}_config.yaml'.format(instance.name)
            dest_instance_config = join('/etc', 'cloudify', instance_config)
            instance.run_command('cp {0} {1}'.format(
                join(CONFIG_FILES_DIR, instance_config), dest_instance_config),
                use_sudo=True)

            install_cmd = 'cfy_manager install -c {config} {verbose}'.format(
                config=dest_instance_config, verbose='-v' if verbose else '')

            instance.run_command(install_cmd)


def _sort_instances_dict(instances_dict):
    for _, instance_items in instances_dict.items():
        if len(instance_items) > 1:
            instance_items.sort(key=lambda x: int(x.name.rsplit('-', 1)[1]))


def _using_provided_certificates(config):
    return config.get('ca_cert_path')


def _using_three_nodes_cluster(config):
    return len(config.get('existing_vms')) == 3


def _get_cfy_node(config, node_dict, node_name, validate_connection=True):
    username = config.get('machine_username')
    cert_path = join(CERTS_DIR, node_name + '_cert.pem')
    key_path = join(CERTS_DIR, node_name + '_key.pem')
    if _using_provided_certificates(config):
        copy(expanduser(node_dict.get('cert_path')), cert_path)
        copy(expanduser(node_dict.get('key_path')), key_path)

    public_ip = node_dict.get('public_ip') or node_dict.get('private_ip')
    new_vm = CfyNode(node_dict.get('private_ip'),
                     public_ip,
                     config.get('key_file_path'),
                     username,
                     node_name,
                     node_dict.get('hostname'),
                     cert_path,
                     key_path)
    if validate_connection:
        logger.debug('Testing connection to %s', new_vm.private_ip)
        new_vm.test_connection()

    return new_vm


def _generate_three_nodes_cluster_dict(config):
    instances_dict = OrderedDict(
        (('postgresql', []), ('rabbitmq', []), ('manager', [])))
    existing_nodes_list = config.get('existing_vms').values()
    for node_type in instances_dict:
        for i, node_dict in enumerate(existing_nodes_list):
            new_vm = _get_cfy_node(config,
                                   node_dict,
                                   node_name=(node_type + '-' + str(i+1)),
                                   validate_connection=(i == 0))
            instances_dict[node_type].append(new_vm)
    return instances_dict


def generate_general_cluster_dict(config):
    instances_dict = OrderedDict(
        (('postgresql', []), ('rabbitmq', []), ('manager', [])))
    for node_name, node_dict in config.get('existing_vms').items():
        new_vm = _get_cfy_node(config, node_dict, node_name)
        instances_dict[node_name.split('-')[0]].append(new_vm)

    _sort_instances_dict(instances_dict)
    return instances_dict


def _create_cluster_install_directory():
    logger.info('Creating `{0}` directory'.format(DIR_NAME))
    if exists(CLUSTER_INSTALL_DIR):
        new_dirname = (time.strftime('%Y%m%d-%H%M%S_') + DIR_NAME)
        run(['mv', CLUSTER_INSTALL_DIR, join(TOP_DIR, new_dirname)])

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
    with open(CREDENTIALS_FILE_PATH, 'w') as credentials_file:
        yaml.dump(credentials, credentials_file)

    return credentials


def _log_managers_connection_strings(manager_nodes):
    managers_str = ''
    for manager in manager_nodes:
        managers_str += '{0}: {1}@{2}\n'.format(manager.name,
                                                manager.username,
                                                manager.public_ip)
    logger.info('In order to connect to one of the managers, use one of the '
                'following connection strings:\n%s', managers_str)


def _print_successful_installation_message(start_time):
    running_time = time.time() - start_time
    m, s = divmod(running_time, 60)
    logger.info('Successfully installed a Cloudify cluster in '
                '{0} minutes and {1} seconds'.format(int(m), int(s)))


def _install_cloudify_locally(rpm_download_link):
    rpm_name = splitext(basename(rpm_download_link))[0]
    if cloudify_is_installed(rpm_name):
        logger.info('Cloudify RPM is already installed')
    else:
        logger.info('Downloading Cloudify RPM from %s', rpm_download_link)
        run(['curl', '-o', RPM_PATH, rpm_download_link])
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


def _check_existing_vms(config, errors_list):
    existing_vms_list = config.get('existing_vms')
    ca_path_exists = (_using_provided_certificates(config) and
                      _check_path(config, 'ca_cert_path', errors_list))
    for vm_name, vm_dict in existing_vms_list.items():
        logger.info('Validating %s', vm_name)
        if not vm_dict.get('private_ip'):
            errors_list.append('private_ip should be provided for '
                               '{0}'.format(vm_name))

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


def _validate_config(config):
    errors_list = []
    _check_path(config, 'key_file_path', errors_list)
    _check_value_provided(config, 'machine_username', errors_list)
    _check_path(config, 'cloudify_license_path', errors_list)
    _check_value_provided(config, 'manager_rpm_download_link', errors_list)
    _check_existing_vms(config, errors_list)
    if errors_list:
        raise_errors_list(errors_list)


def generate_config(output_path, verbose, using_three_nodes):
    setup_logger(verbose)
    output_path = output_path or CLUSTER_INSTALL_CONFIG_PATH
    if isdir(output_path):
        output_path = join(output_path, CLUSTER_CONFIG_FILE_NAME)
    if using_three_nodes:
        copy(join(CLUSTER_CONFIG_FILES_DIR,
                  THREE_NODES_CLUSTER_CONFIG_FILE_NAME), output_path)
    else:
        copy(join(CLUSTER_CONFIG_FILES_DIR, CLUSTER_CONFIG_FILE_NAME),
             output_path)
    logger.info('Created the cluster install configuration file in %s',
                output_path)


def install(config_path, verbose):
    setup_logger(verbose)
    if not yum_is_present():
        raise ClusterInstallError('Yum is not present.')

    logger.info('Installing a Cloudify cluster')
    start_time = time.time()
    config_path = config_path or CLUSTER_INSTALL_CONFIG_PATH
    config = get_dict_from_yaml(config_path)
    _validate_config(config)
    load_balancer_ip = config.get('load_balancer_ip')
    rpm_download_link = config.get('manager_rpm_download_link')
    credentials = _handle_credentials(config.get('credentials'))
    _create_cluster_install_directory()
    copy(config.get('cloudify_license_path'),
         join(CLUSTER_INSTALL_DIR, 'license.yaml'))
    _install_cloudify_locally(rpm_download_link)

    using_three_nodes_cluster = _using_three_nodes_cluster(config)
    instances_dict = (_generate_three_nodes_cluster_dict(config)
                      if using_three_nodes_cluster else
                      generate_general_cluster_dict(config))
    logger.info(instances_dict)
    if _using_provided_certificates(config):
        copy(expanduser(config.get('ca_cert_path')), CA_PATH)
    else:
        _generate_certs(instances_dict)
    _prepare_config_files(instances_dict, credentials, load_balancer_ip)
    _install_instances(instances_dict, using_three_nodes_cluster,
                       rpm_download_link, verbose)
    _log_managers_connection_strings(instances_dict['manager'])
    logger.info('The credentials file was saved to %s', CREDENTIALS_FILE_PATH)
    _print_successful_installation_message(start_time)


def add_verbose_arg(parser):
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        default=False,
        help='Show verbose output.'
    )


def main():
    parser = argparse.ArgumentParser(
        description='Setting up a Cloudify cluster')

    subparsers = parser.add_subparsers(help='Cloudify cluster setup action',
                                       dest='action')

    generate_config_args = subparsers.add_parser(
        'generate-config',
        help='Generate the cluster install configuration file')

    generate_config_args.add_argument(
        '-o', '--output',
        action='store',
        help='The local path to save the cluster install configuration file '
             'to. default: ./{0}'.format(CLUSTER_CONFIG_FILE_NAME))

    generate_config_args.add_argument(
        '--three-nodes',
        action='store_true',
        default=False,
        help='Using a three nodes cluster.')

    add_verbose_arg(generate_config_args)

    install_args = subparsers.add_parser(
        'install',
        help='Install a Cloudify cluster based on the cluster install '
             'configuration file.')

    install_args.add_argument(
        '--config-path',
        action='store',
        help='The completed cluster install configuration file. '
             'default: ./{0}'.format(CLUSTER_CONFIG_FILE_NAME))

    add_verbose_arg(install_args)

    args = parser.parse_args()

    if args.action == 'generate-config':
        generate_config(args.output, args.verbose, args.three_nodes)

    elif args.action == 'install':
        install(args.config_path, args.verbose)

    else:
        raise RuntimeError('Invalid action specified in parser.')


if __name__ == "__main__":
    main()
