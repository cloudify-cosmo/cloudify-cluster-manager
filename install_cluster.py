import os
import time
import shutil
import string
import random
from os.path import join, expanduser, exists

import yaml

from common import (logger, run, sudo, copy, move, CfyNode, get_dict_from_yaml,
                    JUMP_HOST_DIR, JUMP_HOST_SSH_KEY_PATH,
                    JUMP_HOST_CONFIG_PATH, JUMP_HOST_LICENSE_PATH)

INSTANCES_TYPES = ['postgresql', 'rabbitmq', 'manager']  # Order is important
CERT_PATH = '{0}/.cloudify-test-ca'.format(expanduser('~'))
RPM_NAME = 'cloudify-manager-install.rpm'
CONFIG_FILES = 'config_files'

JUMP_HOST_RPM_PATH = join(JUMP_HOST_DIR, RPM_NAME)
LOCAL_INSTALL_CLUSTER_DIR = join(JUMP_HOST_DIR, 'cluster_install')
LOCAL_CERTS_DIR = join(LOCAL_INSTALL_CLUSTER_DIR, 'certs')
LOCAL_CONFIG_DIR = join(LOCAL_INSTALL_CLUSTER_DIR, CONFIG_FILES)

REMOTE_INSTALL_CLUSTER_DIR = join('/tmp', 'cluster_install')
REMOTE_CERTS_DIR = join(REMOTE_INSTALL_CLUSTER_DIR, 'certs')
REMOTE_RPM_PATH = join(REMOTE_INSTALL_CLUSTER_DIR, RPM_NAME)
REMOTE_CONFIG_DIR = join(REMOTE_INSTALL_CLUSTER_DIR, CONFIG_FILES)


def _generate_instance_certificate(instance):
    run(['cfy_manager', 'generate-test-cert', '-s',
         instance.private_ip+','+instance.public_ip])
    move(join(CERT_PATH, instance.private_ip+'.crt'),
         join(CERT_PATH, instance.name+'_cert.pem'))
    new_key_path = join(CERT_PATH, instance.name+'_key.pem')
    move(join(CERT_PATH, instance.private_ip+'.key'), new_key_path)
    sudo(['chmod', '444', new_key_path])


def _generate_certs(instances_dict):
    logger.info('Generating certificates')
    for instances_list in instances_dict.values():
        for instance in instances_list:
            _generate_instance_certificate(instance)
    copy(join(CERT_PATH, 'ca.crt'), join(CERT_PATH, 'ca.pem'))
    os.mkdir(LOCAL_CERTS_DIR)
    copy(CERT_PATH+'/.', LOCAL_CERTS_DIR)
    shutil.rmtree(CERT_PATH)


def _write_certs_to_config(config_dict, config_section, node_name):
    cert_path = join(REMOTE_CERTS_DIR, node_name+'_cert.pem')
    key_path = join(REMOTE_CERTS_DIR, node_name+'_key.pem')
    ca_path = join(REMOTE_CERTS_DIR, 'ca.pem')

    config_dict['prometheus']['cert_path'] = cert_path
    config_dict['prometheus']['key_path'] = key_path
    config_dict['prometheus']['ca_path'] = ca_path

    if config_section == 'manager':
        ssl_inputs = {}
        cert_names = ['internal_cert_path', 'external_cert_path',
                      'postgresql_client_cert_path']
        key_names = ['internal_key_path', 'external_key_path',
                     'postgresql_client_key_path']
        ca_names = ['ca_cert_path', 'external_ca_cert_path']
        for cert_name in cert_names:
            ssl_inputs[cert_name] = cert_path
        for key_name in key_names:
            ssl_inputs[key_name] = key_path
        for ca_name in ca_names:
            ssl_inputs[ca_name] = ca_path
        config_dict['ssl_inputs'] = ssl_inputs

        config_dict['prometheus']['blackbox_exporter']['ca_cert_path'] = \
            ca_path
    else:
        config_dict[config_section]['cert_path'] = cert_path
        config_dict[config_section]['key_path'] = key_path
        config_dict[config_section]['ca_path'] = ca_path


def _get_postgresql_cluster_members(postgresql_instances):
    return {
        postgresql_instances[j].name:
            {'ip': postgresql_instances[j].private_ip}
        for j in range(len(postgresql_instances))}


def _prepare_postgresql_config_files(instances_dict):
    logger.info('Preparing PostgreSQL config files')
    for node in instances_dict['postgresql']:
        config_dict = get_dict_from_yaml(join(JUMP_HOST_DIR,
                                              'postgresql_config.yaml'))
        _write_certs_to_config(config_dict, 'postgresql_server', node.name)
        config_dict['postgresql_server']['cluster']['nodes'] = \
            _get_postgresql_cluster_members(instances_dict['postgresql'])

        config_dict['manager']['private_ip'] = node.private_ip
        config_dict['manager']['public_ip'] = node.public_ip
        _create_config_file(config_dict, node.name)


def _create_config_file(config_dict, node_name):
    config_path = join(LOCAL_CONFIG_DIR, '{0}_config.yaml'.format(node_name))
    with open(config_path, 'w') as config_file:
        yaml.dump(config_dict, config_file)


def _random_credential_generator():
    return ''.join(random.choice(string.ascii_lowercase + string.digits)
                   for _ in range(6))


def _get_rabbitmq_cluster_members(rabbitmq_instances):
    return {
        rabbitmq_instances[j].name: {
            'networks': {'default': rabbitmq_instances[j].private_ip}
        } for j in range(len(rabbitmq_instances))}


def _prepare_rabbitmq_config_files(instances_dict, rabbitmq_credentials):
    logger.info('Preparing RabbitMQ config files')
    first_rabbitmq = instances_dict['rabbitmq'][0]
    rabbitmq_username, rabbitmq_password = rabbitmq_credentials
    for i, node in enumerate(instances_dict['rabbitmq']):
        config_dict = get_dict_from_yaml(join(JUMP_HOST_DIR,
                                              'rabbitmq_config.yaml'))
        config_dict['rabbitmq']['username'] = rabbitmq_username
        config_dict['rabbitmq']['password'] = rabbitmq_password
        config_dict['rabbitmq']['cluster_members'] = \
            _get_rabbitmq_cluster_members(instances_dict['rabbitmq'])
        _write_certs_to_config(config_dict, 'rabbitmq', node.name)
        config_dict['rabbitmq']['nodename'] = node.name
        if i != 0:
            config_dict['rabbitmq']['join_cluster'] = first_rabbitmq.name

        config_dict['manager']['private_ip'] = node.private_ip
        config_dict['manager']['public_ip'] = node.public_ip
        _create_config_file(config_dict, node.name)


def _prepare_manager_config_files(instances_dict,
                                  rabbitmq_credentials,
                                  load_balancer_ip):
    logger.info('Preparing Manager config files')
    ca_path = join(REMOTE_CERTS_DIR, 'ca.pem')
    for node in instances_dict['manager']:
        config_dict = get_dict_from_yaml(join(JUMP_HOST_DIR,
                                              'manager_config.yaml'))
        config_dict['manager']['hostname'] = node.name
        config_dict['manager']['private_ip'] = node.private_ip
        config_dict['manager']['public_ip'] = node.public_ip
        config_dict['manager']['cloudify_license_path'] = \
            join(REMOTE_INSTALL_CLUSTER_DIR, 'license.yaml')
        config_dict['rabbitmq']['cluster_members'] = \
            _get_rabbitmq_cluster_members(instances_dict['rabbitmq'])
        config_dict['rabbitmq']['username'] = rabbitmq_credentials[0]
        config_dict['rabbitmq']['password'] = rabbitmq_credentials[1]
        config_dict['rabbitmq']['ca_path'] = ca_path
        config_dict['postgresql_server']['cluster']['nodes'] = \
            _get_postgresql_cluster_members(instances_dict['postgresql'])
        config_dict['postgresql_server']['ca_path'] = ca_path
        if load_balancer_ip:
            config_dict['networks'] = {'load_balancer': load_balancer_ip}
        _write_certs_to_config(config_dict, 'manager', node.name)
        _create_config_file(config_dict, node.name)


def _install_instances(instances_dict, rpm_download_link):
    for instance_type in INSTANCES_TYPES:
        logger.info('installing %s instances', instance_type)
        for instance in instances_dict[instance_type]:
            logger.info('Copying the %s directory to %s',
                        LOCAL_INSTALL_CLUSTER_DIR, instance.name)
            instance.put_dir(LOCAL_INSTALL_CLUSTER_DIR,
                             REMOTE_INSTALL_CLUSTER_DIR,
                             override=True)
            logger.info('Installing Cloudify RPM on %s', instance.name)
            instance.run_command('curl -o {0} {1}'.format(REMOTE_RPM_PATH,
                                                          rpm_download_link))
            instance.run_command(
                'yum install -y {}'.format(REMOTE_RPM_PATH), use_sudo=True)

            config_path = join(REMOTE_CONFIG_DIR,
                               '{}_config.yaml'.format(instance.name))
            instance.run_command(
                'cp {0} /etc/cloudify/config.yaml'.format(config_path))

            logger.info('Installing %s', instance.name)
            instance.run_command(
                'cfy_manager install --private-ip {0} --public-ip {1}'.format(
                    instance.private_ip, instance.public_ip))


def _sort_instances_dict(instances_dict):
    for _, instance_items in instances_dict.items():
        if len(instance_items) > 1:
            instance_items.sort(key=lambda x: int(x.name.rsplit('-', 1)[1]))


def _get_instances_dict(config):
    instances_dict = {instance_type: [] for instance_type in INSTANCES_TYPES}
    username = config.get('machine_username')
    for node_name, node_dict in config.get('existing_vms').items():
        new_vm = CfyNode(node_dict.get('private_ip'),
                         node_dict.get('public_ip'),
                         JUMP_HOST_SSH_KEY_PATH,
                         username,
                         node_name)
        instances_dict[new_vm.node_type].append(new_vm)
    _sort_instances_dict(instances_dict)
    return instances_dict


def _create_install_cluster_directory():
    logger.info('Creating `remote_cluster_install` directory')
    run(['rm', '-rf', '{}_old'.format(LOCAL_INSTALL_CLUSTER_DIR)])
    if exists(LOCAL_INSTALL_CLUSTER_DIR):
        run(['mv', LOCAL_INSTALL_CLUSTER_DIR,
             '{0}_old'.format(LOCAL_INSTALL_CLUSTER_DIR)])
    os.mkdir(LOCAL_INSTALL_CLUSTER_DIR)
    copy(JUMP_HOST_LICENSE_PATH,
         join(LOCAL_INSTALL_CLUSTER_DIR, 'license.yaml'))


def _show_manager_ips(manager_nodes):
    managers_str = ''
    for manager in manager_nodes:
        managers_str += '{0}: {1}\n'.format(manager.name, manager.public_ip)
    logger.info('In order to connect to one of the managers, use one of the '
                'following IPs:\n%s', managers_str)


def _prepare_config_files(instances_dict, load_balancer_ip):
    os.mkdir(join(LOCAL_INSTALL_CLUSTER_DIR, 'config_files'))
    _prepare_postgresql_config_files(instances_dict)
    rabbitmq_credentials = (_random_credential_generator(),
                            _random_credential_generator())
    _prepare_rabbitmq_config_files(instances_dict, rabbitmq_credentials)
    _prepare_manager_config_files(instances_dict, rabbitmq_credentials,
                                  load_balancer_ip)


def _print_successful_installation_message(start_time):
    running_time = time.time() - start_time
    m, s = divmod(running_time, 60)
    logger.info('Successfully installed an Active-Active cluster in ' 
                '{0} minutes and {1} seconds'.format(int(m), int(s)))


def main():
    start_time = time.time()
    config = get_dict_from_yaml(JUMP_HOST_CONFIG_PATH)
    load_balancer_ip = config.get('load_balancer_ip')
    rpm_download_link = config.get('manager_rpm_download_link')
    instances_dict = _get_instances_dict(config)
    _create_install_cluster_directory()

    logger.info('Downloading Cloudify Manager')
    run(['curl', '-o', JUMP_HOST_RPM_PATH, rpm_download_link])
    sudo(['yum', 'install', '-y', JUMP_HOST_RPM_PATH])
    _generate_certs(instances_dict)
    _prepare_config_files(instances_dict, load_balancer_ip)
    _install_instances(instances_dict, rpm_download_link)
    _show_manager_ips(instances_dict['manager'])
    _print_successful_installation_message(start_time)


if __name__ == "__main__":
    main()
