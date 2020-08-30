import os
import time
import shutil
import string
import random
from collections import OrderedDict
from os.path import expanduser, exists, join, dirname
from jinja2 import Environment, FileSystemLoader

from common import (VM, copy, get_dict_from_yaml,
                    JUMP_HOST_CONFIG_PATH, JUMP_HOST_DIR,
                    JUMP_HOST_LICENSE_PATH, JUMP_HOST_SSH_KEY_PATH,
                    logger, move, run, sudo)

CERT_PATH = '{0}/.cloudify-test-ca'.format(expanduser('~'))
RPM_NAME = 'cloudify-manager-install.rpm'
CONFIG_FILES = 'config_files'
TOP_DIR_NAME = 'cluster_install'

JUMP_HOST_RPM_PATH = join(JUMP_HOST_DIR, RPM_NAME)
LOCAL_CLUSTER_INSTALL_DIR = join(JUMP_HOST_DIR, TOP_DIR_NAME)
LOCAL_CERTS_DIR = join(LOCAL_CLUSTER_INSTALL_DIR, 'certs')
LOCAL_CONFIG_DIR = join(LOCAL_CLUSTER_INSTALL_DIR, CONFIG_FILES)

REMOTE_CLUSTER_INSTALL_DIR = join('/tmp', TOP_DIR_NAME)
REMOTE_CERTS_DIR = join(REMOTE_CLUSTER_INSTALL_DIR, 'certs')
REMOTE_RPM_PATH = join(REMOTE_CLUSTER_INSTALL_DIR, RPM_NAME)
REMOTE_CONFIG_DIR = join(REMOTE_CLUSTER_INSTALL_DIR, CONFIG_FILES)
REMOTE_CA_PATH = join(REMOTE_CERTS_DIR, 'ca.pem')


class CfyNode(VM):
    def __init__(self,
                 private_ip,
                 public_ip,
                 key_file_path,
                 username,
                 node_name):
        super(CfyNode, self).__init__(private_ip, public_ip,
                                      key_file_path, username)
        self.name = node_name
        self.cert_path = join(REMOTE_CERTS_DIR, self.name + '_cert.pem')
        self.key_path = join(REMOTE_CERTS_DIR, self.name + '_key.pem')


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
    copy(join(CERT_PATH, '.'), LOCAL_CERTS_DIR)
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

    else:
        config_dict[config_section]['cert_path'] = cert_path
        config_dict[config_section]['key_path'] = key_path
        config_dict[config_section]['ca_path'] = ca_path


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


def _prepare_postgresql_config_files(template, postgresql_instances):
    logger.info('Preparing PostgreSQL config files')
    postgresql_cluster = _get_postgresql_cluster_members(postgresql_instances)
    for node in postgresql_instances:
        rendered_data = template.render(node=node,
                                        ca_path=REMOTE_CA_PATH,
                                        postgresql_cluster=postgresql_cluster)
        _create_config_file(rendered_data, node.name)


def _prepare_rabbitmq_config_files(template, rabbitmq_instances):
    logger.info('Preparing RabbitMQ config files')
    rabbitmq_cluster = _get_rabbitmq_cluster_members(rabbitmq_instances)
    for i, node in enumerate(rabbitmq_instances):
        join_cluster = rabbitmq_instances[0].name if i > 0 else None
        rendered_data = template.render(node=node,
                                        ca_path=REMOTE_CA_PATH,
                                        join_cluster=join_cluster,
                                        rabbitmq_cluster=rabbitmq_cluster)
        _create_config_file(rendered_data, node.name)


def _prepare_manager_config_files(template,
                                  instances_dict,
                                  load_balancer_ip):
    logger.info('Preparing Manager config files')
    license_path = join(REMOTE_CLUSTER_INSTALL_DIR, 'license.yaml')
    postgresql_cluster = _get_postgresql_cluster_members(
        instances_dict['postgresql'])
    rabbitmq_cluster = _get_rabbitmq_cluster_members(
        instances_dict['rabbitmq'])
    for node in instances_dict['manager']:
        rendered_data = template.render(node=node,
                                        ca_path=REMOTE_CA_PATH,
                                        license_path=license_path,
                                        load_balancer_ip=load_balancer_ip,
                                        rabbitmq_cluster=rabbitmq_cluster,
                                        postgresql_cluster=postgresql_cluster)
        _create_config_file(rendered_data, node.name)


def _create_config_file(rendered_data, node_name):
    config_path = join(LOCAL_CONFIG_DIR, '{0}_config.yaml'.format(node_name))
    with open(config_path, 'w') as config_file:
        config_file.write(rendered_data)


def _prepare_config_files(instances_dict, load_balancer_ip):
    os.mkdir(join(LOCAL_CLUSTER_INSTALL_DIR, 'config_files'))
    templates_env = Environment(
        loader=FileSystemLoader(
            join(dirname(__file__), 'config_files_templates')))

    _prepare_postgresql_config_files(
        templates_env.get_template('postgresql_config.yaml'),
        instances_dict['postgresql'])

    _prepare_rabbitmq_config_files(
        templates_env.get_template('rabbitmq_config.yaml'),
        instances_dict['rabbitmq'])

    _prepare_manager_config_files(
        templates_env.get_template('manager_config.yaml'),
        instances_dict,
        load_balancer_ip)


def _random_credential_generator():
    return ''.join(random.choice(string.ascii_lowercase + string.digits)
                   for _ in range(40))


def _install_instances(instances_dict, rpm_download_link):
    for instance_type in instances_dict:
        logger.info('installing %s instances', instance_type)
        for instance in instances_dict[instance_type]:
            logger.info('Copying the %s directory to %s',
                        LOCAL_CLUSTER_INSTALL_DIR, instance.name)
            instance.put_dir(LOCAL_CLUSTER_INSTALL_DIR,
                             REMOTE_CLUSTER_INSTALL_DIR,
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
                'cfy_manager install'.format(
                    instance.private_ip, instance.public_ip))


def _sort_instances_dict(instances_dict):
    for _, instance_items in instances_dict.items():
        if len(instance_items) > 1:
            instance_items.sort(key=lambda x: int(x.name.rsplit('-', 1)[1]))


def _get_instances_dict(config):
    instances_dict = OrderedDict(
        (('postgresql', []), ('rabbitmq', []), ('manager', [])))
    username = config.get('machine_username')
    for node_name, node_dict in config.get('existing_vms').items():
        new_vm = CfyNode(node_dict.get('private_ip'),
                         node_dict.get('public_ip'),
                         JUMP_HOST_SSH_KEY_PATH,
                         username,
                         node_name)
        instances_dict[node_name.split('-')[0]].append(new_vm)
    _sort_instances_dict(instances_dict)
    return instances_dict


def _create_cluster_install_directory():
    logger.info('Creating `{0}` directory'.format(TOP_DIR_NAME))
    if exists(LOCAL_CLUSTER_INSTALL_DIR):
        new_dirname = (time.strftime('%Y%m%d-%H%M%S_') + TOP_DIR_NAME)
        os.rename(LOCAL_CLUSTER_INSTALL_DIR, join(JUMP_HOST_DIR, new_dirname))
        for dir_name in os.listdir(JUMP_HOST_DIR):  # Delete old dir
            if (TOP_DIR_NAME in dir_name) and (dir_name < new_dirname):
                shutil.rmtree(join(JUMP_HOST_DIR, dir_name))
                break  # There is only one
    os.mkdir(LOCAL_CLUSTER_INSTALL_DIR)

    copy(JUMP_HOST_LICENSE_PATH,
         join(LOCAL_CLUSTER_INSTALL_DIR, 'license.yaml'))


def _show_manager_ips(manager_nodes):
    managers_str = ''
    for manager in manager_nodes:
        managers_str += '{0}: {1}@{2}\n'.format(manager.name,
                                                manager.username,
                                                manager.public_ip)
    logger.info('In order to connect to one of the managers, use one of the '
                'following IPs:\n%s', managers_str)


def main():
    config = get_dict_from_yaml(JUMP_HOST_CONFIG_PATH)
    load_balancer_ip = config.get('load_balancer_ip')
    rpm_download_link = config.get('manager_rpm_download_link')
    instances_dict = _get_instances_dict(config)
    _create_cluster_install_directory()

    logger.info('Downloading Cloudify Manager')
    run(['curl', '-o', JUMP_HOST_RPM_PATH, rpm_download_link])
    sudo(['yum', 'install', '-y', JUMP_HOST_RPM_PATH])
    _generate_certs(instances_dict)
    _prepare_config_files(instances_dict, load_balancer_ip)
    _install_instances(instances_dict, rpm_download_link)
    _show_manager_ips(instances_dict['manager'])


if __name__ == "__main__":
    main()
