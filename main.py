import argparse
from os.path import join, dirname

import common

INSTALL_CLUSTER_SCRIPT = 'install_cluster.py'


def _prepare_jump_host(jump_host, license_path, config_path):
    commands_list = [
        'sudo yum install -y epel-release',
        'sudo yum install -y python-pip',
        'sudo yum groupinstall -y \"Development Tools\"',
        'sudo yum install -y python-devel',
        'sudo pip install --upgrade pip==9.0.1',
        'sudo pip install -r {0}'.format(join(common.JUMP_HOST_DIR,
                                              'requirements.txt'))
    ]
    scp_files_list = [
        'requirements.txt',
        INSTALL_CLUSTER_SCRIPT,
        'common.py',
        'manager_config.yaml',
        'postgresql_config.yaml',
        'rabbitmq_config.yaml',
    ]
    common.logger.info('Preparing the jump-host')
    if jump_host.path_exists(common.JUMP_HOST_DIR):
        jump_host.run_command('rm -rf {}'.format(common.OLD_JUMP_HOST_DIR))
        jump_host.run_command('mv {0} {1}'.format(common.JUMP_HOST_DIR,
                                                  common.OLD_JUMP_HOST_DIR))
    jump_host.run_command('mkdir {0}'.format(common.JUMP_HOST_DIR))

    for file_name in scp_files_list:
        jump_host.put_file(join(dirname(__file__), file_name),
                           join(common.JUMP_HOST_DIR, file_name))
    for command in commands_list:
        jump_host.run_command(command)

    jump_host.put_file(jump_host.key_file_path, common.JUMP_HOST_SSH_KEY_PATH)
    jump_host.run_command('chmod 400 {}'.format(common.JUMP_HOST_SSH_KEY_PATH))
    jump_host.put_file(config_path, common.JUMP_HOST_CONFIG_PATH)
    jump_host.put_file(license_path, common.JUMP_HOST_LICENSE_PATH)


def main():
    parser = argparse.ArgumentParser(description='Installing an Active-Active '
                                                 'manager cluster')
    parser.add_argument('--config-path',
                        action='store',
                        default='cluster_config.yaml',
                        help='The cluster_config.yaml file path')

    config_path = parser.parse_args().config_path
    config = common.get_dict_from_yaml(config_path)

    jump_host_ip = config.get('jump_host_ip')
    jump_host = common.VM(jump_host_ip,
                          jump_host_ip,
                          config.get('key_file_path'),
                          config.get('machine_username'))

    _prepare_jump_host(jump_host, config.get('cloudify_license_path'),
                       config_path)
    jump_host.run_command('python {}'.format(
        join(common.JUMP_HOST_DIR, INSTALL_CLUSTER_SCRIPT)))


if __name__ == "__main__":
    main()
