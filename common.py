import os
import sys
import shlex
import logging
import subprocess
from os.path import dirname, exists, expanduser, isdir, isfile, join
from socket import error as socket_error

import yaml
from fabric import Connection
from paramiko import AuthenticationException


DIR_NAME = 'cloudify_cluster_setup'
JUMP_HOST_DIR = join('/tmp', DIR_NAME)
OLD_JUMP_HOST_DIR = join('/tmp', DIR_NAME+'_old')
JUMP_HOST_SSH_KEY_PATH = join(JUMP_HOST_DIR, 'jump_host_key.pem')
JUMP_HOST_CONFIG_PATH = join(JUMP_HOST_DIR, 'config_cluster.yaml')
JUMP_HOST_LICENSE_PATH = join(JUMP_HOST_DIR, 'cloudify_license.yaml')
JUMP_HOST_CREDENTIALS_FILE = join(JUMP_HOST_DIR, 'secret_credentials.yaml')


def init_logger():
    log = logging.getLogger('MAIN')
    log.setLevel(logging.INFO)
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.DEBUG)
    formatter = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    log.addHandler(handler)
    return log


logger = init_logger()


class ClusterInstallError(Exception):
    pass


class ProcessExecutionError(ClusterInstallError):
    def __init__(self, message, return_code=None):
        self.return_code = return_code
        super(ProcessExecutionError, self).__init__(message)


def run(command, retries=0, ignore_failures=False):
    if isinstance(command, str):
        command = shlex.split(command)
    logger.debug('Running: {0}'.format(command))
    proc = subprocess.Popen(command, stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc.aggr_stdout, proc.aggr_stderr = proc.communicate(input=u'')
    if proc.aggr_stdout is not None:
        proc.aggr_stdout = proc.aggr_stdout.decode('utf-8')
    if proc.aggr_stderr is not None:
        proc.aggr_stderr = proc.aggr_stderr.decode('utf-8')
    if proc.returncode != 0:
        if retries:
            logger.warn('Failed running command: %s. Retrying. '
                        '(%s left)', command, retries)
            proc = run(command, retries - 1)
        elif not ignore_failures:
            msg = 'Failed running command: {0} ({1}).'.format(
                command, proc.aggr_stderr)
            err = ProcessExecutionError(msg, proc.returncode)
            err.aggr_stdout = proc.aggr_stdout
            err.aggr_stderr = proc.aggr_stderr
            raise err
    return proc


def sudo(command, *args, **kwargs):
    if isinstance(command, str):
        command = shlex.split(command)
    command.insert(0, 'sudo')
    return run(command=command, *args, **kwargs)


def ensure_destination_dir_exists(destination):
    destination_dir = dirname(destination)
    if not exists(destination_dir):
        sudo(['mkdir', '-p', destination_dir])


def copy(source, destination):
    ensure_destination_dir_exists(destination)
    sudo(['cp', '-rp', source, destination])


def move(source, destination):
    ensure_destination_dir_exists(destination)
    sudo(['mv', source, destination])


class VM(object):
    def __init__(self,
                 private_ip,
                 public_ip,
                 key_file_path,
                 username):
        self.username = username
        self.private_ip = private_ip
        self.public_ip = public_ip
        self.key_file_path = expanduser(key_file_path)

    def _get_connection(self):
        connection = Connection(
            host=self.private_ip, user=self.username, port=22,
            connect_kwargs={'key_filename': self.key_file_path})
        try:  # Connection is lazy, so **we** need to check it can be opened
            connection.open()
        except (socket_error, AuthenticationException) as exc:
            raise ClusterInstallError(
                "SSH: could not connect to {host} (username: {user}, "
                "key: {key}): {exc}".format(
                    host=self.private_ip, user=self.username,
                    key=self.key_file_path, exc=exc))
        finally:
            connection.close()

        return connection

    def run_command(self, command, use_sudo=False):
        with self._get_connection() as connection:
            logger.debug('Running `%s` on %s', command, self.private_ip)
            result = (connection.sudo(command, warn=True, hide='stderr')
                      if use_sudo else
                      connection.run(command, warn=True, hide='stderr'))
            if result.failed:
                raise ClusterInstallError(
                    'The command `{0}` on host {1} failed with the '
                    'error {2}'.format(command, self.private_ip,
                                       result.stderr.encode('utf-8')))

    def put_file(self, local_path, remote_path):
        if not isfile(local_path):
            raise ClusterInstallError(
                '{} is not a file'.format(local_path))

        with self._get_connection() as connection:
            logger.debug('Copying %s to %s on host %a',
                         local_path, remote_path, self.private_ip)
            connection.put(expanduser(local_path), remote_path)

    def get_file(self, remote_path, local_path):
        with self._get_connection() as connection:
            logger.debug('Copying %s to %s from host %a',
                         remote_path, local_path, self.private_ip)
            connection.get(remote_path, expanduser(local_path))

    def put_dir(self, local_dir_path, remote_dir_path, override=False):
        """Copy a local directory to a remote host.

        :param local_dir_path: An existing local directory path.
        :param remote_dir_path: A directory path on the remote host. If the
                                path doesn't exist, it will be created.
        :param override: If True and the remote directory path exists, then
                         it will be deleted.
                         If False and the remote directory path exists, then
                         the files from the local directory will be added to
                         the remote one.
                         If the remote directory path doesn't exist, it
                         doesn't have any effect.
        """
        if not isdir(local_dir_path):
            raise ClusterInstallError(
                '{} is not a directory'.format(local_dir_path))

        logger.debug('Copying %s to %s on host %a',
                     local_dir_path, remote_dir_path, self.private_ip)
        if override:
            self.run_command('rm -rf {}'.format(remote_dir_path))
        self.run_command('mkdir -p {}'. format(remote_dir_path))
        for file_name in os.listdir(local_dir_path):
            object_path = join(local_dir_path, file_name)
            if isfile(object_path):
                self.put_file(join(local_dir_path, file_name), remote_dir_path)
            elif isdir(object_path):
                self.put_dir(object_path, join(remote_dir_path, file_name))

    def path_exists(self, path):
        try:
            self.run_command('test -e {0}'.format(path), use_sudo=True)
        except ClusterInstallError:
            return False
        return True


def get_dict_from_yaml(yaml_path):
    with open(yaml_path) as yaml_file:
        yaml_dict = yaml.load(yaml_file, yaml.Loader)
    return yaml_dict
