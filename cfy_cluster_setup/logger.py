import os
import sys
import logging


FORMAT_MSG = '%(name)s - %(levelname)s - %(message)s'


def setup_logger(verbose):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # paramiko.transport, invoke, and fabric are very verbose
    packages_log_level = logging.INFO if verbose else logging.WARNING
    logging.getLogger('paramiko.transport').setLevel(packages_log_level)
    logging.getLogger('invoke').setLevel(packages_log_level)
    logging.getLogger('fabric').setLevel(packages_log_level)

    logger = logging.getLogger()
    log_level = logging.DEBUG if verbose else logging.INFO
    out_sh = logging.StreamHandler(sys.stdout)
    out_sh.setLevel(log_level)
    out_sh.setFormatter(logging.Formatter(FORMAT_MSG))

    fh = logging.FileHandler(_get_log_file_path())
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(FORMAT_MSG))

    logger.addHandler(out_sh)
    logger.addHandler(fh)


def get_cfy_cluster_setup_logger():
    return logging.getLogger('[CFY-CLUSTER-SETUP]')


def _get_log_file_path():
    base = os.environ.get('CFY_WORKDIR', os.path.expanduser('~'))
    workdir = os.path.join(base, '.cloudify/logs')
    if not os.path.exists(workdir):
        os.makedirs(workdir)
    return os.path.join(workdir, 'cfy-cluster-setup.log')