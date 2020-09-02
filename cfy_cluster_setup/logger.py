import sys
import logging


def setup_console_logger(verbose):
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)

    # paramiko.transport, invoke, and fabric are very verbose
    if not verbose:
        logging.getLogger('paramiko.transport').setLevel(logging.WARNING)
        logging.getLogger('invoke').setLevel(logging.WARNING)
        logging.getLogger('fabric').setLevel(logging.WARNING)

    logger = logging.getLogger()
    log_level = logging.DEBUG if verbose else logging.INFO
    out_sh = logging.StreamHandler(sys.stdout)
    out_sh.setLevel(log_level)
    out_sh.setFormatter(
        logging.Formatter('%(name)s - %(levelname)s - %(message)s'))
    logger.addHandler(out_sh)


def get_cfy_cluster_setup_logger():
    return logging.getLogger('[CFY-CLUSTER-SETUP]')
