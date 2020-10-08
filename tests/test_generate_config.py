import os
import tempfile
import pkg_resources
from os.path import join

import mock
import yaml
import pytest

from cfy_cluster_manager.main import generate_config
from cfy_cluster_manager.utils import ClusterInstallError

CONFIG_FILES_PATH = pkg_resources.resource_filename(
    'cfy_cluster_manager', 'cfy_cluster_config_files')


@pytest.mark.parametrize('using_external_db', [True, False])
def test_generate_three_nodes_config(using_external_db):
    outfile_path = tempfile.mkstemp()[1]
    with mock.patch('cfy_cluster_manager.main.input', return_value='yes'):
        generate_config(output_path=outfile_path, verbose=False,
                        using_three_nodes=True, using_nine_nodes=False,
                        using_external_db=using_external_db)
    config_name = ('cfy_three_nodes_external_db_cluster_config.yaml'
                   if using_external_db else
                   'cfy_three_nodes_cluster_config.yaml')
    _assert_same_config_contentents(outfile_path, config_name)
    os.remove(outfile_path)


@pytest.mark.parametrize('using_external_db', [True, False])
def test_generate_nine_nodes_config(using_external_db):
    outfile_path = tempfile.mkstemp()[1]
    with mock.patch('cfy_cluster_manager.main.input', return_value='yes'):
        generate_config(output_path=outfile_path, verbose=True,
                        using_three_nodes=False, using_nine_nodes=True,
                        using_external_db=using_external_db)
    config_name = ('cfy_nine_nodes_external_db_cluster_config.yaml'
                   if using_external_db else
                   'cfy_nine_nodes_cluster_config.yaml')
    _assert_same_config_contentents(outfile_path, config_name)
    os.remove(outfile_path)


def test_fail_three_and_nine_nodes_not_supplied():
    with pytest.raises(ClusterInstallError):
        generate_config(output_path=None, verbose=True,
                        using_three_nodes=False, using_nine_nodes=False,
                        using_external_db=False)


def _assert_same_config_contentents(output_path, config_name):
    """Assert the output file is the same as the config file."""
    with open(join(CONFIG_FILES_PATH, config_name)) as config_file:
        config_dict = yaml.load(config_file, yaml.Loader)
    with open(output_path) as output_file:
        output_dict = yaml.load(output_file, yaml.Loader)
    err_msg = ('The output file {0} is not the same as the config file '
               '{1}'.format(output_path, config_name))
    assert config_dict == output_dict, err_msg
