########
# Copyright (c) 2020 Cloudify Platform Ltd. All rights reserved
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
#    * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#    * See the License for the specific language governing permissions and
#    * limitations under the License.

from os import path

from setuptools import setup


def get_readme_contents():
    this_directory = path.abspath(path.dirname(__file__))
    with open(path.join(this_directory, 'README.md')) as f:
        return f.read()


setup(
    name='cloudify-cluster-manager',
    long_description=get_readme_contents(),
    long_description_content_type='text/markdown',
    version='1.0.10',
    author='Cloudify',
    author_email='cosmo-admin@cloudify.co',
    packages=['cfy_cluster_manager'],
    include_package_data=True,
    license='LICENSE',
    description="Install a Cloudify cluster",
    entry_points={
        'console_scripts': [
            'cfy_cluster_manager = cfy_cluster_manager.main:main'
        ]
    },
    install_requires=[
        'pyyaml>=5.3.0,<5.4.0',
        'jinja2>=2.11.0,<2.12.0',
        'fabric>=2.5.0,<2.6.0',
        'cryptography==3.3.2'
    ]
)
