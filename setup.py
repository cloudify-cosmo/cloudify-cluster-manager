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

from setuptools import setup


setup(
    name='cloudify-cluster-manager',
    version='0.0.1.dev1',
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
        'fabric>=2.5.0,<2.6.0'
    ]
)
