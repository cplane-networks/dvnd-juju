import json
import netaddr
import os
import subprocess
import time

from collections import OrderedDict
from charmhelpers.contrib.openstack.utils import os_release, remote_restart
from charmhelpers.contrib.openstack import context, templating
from charmhelpers.core.hookenv import (
    config,
    log as juju_log,
    relation_ids,
    relation_get,
    related_units,
)

from charmhelpers.contrib.openstack.utils import (
    git_install_requested,
    git_clone_and_install,
    git_pip_venv_dir,
)

import cplane_context

from cplane_package_manager import(
    CPlanePackageManager
)

from charmhelpers.fetch import (
    apt_install,
    apt_update,
)

TEMPLATES = 'templates/'
CHARM_LIB_DIR = os.environ.get('CHARM_DIR', '') + "/lib/"

ML2_CONFIG = '/etc/neutron/plugins/ml2/ml2_conf.ini'

neutron_config = {
                     "neutron.ml2.mechanism_drivers": {
                         "cplane_mech": "neutron.plugins.ml2.drivers.cplane.mechanism_cplane:CPlaneMechanism"
                     },
                     "neutron.service_plugins": {
                         "cplane_l3": "neutron.services.l3_router.cplane.l3_router_plugin:CPlaneServicePlugin"
                     },
                     "neutron.core_plugins": {
                         "cplane_core_plugin":"neutron.plugins.cplane.cplane_plugin:CPlaneNeutronPlugin",
                         "cplane_ml2": "neutron.plugins.ml2.cplane.cplane_ml2_plugin:CPlaneML2Plugin"
                     },
                     "neutron.ml2.extension_drivers": {
                         "cplane_qos": "neutron.plugins.ml2.extensions.cplane_qos:CpQosExtensionDriver"
                     }
                 }

cplane_packages = OrderedDict([
            ('python-cplane-neutron-plugin' ,439 ),
            ('neutronclient' ,0 ),
])


PACKAGES = ['neutron-plugin-ml2', 'crudini', 'python-dev']

CPLANE_URL = "https://www.dropbox.com/s/h2edle1o0jj1btt/cplane_metadata.json?dl=1"

def determine_packages():
    return PACKAGES

def register_configs(release=None):
    resources = OrderedDict([
        (ML2_CONFIG, {
            'services': ['neutron-server'],
            'contexts': [cplane_context.CplaneMl2Context(), ]
        })
    ])
    release = os_release('neutron-common')
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)
    for cfg, rscs in resources.iteritems():
        configs.register(cfg, rscs['contexts'])
    return configs


def api_ready(relation, key):
    ready = 'no'
    for rid in relation_ids(relation):
        for unit in related_units(rid):
            ready = relation_get(attribute=key, unit=unit, rid=rid)
    return ready == 'yes'


def is_neutron_api_ready():
    return api_ready('neutron-plugin-api-subordinate', 'neutron-api-ready')

def crudini_set(_file, section, key, value):
    option = '--set'
    cmd = ['crudini', option, _file, section, key, value ]
    subprocess.check_call(cmd)

def cplane_config(data, config_file):
    for section in data:
        _data = data.get(section)
        for key in _data:
            value = _data.get(key, "")
            crudini_set(config_file, section, key, value)


def install_cplane_packages():
    cp_package = CPlanePackageManager(CPLANE_URL)
    for key, value in cplane_packages.items():
        filename = cp_package.download_package(key, value)
        if key == "neutronclient":
            cmd = ['tar', '-xvf', filename, '-C', '/usr/lib/python2.7/dist-packages/']
            subprocess.check_call(cmd)
        else:
            cmd = ['dpkg', '-i', filename]
            subprocess.check_call(cmd)
            options = "--fix-broken"
            apt_install(options, fatal=True)

def create_link():
    cmd = ['rm', '-f', '/etc/neutron/plugin.ini']
    subprocess.check_call(cmd)
    cmd = ['ln', '-s', ML2_CONFIG, '/etc/neutron/plugin.ini']
    subprocess.check_call(cmd)

def restart_service():
    cmd = ['service', 'neutron-server', 'restart']
    subprocess.check_call(cmd)

def python_intall(package):
    cmd = ['pip', 'install', package]
    subprocess.check_call(cmd)

def migrate_db():
    cmd = ['neutron-db-manage', '--config-file', '/etc/neutron/neutron.conf', '--config-file', '/etc/neutron/plugins/ml2/ml2_conf.ini', 'upgrade', 'head']
    subprocess.check_call(cmd)
