import json
import netaddr
import os
import subprocess
import time

from copy import deepcopy
from collections import OrderedDict
from charmhelpers.contrib.openstack.utils import os_release, remote_restart
from charmhelpers.contrib.openstack import context, templating
from charmhelpers.core.hookenv import (
    config,
    log,
    log as juju_log,
    relation_ids,
    relation_get,
    relation_get,
    related_units,
    unit_private_ip,
)

from charmhelpers.contrib.openstack.utils import (
    git_install_requested,
    git_clone_and_install,
    git_pip_venv_dir,
)

from charmhelpers.fetch import (
    apt_install,
    apt_update,
)
import cplane_context

TEMPLATES = 'templates/'

PACKAGES = ['sysfsutils', 'neutron-metadata-agent', 'python-neutronclient', 'crudini', 'conntrack', 'neutron-plugin-ml2', 'neutron-plugin-linuxbridge-agent']

METADATA_AGENT_INI = '/etc/neutron/metadata_agent.ini'
NEUTRON_CONF_DIR = "/etc/neutron"
NEUTRON_CONF = '%s/neutron.conf' % NEUTRON_CONF_DIR

BASE_RESOURCE_MAP = OrderedDict([
    (NEUTRON_CONF, {
        'services': ['neutron'],
        'contexts': [context.AMQPContext(ssl_dir=NEUTRON_CONF_DIR),
                     context.SharedDBContext(
                         user=config('database-user'),
                         database=config('database'),
                         ssl_dir=NEUTRON_CONF_DIR),
                     context.PostgresqlDBContext(database=config('database')),
                     cplane_context.IdentityServiceContext(
                         service='neutron',
                         service_user='neutron'),
                     cplane_context.NeutronCCContext(),
                     context.SyslogContext(),
                     context.ZeroMQContext(),
                     context.NotificationDriverContext(),
                     context.BindHostContext(),
                     context.WorkerConfigContext()],
    }),
    (METADATA_AGENT_INI, {
        'services': ['metadata-agent'],
        'contexts': [cplane_context.IdentityServiceContext(
                         service='neutron',
                         service_user='neutron')],
    }),

])


metadata_agent_config = OrderedDict([
            ('auth_region', config('region')),
            ('nova_metadata_ip', config('openstack-controller-ip')),
            ('metadata_proxy_shared_secret', 'secret'),
])

def api_ready(relation, key):
    ready = 'no'
    for rid in relation_ids(relation):
        for unit in related_units(rid):
            ready = relation_get(attribute=key, unit=unit, rid=rid)
    return ready == 'yes'


def is_neutron_api_ready():
    return api_ready('neutron-plugin-api-subordinate', 'neutron-api-ready')

def determine_packages():
    return PACKAGES


def crudini_set(_file, section, key, value):
    option = '--set'
    cmd = ['crudini', option, _file, section, key, value ]
    subprocess.check_call(cmd)

def cplane_config(data, config_file, section):
    for key, value in data.items():
       crudini_set(config_file, section, key, value)

def restart_services():
    cmd = ['service', 'nova-compute', 'restart']
    subprocess.check_call(cmd)

def remmove_sql_lite():
    cmd = ['rm', '-f', '/var/lib/nova/nova.sqlite']
    subprocess.check_call(cmd)

def register_configs(release=None):
    release = release or os_release('neutron-common')
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)
    for cfg, rscs in resource_map().iteritems():
        configs.register(cfg, rscs['contexts'])
    return configs

def resource_map(release=None):
    '''
    Dynamically generate a map of resources that will be managed for a single
    hook execution.
    '''
    release = release or os_release('neutron-common')
    resource_map = deepcopy(BASE_RESOURCE_MAP)
    return resource_map

