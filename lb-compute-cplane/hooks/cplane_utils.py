import subprocess
import os
import socket

from copy import deepcopy
from collections import OrderedDict
from charmhelpers.contrib.openstack.utils import os_release
from charmhelpers.contrib.openstack import context, templating
from charmhelpers.core.hookenv import (
    config,
    relation_ids,
    relation_get,
    related_units,
)

from charmhelpers.contrib.openstack.utils import (
    make_assess_status_func,
)

import charmhelpers.core.hookenv as hookenv


import cplane_context

TEMPLATES = 'templates/'
PACKAGES = ['neutron-dhcp-agent', 'neutron-metadata-agent', 'neutron-linuxbridge-agent']

DHCP_AGENT_INI = '/etc/neutron/dhcp_agent.ini'
NEUTRON_CONF_DIR = "/etc/neutron"
NEUTRON_CONF = '%s/neutron.conf' % NEUTRON_CONF_DIR

ML2_CONFIG = '/etc/neutron/plugins/ml2/linuxbridge_agent.ini'

BASE_RESOURCE_MAP = OrderedDict([
    (NEUTRON_CONF, {
        'services': ['neutron'],
        'contexts': [context.AMQPContext(ssl_dir=NEUTRON_CONF_DIR),
                     context.SharedDBContext(
                         user=config('database-user'),
                         database=config('database'),
                         ssl_dir=NEUTRON_CONF_DIR),
                     context.PostgresqlDBContext(database=config('database')),
                     cplane_context.IdentityServiceContext(),
                     cplane_context.NeutronCCContext(),
                     context.SyslogContext(),
                     context.WorkerConfigContext()],
    }),
    (DHCP_AGENT_INI, {
        'services': ['neutron-dhcp-agent'],
        'contexts': [cplane_context.DhcpContext(), ]
    }),
    (ML2_CONFIG, {
                'services': ['neutron-server'],
                        'contexts': [cplane_context.CplaneMl2Context(), ]
                            })
])



REQUIRED_INTERFACES = {
    'messaging': ['amqp'],
    'neutron-api': ['neutron-plugin-api'],
}
SERVICES = ['nova-compute']


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



def restart_services():
    cmd = ['service', 'neutron-linuxbridge-agent', 'restart']
    subprocess.check_call(cmd)
    cmd = ['service', 'neutron-metadata-agent', 'restart']
    subprocess.check_call(cmd)
    cmd = ['service', 'neutron-dhcp-agent', 'restart']
    subprocess.check_call(cmd)


def change_hostname():    
    cmd = ['hostnamectl', 'set-hostname', socket.getfqdn()]
    subprocess.check_call(cmd)



def register_configs(release=None):
    release = release or os_release('neutron-common')
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)
    for cfg, rscs in resource_map().items():
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


def assess_status(configs):
    assess_status_func(configs)()
    hookenv.application_version_set('nova-common')


def assess_status_func(configs):
    required_interfaces = REQUIRED_INTERFACES.copy()
    return make_assess_status_func(
        configs, required_interfaces, services=SERVICES
    )


class FakeOSConfigRenderer(object):
    def complete_contexts(self):
        interfaces = []
        for key, values in REQUIRED_INTERFACES.items():
            for value in values:
                for rid in relation_ids(value):
                    for unit in related_units(rid):
                        interfaces.append(value)
        return interfaces

    def get_incomplete_context_data(self, interfaces):
        return {}


def fake_register_configs():
    return FakeOSConfigRenderer()

