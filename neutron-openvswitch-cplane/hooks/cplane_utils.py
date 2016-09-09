import subprocess
import os
import uuid

from collections import OrderedDict
from charmhelpers.core.hookenv import (
    config,
    log as juju_log,
    relation_ids,
    relation_get,
    related_units,
)

from charmhelpers.fetch import (
    apt_install,
)


from cplane_package_manager import(
    CPlanePackageManager
)

from cplane_network import (
    add_bridge,
    check_interface,
)

cplane_packages = OrderedDict([
    ('python-cplane-neutron-plugin', 439),
    ('openvswitch-common', 0),
    ('openvswitch-datapath-dkms', 0),
    ('openvswitch-switch', 0),
    ('cp-agentd', 396),
])

neutron_config = {
    'rabbit_userid': config('rabbit-user'),
    'rabbit_virtual_host': config('rabbit-vhost'),
    'rabbit_password': 'password',
    'rabbit_host': 'localhost',
}

NEUTRON_CONF = '/etc/neutron/neutron.conf'

PACKAGES = ['neutron-metadata-agent', 'neutron-plugin-ml2', 'crudini',
            'dkms', 'iputils-arping', 'dnsmasq']

METADATA_AGENT_INI = '/etc/neutron/metadata_agent.ini'

CPLANE_URL = config('cp-package-url')

metadata_agent_config = OrderedDict([
    ('auth_url', 'http://' + config('openstack-controller-ip') + ':5000/v2.0'),
    ('auth_region', config('region')),
    ('admin_tenant_name', 'service'),
    ('admin_user', config('admin-user')),
    ('admin_password', config('admin-password')),
    ('metadata_proxy_shared_secret', 'secret'),
])

SYSTEM_CONF = '/etc/sysctl.conf'
system_config = OrderedDict([
    ('net.ipv4.conf.all.rp_filter', '0'),
    ('net.ipv4.ip_forward', '1'),
    ('net.ipv4.conf.default.rp_filter', '0'),
    ('net.bridge.bridge-nf-call-iptables', '1'),
    ('net.bridge.bridge-nf-call-ip6tables', '1'),
])

SHARED_SECRET = "/var/lib/juju/metadata-secret"


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


def disable_neutron_agent():
    cmd = ['service', 'neutron-plugin-openvswitch-agent', 'stop']
    subprocess.check_call(cmd)

    cmd = ['update-rc.d', 'neutron-plugin-openvswitch-agent', 'disable']
    subprocess.check_call(cmd)


def crudini_set(_file, section, key, value):
    option = '--set'
    cmd = ['crudini', option, _file, section, key, value]
    subprocess.check_call(cmd)


def cplane_config(data, config_file, section):
    for key, value in data.items():
        crudini_set(config_file, section, key, value)


def install_cplane_packages():

    cp_package = CPlanePackageManager(CPLANE_URL)
    for key, value in cplane_packages.items():
        filename = cp_package.download_package(key, value)
        cmd = ['dpkg', '-i', filename]
        subprocess.check_call(cmd)
        options = "--fix-broken"
        apt_install(options, fatal=True)


def manage_fip():
    for rid in relation_ids('cplane-controller-ovs'):
        for unit in related_units(rid):
            fip_set = relation_get(attribute='fip-set', unit=unit, rid=rid)
            if fip_set:
                if check_interface(config('fip-interface')):
                    add_bridge('br-fip', config('fip-interface'))
                else:
                    juju_log('Fip interface doesnt exist, and \
                    will be used by default by Cplane controller')


def set_cp_agent():
    mport = 0
    for rid in relation_ids('cplane-controller-ovs'):
        for unit in related_units(rid):
            mport = relation_get(attribute='mport', unit=unit, rid=rid)
            cplane_controller = relation_get('private-address')
            if mport:
                key = 'mcast-port=' + mport
                cmd = ['cp-agentd', 'set-config', key]
                subprocess.check_call(cmd)
                key = 'mgmt-iface=' + config('mgmt-int')
                cmd = ['cp-agentd', 'set-config', key]
                subprocess.check_call(cmd)
                key = 'ucast-ip=' + cplane_controller
                cmd = ['cp-agentd', 'set-config', key]
                subprocess.check_call(cmd)
                key = 'ucast-port=' + str(config('cp-controller-uport'))
                cmd = ['cp-agentd', 'set-config', key]
                subprocess.check_call(cmd)
                key = 'log-level=file:' + str(config('cp-agent-log-level'))
                cmd = ['cp-agentd', 'set-config', key]
                subprocess.check_call(cmd)
                return
    key = 'mcast-port=' + str(config('cp-controller-mport'))
    cmd = ['cp-agentd', 'set-config', key]
    subprocess.check_call(cmd)
    key = 'mgmt-iface=' + config('mgmt-int')
    cmd = ['cp-agentd', 'set-config', key]
    subprocess.check_call(cmd)
    key = 'ucast-ip=' + config('cplane-controller-ip')
    cmd = ['cp-agentd', 'set-config', key]
    subprocess.check_call(cmd)
    key = 'ucast-port=' + str(config('cp-controller-uport'))
    cmd = ['cp-agentd', 'set-config', key]
    subprocess.check_call(cmd)
    key = 'log-level=file:' + str(config('cp-agent-log-level'))
    cmd = ['cp-agentd', 'set-config', key]
    subprocess.check_call(cmd)


def restart_services():
    cmd = ['service', 'neutron-metadata-agent', 'restart']
    subprocess.check_call(cmd)
    cmd = ['service', 'openvswitch-switch', 'restart']
    subprocess.check_call(cmd)
    cmd = ['service', 'cp-agentd', 'stop']
    subprocess.check_call(cmd)
    cmd = ['service', 'cp-agentd', 'start']
    subprocess.check_call(cmd)

    cmd = ['update-rc.d', 'cp-agentd', 'enable']
    subprocess.check_call(cmd)


def get_shared_secret():
    secret = None
    if not os.path.exists(SHARED_SECRET):
        secret = str(uuid.uuid4())
        with open(SHARED_SECRET, 'w') as secret_file:
            secret_file.write(secret)
    else:
        with open(SHARED_SECRET, 'r') as secret_file:
            secret = secret_file.read().strip()
    return secret
