import os
import uuid
from charmhelpers.core.hookenv import (
    config,
    log,
    relation_ids,
    related_units,
    relation_get,
)
from charmhelpers.contrib.openstack import context
from charmhelpers.contrib.openstack.utils import (
    os_release,
)

from charmhelpers.core.strutils import (
            bool_from_string,
)

VLAN = 'vlan'
VXLAN = 'vxlan'
GRE = 'gre'
OVERLAY_NET_TYPES = [VXLAN, GRE]
SHARED_SECRET = "/var/lib/juju/metadata-secret"


def get_l2population():
    plugin = config('neutron-plugin')
    return config('l2-population') if plugin == "ovs" else False


def get_overlay_network_type():
    overlay_networks = config('overlay-network-type').split()
    for overlay_net in overlay_networks:
        if overlay_net not in OVERLAY_NET_TYPES:
            raise ValueError('Unsupported overlay-network-type %s'
                             % overlay_net)
    return ','.join(overlay_networks)


def get_l3ha():
    if config('enable-l3ha'):
        if os_release('neutron-server') < 'juno':
            log('Disabling L3 HA, enable-l3ha is not valid before Juno')
            return False
        if get_l2population():
            log('Disabling L3 HA, l2-population must be disabled with L3 HA')
            return False
        return True
    else:
        return False


def get_dvr():
    if config('enable-dvr'):
        if os_release('neutron-server') < 'juno':
            log('Disabling DVR, enable-dvr is not valid before Juno')
            return False
        if os_release('neutron-server') == 'juno':
            if VXLAN not in config('overlay-network-type').split():
                log('Disabling DVR, enable-dvr requires the use of the vxlan '
                    'overlay network for OpenStack Juno')
                return False
        if get_l3ha():
            log('Disabling DVR, enable-l3ha must be disabled with dvr')
            return False
        if not get_l2population():
            log('Disabling DVR, l2-population must be enabled to use dvr')
            return False
        return True
    else:
        return False


def get_shared_secret():
    secret = config('metadata-shared-secret') or str(uuid.uuid4())
    if not os.path.exists(SHARED_SECRET):
        with open(SHARED_SECRET, 'w') as secret_file:
            secret_file.write(secret)
    else:
        with open(SHARED_SECRET, 'r') as secret_file:
            secret = secret_file.read().strip()
    return secret

def nova_metadata_requirement():
    enable = False
    secret = None
    for rid in relation_ids('neutron-plugin'):
        for unit in related_units(rid):
            rdata = relation_get(rid=rid, unit=unit)
            if 'metadata-shared-secret' in rdata:
                secret = rdata['metadata-shared-secret']
                enable = True
            if bool_from_string(rdata.get('enable-metadata', 'False')):
                enable = True
    return enable, secret


def get_controller_ip():
    for rid in relation_ids('neutron-plugin'):
        for unit in related_units(rid):
            return  relation_get('private-address')


class SharedSecretContext(context.OSContextGenerator):
    def __call__(self):
        ctxt = {}
        _, secret = nova_metadata_requirement()
        if secret:
            ctxt['metadata_shared_secret'] = secret
        ctxt['controller'] = get_controller_ip()
        return ctxt

class DhcpContext(context.OSContextGenerator):

    def __call__(self):
        ctxt = {
            'interface_driver ': 'linuxbridge',
        }
        return ctxt


class IdentityServiceContext(context.OSContextGenerator):
    def __call__(self):
        ctxt = self.identity_context()
        return ctxt

    def identity_context(self):
        # generate config context for neutron or quantum. these get converted
        # directly into flags in nova.conf
        # NOTE: Its up to release templates to set correct driver
        ctxt = {}
        for rid in relation_ids('neutron-plugin-api'):
            for unit in related_units(rid):
                rel = {'rid': rid, 'unit': unit}
                ctxt = {
                    'auth_protocol': relation_get(
                        'auth_protocol', **rel) or 'http',
                    'service_protocol': relation_get(
                        'service_protocol', **rel) or 'http',
                    'service_port': relation_get(
                        'service_port', **rel) or '5000',
                    'auth_host': relation_get(
                        'auth_host', **rel),
                    'service_host': relation_get(
                        'service_host', **rel) or 'http',
                    'auth_port': relation_get(
                        'auth_port', **rel),
                    'service_tenant': relation_get(
                        'service_tenant', **rel),
                    'service_username': relation_get(
                        'service_username', **rel),
                    'service_password': relation_get(
                        'service_password', **rel),
                    'api_version': relation_get(
                        'api_version', **rel) or '2.0',
                    'auth_region': relation_get(
                        'region', **rel),
                }
        return ctxt


class NeutronCCContext(context.NeutronContext):
    interfaces = []

    @property
    def network_manager(self):
        return 'neutron'

    @property
    def plugin(self):
        return config('neutron-plugin')

    @property
    def neutron_security_groups(self):
        return config('neutron-security-groups')

    @property
    def neutron_l2_population(self):
        return get_l2population()

    @property
    def neutron_overlay_network_type(self):
        return get_overlay_network_type()

    @property
    def neutron_dvr(self):
        return get_dvr()

    @property
    def neutron_l3ha(self):
        return get_l3ha()

    # Do not need the plugin agent installed on the api server
    def _ensure_packages(self):
        pass

    # Do not need the flag on the api server
    def _save_flag_file(self):
        pass

    def __call__(self):
        ctxt = super(NeutronCCContext, self).__call__()
        ctxt['l2_population'] = self.neutron_l2_population
        ctxt['enable_dvr'] = self.neutron_dvr
        ctxt['l3_ha'] = self.neutron_l3ha
        ctxt['overlay_network_type'] = self.neutron_overlay_network_type
        ctxt['external_network'] = config('neutron-external-network')
        ctxt['verbose'] = config('verbose')
        ctxt['debug'] = config('debug')

        flat_providers = config('flat-network-providers')
        if flat_providers:
            ctxt['network_providers'] = ','.join(flat_providers.split())

        vlan_ranges = config('vlan-ranges')
        if vlan_ranges:
            ctxt['vlan_ranges'] = ','.join(vlan_ranges.split())

        return ctxt

class CplaneMl2Context(context.OSContextGenerator):

    def __call__(self):
        ctxt = {}
        ctxt['physical_interface_mappings'] = config('physical-intf-mappings')
        return ctxt

