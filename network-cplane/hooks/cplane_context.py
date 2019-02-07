from charmhelpers.core.hookenv import (
    config,
    unit_get,
    relation_get,
    relation_ids,
    related_units,
)

from charmhelpers.contrib.openstack import context

VLAN = 'vlan'
VXLAN = 'vxlan'
GRE = 'gre'
OVERLAY_NET_TYPES = [VXLAN, GRE]


class CplaneNeutronContext(context.OSContextGenerator):
    def __init__(self, database_host, database_service):
        self.database_host = database_host
        self.database_service = database_service

    def _cplane_context(self):
        ctxt = {'database_host': self.database_host,
                'database_service': self.database_service,
                'database_user': config('database-user'),
                'database_password': config('database-password'),
                'database_type': config('database-type'),
                'database_port': config('database-port'),
                'local_ip': unit_get('private-address')}
        
        for rid in relation_ids('auth'):
            for unit in related_units(rid):
                rel = {'rid': rid, 'unit': unit}
                ctxt['auth_ip'] = relation_get('private-address', **rel)


        return ctxt

    def __call__(self):
        ctxt = self._cplane_context()
        if not ctxt:
            return {}
        return ctxt

def get_overlay_network_type():
    overlay_networks = config('overlay-network-type').split()
    for overlay_net in overlay_networks:
        if overlay_net not in OVERLAY_NET_TYPES:
            raise ValueError('Unsupported overlay-network-type %s'
                             % overlay_net)
    return ','.join(overlay_networks)


class CplaneMl2Context(context.OSContextGenerator):
    def _cplane_context(self):
        ctxt = {'controller_ip': config('cplane-controller_ip'),
                'cplane_topology_name': config('topology-name')}
        return ctxt

    def __call__(self):
        ctxt = self._cplane_context()
        if not ctxt:
            return {}
        ctxt['vlan_ranges'] = config('vlan-ranges')
        ctxt['overlay_network_type'] = get_overlay_network_type()
        ctxt['security_groups'] = config('security-groups')
        ctxt['controller_port'] = config('cplane-controller_port')
        ctxt['network_vlan_ranges'] = config('vlan-ranges')
        return ctxt
