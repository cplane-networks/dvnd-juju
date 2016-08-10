from charmhelpers.core.hookenv import (
    config,
    relation_ids,
    related_units,
    relation_get,
    log,
)

from charmhelpers.contrib.openstack import context

VLAN = 'vlan'
VXLAN = 'vxlan'
GRE = 'gre'
OVERLAY_NET_TYPES = [VXLAN, GRE]


def get_overlay_network_type():
    overlay_networks = config('overlay-network-type').split()
    for overlay_net in overlay_networks:
        if overlay_net not in OVERLAY_NET_TYPES:
            raise ValueError('Unsupported overlay-network-type %s'
                             % overlay_net)
    return ','.join(overlay_networks)


class CplaneMl2Context(context.OSContextGenerator):
    interfaces = ['cp_controller']
    ml2_keys = [
        'controller_ip',
        'controller_port',
        'overlay_network_type',
        'security_groups',
    ]

    def _cplane_context(self):
        for rid in relation_ids('cp_controller'):
            for unit in related_units(rid):
                ctxt = {}
                rel_data = relation_get(unit=unit, rid=rid)
                for k in self.ml2_keys:
                    ctxt[k] = rel_data.get(k)
                if None not in ctxt.values():
                    return ctxt

        log('Cplane controller relation data incomplete/relation not set, \
             get data from config')

        ctxt = {'controller_ip': config('cplane-controller_ip'),
                'controller_port': config('cplane-controller_port')}
        return ctxt

    def __call__(self):
        ctxt = self._cplane_context()
        if not ctxt:
            return {}
        ctxt['vlan_ranges'] = config('vlan-ranges')
        ctxt['overlay_network_type'] = get_overlay_network_type()
        ctxt['security_groups'] = config('security-groups')
        return ctxt
