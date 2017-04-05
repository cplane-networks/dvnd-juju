from charmhelpers.core.hookenv import (
    config,
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
        return ctxt
