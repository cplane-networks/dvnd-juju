from charmhelpers.contrib.openstack import context
from charmhelpers.contrib.hahelpers.cluster import (
    determine_api_port,
    determine_apache_port,
)


class HAProxyContext(context.HAProxyContext):
    interfaces = []

    def __call__(self):
        from cplane_utils import api_port
        ctxt = super(HAProxyContext, self).__call__()

        # Apache ports
        a_msm_api = determine_apache_port(api_port('msm'),
                                          singlenode_mode=True)

        port_mapping = {
            'msm': [
                api_port('msm'), a_msm_api]
        }

        ctxt['msm_bind_port'] = determine_api_port(
            api_port('msm'),
            singlenode_mode=True,
        )

        # for haproxy.conf
        ctxt['service_ports'] = port_mapping
        return ctxt
