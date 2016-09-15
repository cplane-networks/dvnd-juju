from charmhelpers.core.hookenv import (
    config,
    unit_private_ip,
)

from charmhelpers.contrib.openstack import context


class CplaneMetadataContext(context.OSContextGenerator):
    interfaces = ['neutron-plugin']
    metadata_keys = [
        'metadata_ip',
        'shared_secret',
    ]

    def _cplane_context(self):
        ctxt = {'metadata_ip': unit_private_ip()}
        return ctxt

    def __call__(self):
        ctxt = self._cplane_context()
        if not ctxt:
            return {}
        ctxt['shared_secret'] = config('metadata-shared-secret')
        return ctxt


class IdentityServiceContext(context.IdentityServiceContext):

    def __call__(self):
        ctxt = super(IdentityServiceContext, self).__call__()
        if not ctxt:
            return
        ctxt['region'] = config('region')

        return ctxt
