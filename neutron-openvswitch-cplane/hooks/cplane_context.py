import os
import uuid

from charmhelpers.core.hookenv import (
    config,
    relation_ids,
    related_units,
    relation_get,
)

import charmhelpers.contrib.openstack.context as context


SHARED_SECRET = "/var/lib/juju/metadata-secret"


def get_shared_secret():
    secret = config('metadata-shared-secret') or str(uuid.uuid4())
    if not os.path.exists(SHARED_SECRET):
        with open(SHARED_SECRET, 'w') as secret_file:
            secret_file.write(secret)
    else:
        with open(SHARED_SECRET, 'r') as secret_file:
            secret = secret_file.read().strip()
    return secret


class SharedSecretContext(context.OSContextGenerator):

    def __call__(self):
        ctxt = {
            'shared_secret': get_shared_secret(),
        }
        return ctxt


class APIIdentityServiceContext(context.IdentityServiceContext):

    def __init__(self):
        super(APIIdentityServiceContext,
              self).__init__(rel_name='neutron-plugin-api')

    def __call__(self):
        ctxt = super(APIIdentityServiceContext, self).__call__()
        if not ctxt:
            return
        for rid in relation_ids('neutron-plugin-api'):
            for unit in related_units(rid):
                rdata = relation_get(rid=rid, unit=unit)
                ctxt['region'] = rdata.get('region')
                if ctxt['region']:
                    return ctxt
        return ctxt
