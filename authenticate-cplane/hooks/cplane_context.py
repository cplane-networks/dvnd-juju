from charmhelpers.core.hookenv import (
    config,
)

from charmhelpers.contrib.openstack import context


class CplaneKeystoneContext(context.OSContextGenerator):
    def __init__(self, database_host, database_service):
        self.database_host = database_host
        self.database_service = database_service

    def _cplane_context(self):
        ctxt = {'database_host': self.database_host,
                'database_service': self.database_service,
                'database_user': config('database-user'),
                'database_password': config('database-password'),
                'database_type': config('database-type'),
                'database_port': config('database-port')}

        return ctxt

    def __call__(self):
        ctxt = self._cplane_context()
        if not ctxt:
            return {}
        return ctxt
