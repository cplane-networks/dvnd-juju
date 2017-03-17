#!/usr/bin/env python
from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    log as juju_log,
    unit_get,
    config,
    relation_set,
)
import sys

from charmhelpers.fetch import (
    apt_install,
)

from cplane_utils import (
    determine_packages,
    download_cplane_packages,
    install_oracle,
    configure_oracle,
    install_reboot_scripts,
)

hooks = Hooks()


@hooks.hook('oracle-relation-joined')
def oracle_relation_joined():
    host = unit_get('private-address')
    relation_info = {
        'oracle-host': host,
        'db-password': config('oracle-password'),
        'db-service': 'XE'
    }
    relation_set(relation_settings=relation_info)


@hooks.hook('install')
def install():
    pkgs = determine_packages()
    apt_install(pkgs, fatal=True)
    download_cplane_packages()
    install_oracle()
    configure_oracle()
    install_reboot_scripts()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        juju_log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()
