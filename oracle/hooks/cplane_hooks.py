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
    configure_host,
    install_reboot_scripts,
    assess_status,
    fake_register_configs,
)

hooks = Hooks()


@hooks.hook('oracle-relation-joined')
def oracle_relation_joined():
    host = unit_get('private-address')
    relation_info = {
        'oracle-host': host,
        'db-password': config('oracle-password'),
        'db-service': 'XE',
        'db-path': '/u01/app/oracle/oradata/XE/'
    }
    relation_set(relation_settings=relation_info)


@hooks.hook('install.real')
def install():
    pkgs = determine_packages()
    apt_install(pkgs, fatal=True)
    configure_host()
    download_cplane_packages()
    install_oracle()
    configure_oracle()
    install_reboot_scripts()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        juju_log('Unknown hook {} - skipping.'.format(e))
    assess_status(fake_register_configs())


if __name__ == '__main__':
    main()
