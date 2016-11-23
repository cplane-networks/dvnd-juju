#!/usr/bin/env python
from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log as juju_log,
    relation_set
)
import sys

from charmhelpers.fetch import (
    apt_install,
    apt_update,
)

from cplane_utils import (
    determine_packages,
    download_cplane_packages,
    download_cplane_installer,
    prepare_env,
    install_jboss,
    install_jdk,
    install_oracle,
    configure_oracle,
    cplane_installer,
    start_services,
    check_fip_mode,
    get_upgrade_type,
    stop_jboss_service,
    clean_create_db,
    check_jboss_service,
    run_cp_installer,
    install_reboot_scripts,
)


hooks = Hooks()


@hooks.hook('cplane-controller-relation-joined')
def cplane_controller_relation_changed():
    if check_fip_mode() == 'true':
        fip_mode = True
    else:
        fip_mode = False
    relation_info = {
        'fip-mode': fip_mode,
        'mport': config('multicast-port'),
        'uport': config('unicast-port')
    }
    relation_set(relation_settings=relation_info)


@hooks.hook('upgrade-charm')
def upgrade_charm():
    download_cplane_installer()
    upgrade_type = get_upgrade_type()
    stop_jboss_service()
    if upgrade_type == 'clean-db':
        clean_create_db()
    cplane_installer('upgrade')
    start_services(upgrade_type)


@hooks.hook('install')
def install():
    apt_update(fatal=True)
    pkgs = determine_packages()
    apt_install(pkgs, fatal=True)
    prepare_env()
    download_cplane_packages()
    install_jboss()
    install_jdk()
    install_oracle()
    configure_oracle()
    cplane_installer('install')
    if config('intall-reboot-scripts') == 'y':
        install_reboot_scripts()


@hooks.hook('start')
def start():
    start_services('clean-db')


@hooks.hook('config-changed')
def config_changed():
    if check_jboss_service() is True:
        stop_jboss_service()
        run_cp_installer()
        start_services('config-change')


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        juju_log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()
