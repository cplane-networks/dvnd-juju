#!/usr/bin/env python
from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log as juju_log,
    relation_set,
    relation_ids,
)
import sys
import commands

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
    set_oracle_host,
    install_oracle_client,
    configure_oracle_client,
    prepare_database,
    set_oracle_env,
    flush_upgrade_type,
    get_unit_ip,
)


hooks = Hooks()


@hooks.hook('cplane-controller-relation-joined')
def cplane_controller_relation_joined(rid=None):
    tm = commands.getoutput("date")
    if check_fip_mode() == 'true':
        fip_mode = True
    else:
        fip_mode = False
    relation_info = {
        'fip-mode': fip_mode,
        'mport': config('multicast-port'),
        'uport': config('unicast-port'),
        'rel-time': tm,
        'private-address': get_unit_ip(),
        'hostname': get_unit_ip(),
    }
    relation_set(relation_id=rid, relation_settings=relation_info)


@hooks.hook('upgrade-charm')
def upgrade_charm():
    download_cplane_installer()
    upgrade_type = get_upgrade_type()
    stop_jboss_service()
    if upgrade_type == 'clean-db':
        clean_create_db()
    cplane_installer()
    if config('intall-reboot-scripts') == 'y':
        install_reboot_scripts()
    start_services(upgrade_type)


@hooks.hook('install.real')
def install():
    apt_update(fatal=True)
    pkgs = determine_packages()
    apt_install(pkgs, fatal=True)
    prepare_env()
    flush_upgrade_type()
    download_cplane_packages()
    install_jboss()
    install_jdk()
    if config('jboss-db-on-host'):
        install_oracle()
        configure_oracle()
    else:
        install_oracle_client()
        configure_oracle_client()
    cplane_installer()
    if config('intall-reboot-scripts') == 'y':
        install_reboot_scripts()


@hooks.hook('start')
def start():
    if config('jboss-db-on-host'):
        oracle_host = set_oracle_host()
        if oracle_host:
            set_oracle_env()
            prepare_database()
            start_services('create-db')


@hooks.hook('oracle-relation-changed')
def oracle_relation_changed():
    if config('jboss-db-on-host') is False:
        oracle_host = set_oracle_host()
        if oracle_host:
            if check_jboss_service() is False:
                cplane_installer()
                if config('intall-reboot-scripts') == 'y':
                    install_reboot_scripts()
                prepare_database()
                start_services('create-db')


@hooks.hook('config-changed')
def config_changed():
    upgrade_type = get_upgrade_type()
    if upgrade_type == 'clean-db' or upgrade_type == 'reuse-db':
        flush_upgrade_type()
    elif check_jboss_service() is True:
        stop_jboss_service()
        run_cp_installer()
        if config('intall-reboot-scripts') == 'y':
            install_reboot_scripts()
        start_services('config-change')
    for r_id in relation_ids('cplane-controller'):
        cplane_controller_relation_joined(rid=r_id)


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        juju_log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()
