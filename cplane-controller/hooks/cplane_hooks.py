#!/usr/bin/env python
from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log as juju_log,
    log,
    relation_set,
    relation_ids,
    is_leader,
    leader_set,
)
import sys
import commands
import os

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
    assess_status,
    fake_register_configs,
    is_leader_ready,
    is_oracle_relation_joined,
    set_data_source,
)

from cplane_network import (
    change_iface_config,
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
        if is_leader():
            leader_set({'status': "db_cleaned"})
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
    cmd = "echo '#Added by cplane' >> /etc/hosts"
    os.system(cmd)
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
                if is_leader():
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

    mtu_string = config('intf-mtu')
    if mtu_string:
        intf_mtu = mtu_string.split(',')
        for line in intf_mtu:
            interface = line.split('=')
            log("Change request for mtu for interface {} = {}"
                .format(interface[0], interface[1]))
            change_iface_config(interface[0], 'mtu', interface[1])

    tso_string = config('tso-flag')
    if tso_string:
        intf_tso = tso_string.split(',')
        for line in intf_tso:
            interface = line.split('=')
            log("Change request for tso for interface {} = {}"
                .format(interface[0], interface[1]))
            change_iface_config(interface[0], 'tso', interface[1])

    gso_string = config('gso-flag')
    if gso_string:
        intf_gso = gso_string.split(',')
        for line in intf_gso:
            interface = line.split('=')
            log("Change request for gso for interface {} = {}"
                .format(interface[0], interface[1]))
            change_iface_config(interface[0], 'gso', interface[1])

    rx_string = config('rx-flag')
    if rx_string:
        intf_rx = rx_string.split(',')
        for line in intf_rx:
            interface = line.split('=')
            log("Change request for rx for interface {} = {}"
                .format(interface[0], interface[1]))
            change_iface_config(interface[0], 'rx', interface[1])

    tx_string = config('tx-flag')
    if tx_string:
        intf_tx = tx_string.split(',')
        for line in intf_tx:
            interface = line.split('=')
            log("Change request for tx for interface {} = {}"
                .format(interface[0], interface[1]))
            change_iface_config(interface[0], 'tx', interface[1])

    sg_string = config('sg-flag')
    if sg_string:
        intf_sg = sg_string.split(',')
        for line in intf_sg:
            interface = line.split('=')
            log("Change request for sg for interface {} = {}"
                .format(interface[0], interface[1]))
            change_iface_config(interface[0], 'sg', interface[1])

    ufo_string = config('ufo-flag')
    if ufo_string:
        intf_ufo = ufo_string.split(',')
        for line in intf_ufo:
            interface = line.split('=')
            log("Change request for ufo for interface {} = {}"
                .format(interface[0], interface[1]))
            change_iface_config(interface[0], 'ufo', interface[1])

    gro_string = config('gro-flag')
    if gro_string:
        intf_gro = gro_string.split(',')
        for line in intf_gro:
            interface = line.split('=')
            log("Change request for gro for interface {} = {}"
                .format(interface[0], interface[1]))
            change_iface_config(interface[0], 'gro', interface[1])

    lro_string = config('lro-flag')
    if lro_string:
        intf_lro = lro_string.split(',')
        for line in intf_lro:
            interface = line.split('=')
            log("Change request for lro for interface {} = {}"
                .format(interface[0], interface[1]))
            change_iface_config(interface[0], 'lro', interface[1])


@hooks.hook('leader-settings-changed')
def leader_settings_changed():
    if not is_leader() and is_leader_ready() and is_oracle_relation_joined():
        set_oracle_host()
        set_data_source()
        start_services('create-db')


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        juju_log('Unknown hook {} - skipping.'.format(e))
    assess_status(fake_register_configs())

if __name__ == '__main__':
    main()
