#!/usr/bin/env python

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    log as juju_log,
    log,
    config,
)

import sys
import os

from charmhelpers.fetch import (
    apt_install,
    apt_update,
)

from charmhelpers.contrib.python.packages import (
    pip_install,
)

from cplane_utils import (
    register_configs,
    determine_packages,
    determine_pip_packages,
    install_cplane_packages,
    install_keystone,
    download_cplane_packages,
    prepare_env,
    restart_service,
    set_oracle_host,
    install_oracle_client,
    configure_oracle_client,
    configure_keystone,
    create_ketstone_user,
    send_active_notification,
    create_domain,
    assess_status,
    fake_register_configs,
)

from cplane_network import (
    change_iface_config,
)

hooks = Hooks()
configs = register_configs()


@hooks.hook('config-changed')
def config_changed():
    configs.write_all()

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


@hooks.hook('install.real')
def install():
    apt_update(fatal=True)
    pkgs = determine_packages()
    apt_install(pkgs, fatal=True)
    pkgs = determine_pip_packages()
    pip_install(pkgs, fatal=True, upgrade=True)
    download_cplane_packages()
    install_cplane_packages()
    prepare_env()
    install_keystone()
    cmd = 'pip install -r requirement.txt'
    os.system(cmd)
    if config('db-on-host') is False:
        install_oracle_client()
        configure_oracle_client()
    os.system("pip install python-openstackclient")
    restart_service()
    

@hooks.hook('oracle-relation-changed')
def oracle_relation_changed():
    oracle_host = set_oracle_host()
    if oracle_host:
        create_ketstone_user()
        configs.write_all()
        restart_service()
        configure_keystone()
        create_domain()
        send_active_notification()


@hooks.hook('start')
def start():
    if config('db-on-host'):
        oracle_host = set_oracle_host()
        if oracle_host:
            create_ketstone_user()
            configs.write_all()
            restart_service()
            configure_keystone()
            create_domain()
            send_active_notification()   


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        juju_log('Unknown hook {} - skipping.'.format(e))
    assess_status(fake_register_configs())

if __name__ == '__main__':
    main()
