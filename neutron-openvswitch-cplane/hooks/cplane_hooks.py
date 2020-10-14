#!/usr/bin/env python3
from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
    relation_set,
    relation_get,

)
import json
import subprocess
import sys

from charmhelpers.fetch import (
    apt_install,
    apt_update,
)

from cplane_context import (
    get_shared_secret,
)

from cplane_utils import (
    determine_packages,
    install_cplane_packages,
    cplane_config,
    set_cp_agent,
    manage_fip,
    restart_services,
    system_config,
    SYSTEM_CONF,
    register_configs,
    NEUTRON_CONF,
    neutron_config,
    restart_cp_agentd,
    assess_status,
    fake_register_configs,
    get_os_release,
    create_vfio_file,
    set_dpdk_env,
)


from cplane_network import (
    add_bridge,
    check_interface,
    change_iface_config,
)

hooks = Hooks()
CONFIGS = register_configs()


@hooks.hook('cplane-controller-relation-changed')
def cplane_controller_relation_changed():
    set_cp_agent()
    manage_fip()
    restart_cp_agentd()


@hooks.hook('neutron-plugin-api-relation-changed')
def neutron_plugin_api_changed():
    if not relation_get('neutron-api-ready'):
        log('Relationship with neutron-api not yet complete')
        return
    CONFIGS.write_all()
    restart_services()


@hooks.hook('neutron-plugin-relation-joined')
def neutron_plugin_relation_joined(rid=None):
    principle_config = {
        'nova-compute': {
            '/etc/nova/nova.conf': {
                'sections': {
                    'DEFAULT': [
                        ('allow_resize_to_same_host', 'True'),
                        ('resize_confirm_window', '1'),
                    ],
                }
            }
        }
    }
    relation_info = {
        'neutron-plugin': 'cplane',
        'subordinate_configuration': json.dumps(principle_config),
        'metadata-shared-secret': get_shared_secret(),
    }
    relation_set(relation_settings=relation_info)
    restart_services()


@hooks.hook('amqp-relation-joined')
def amqp_joined(relation_id=None):
    relation_set(relation_id=relation_id,
                 username=config('rabbit-user'),
                 vhost=config('rabbit-vhost'))


@hooks.hook('amqp-relation-changed')
def amqp_changed(relation_id=None):
    if relation_get('password'):
        neutron_config.update({'rabbit_password': relation_get('password')})
        neutron_config.update({'rabbit_host': relation_get('hostname')})
        cplane_config(neutron_config, NEUTRON_CONF, 'oslo_messaging_rabbit')
        restart_services()


@hooks.hook('cplane-ovs-relation-changed')
def cplane_ovs_relation_changed():
    topology = relation_get('topology')
    if topology:
        key = 'topology=' + topology
        cmd = ['cp-agentd', 'set-config', key]
        subprocess.check_call(cmd)
        restart_services()


@hooks.hook('config-changed')
def config_changed():
    set_dpdk_env()
    set_cp_agent()
    cplane_config(system_config, SYSTEM_CONF, '')
    if get_os_release() == '16.04':
        cmd = ['modprobe', 'br_netfilter']
        subprocess.check_call(cmd)
    cmd = ['sysctl', '-p']
    subprocess.check_call(cmd)
    manage_fip()
    CONFIGS.write_all()
    restart_services()

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


@hooks.hook('upgrade-charm')
@hooks.hook('install.real')
def install():
    apt_update(fatal=True)
#    disable_neutron_agent()
    pkgs = determine_packages()
    apt_install(pkgs, fatal=True)
    create_vfio_file()
    install_cplane_packages()
    add_bridge('br-ext',
               interface=config('data-interface'),
               gw=config('data-gateway'))
    if check_interface(config('tun-interface')):
        add_bridge('br-tun', interface=config('tun-interface'),
                   gw=config('tun-gateway'))
    else:
        log('Tunnel interface doesnt exist, and will be '
            'used by default by Cplane controller')


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))
    assess_status(fake_register_configs())


if __name__ == '__main__':
    main()
