#!/usr/bin/env python

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    log as juju_log,
    log,
    config,
    relation_set,
    relation_get,
    relation_ids,
    related_units,

)
import json
import sys
import uuid
import os

from charmhelpers.fetch import (
    apt_install,
    apt_update,
)

from cplane_utils import (
    register_configs,
    determine_packages,
    install_cplane_packages,
    cplane_config,
    neutron_config,
    create_link,
    restart_service,
    migrate_db,
    configure_policy,
    assess_status,
    fake_register_configs,
)

from cplane_network import (
    change_iface_config,
)

hooks = Hooks()


@hooks.hook('config-changed')
def config_changed():
    configs = register_configs()
    configs.write_all()
    if config('cplane-version') == "1.3.5":
        import pkg_resources
        NEUTRON_ENTRY_POINT = "/usr/lib/python2.7/dist-packages/neutron-" \
                              + pkg_resources.get_distribution('neutron').\
                              version + ".egg-info/entry_points.txt"
        cplane_config(neutron_config, NEUTRON_ENTRY_POINT)

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

    for rid in relation_ids('cplane-controller'):
        for unit in related_units(rid):
            data = relation_get(rid=rid, unit=unit)
            cplane_controller = data['private-address']
            mport = data['mport']
            if mport:
                cmd = "sed -ie 's/cplane_controller_hosts.*/cplane_controller_\
hosts = {}/g' /etc/neutron/plugins/ml2/ml2_conf.ini".format(cplane_controller)
                os.system(cmd)
                restart_service()


@hooks.hook('cplane-controller-relation-changed')
def cplane_controller_relation_changed():
    mport = relation_get('mport')
    cplane_controller = relation_get('private-address')
    if mport:
        cmd = "sed -ie 's/cplane_controller_hosts.*/cplane_controller_\
hosts = {}/g' /etc/neutron/plugins/ml2/ml2_conf.ini".format(cplane_controller)
        os.system(cmd)
        restart_service()


@hooks.hook('shared-db-relation-changed')
def share_db_relation_changed():
    migrate_db()


@hooks.hook('amqp-relation-changed')
def amqp_changed(relation_id=None):
    relation_set(relation_id=relation_id,
                 username=config('rabbit-user'),
                 vhost=config('rabbit-vhost'))


@hooks.hook('neutron-plugin-api-subordinate-relation-joined')
def neutron_api_joined(rid=None):
    principle_config = {
        'neutron-api': {
            '/etc/neutron/neutron.conf': {
                'sections': {
                    'DEFAULT': [
                    ],
                }
            }
        }
    }
    relation_info = {
        'neutron-plugin': 'cplane',
        'core-plugin': 'ml2',
        'service-plugins': 'cplane_l3',
        'subordinate_configuration': json.dumps(principle_config),
        'restart-trigger': str(uuid.uuid4()),
        'migration-configs': ['/etc/neutron/plugins/ml2/ml2_conf.ini'],
    }
    relation_set(relation_settings=relation_info)


@hooks.hook('cplane-ovs-relation-joined')
def cplane_ovs(rid=None):
    relation_info = {
        'topology': config('topology-name')
    }
    relation_set(relation_settings=relation_info)


@hooks.hook('install')
def install():
    apt_update(fatal=True)
    pkgs = determine_packages()
    apt_install(pkgs, fatal=True)
    install_cplane_packages()
    create_link()
    if config('cplane-version') == "1.3.7" or "1.3.8":
        configure_policy()
    restart_service()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        juju_log('Unknown hook {} - skipping.'.format(e))
    assess_status(fake_register_configs())

if __name__ == '__main__':
    main()
