#!/usr/bin/env python
from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
    log as juju_log,
    relation_get,
    relation_set,
)
import json
import sys
import uuid

from charmhelpers.fetch import (
    apt_install,
    apt_update,
)

from cplane_utils import (
    determine_packages,
    metadata_agent_config,
    METADATA_AGENT_INI,
    restart_services,
    cplane_config,
    register_configs,
    NEUTRON_CONF,
    assess_status,
    fake_register_configs,
    ML2_CONFIG,
)

from cplane_network import (
    change_iface_config,
)

hooks = Hooks()

CONFIGS = register_configs()


@hooks.hook('cplane-neutron-relation-changed')
def cplane_neutron_relation_changed():
    controller = relation_get('private-address')
    if controller:
        metadata_agent_config.update({'nova_metadata_ip': controller})
        metadata_agent_config.update({'auth_url': 'http://' + controller +
                                      ':5000/v2.0'})
        cplane_config(metadata_agent_config, METADATA_AGENT_INI, 'DEFAULT')


@hooks.hook('neutron-plugin-relation-joined')
def neutron_plugin_relation_joined(rid=None):
    principle_config = {
        'nova-compute': {
            '/etc/nova/nova.conf': {
                'sections': {
                    'DEFAULT': [
                        ('linuxnet_interface_driver',
                         'nova.network.linux_net.NeutronLinux \
                          BridgeInterfaceDriver')],
                }
            }
        }
    }
    relation_info = {
        'neutron-plugin': 'cplane',
        'subordinate_configuration': json.dumps(principle_config),
    }
    relation_set(relation_settings=relation_info)


@hooks.hook('amqp-relation-joined')
def amqp_joined(relation_id=None):
    relation_set(relation_id=relation_id,
                 username=config('rabbit-user'),
                 vhost=config('rabbit-vhost'))


@hooks.hook('amqp-relation-changed')
def amqp_changed():
    if 'amqp' not in CONFIGS.complete_contexts():
        log('amqp relation incomplete. Peer not ready?')
        return
    CONFIGS.write(NEUTRON_CONF)
    restart_services()


@hooks.hook('config-changed')
def config_changed():
    # cplane_config(metadata_agent_config, METADATA_AGENT_INI, 'DEFAULT')
    CONFIGS.write(ML2_CONFIG)
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


@hooks.hook('install')
def install():
    apt_update(fatal=True)
    # disable_neutron_agent()
    pkgs = determine_packages()
    apt_install(pkgs, fatal=True)


@hooks.hook('identity-service-relation-joined')
def identity_joined(rid=None, relation_trigger=False):
    """
    Needs to check why this section od code is not working

    public_url = '{}:{}'.format(canonical_url(CONFIGS, PUBLIC),
                             api_port('neutron-server'))
    admin_url = '{}:{}'.format(canonical_url(CONFIGS, ADMIN),
                               api_port('neutron-server'))
    internal_url = '{}:{}'.format(canonical_url(CONFIGS, INTERNAL),
                                  api_port('neutron-server'))
    """

    internal_url = 'http://cplanenetworks.com'
    admin_url = 'http://cplanenetworks.com'
    public_url = 'http://cplanenetworks.com'

    rel_settings = {
        'neutron_service': 'neutron',
        'neutron_region': config('region'),
        'neutron_public_url': public_url,
        'neutron_admin_url': admin_url,
        'neutron_internal_url': internal_url,
        'quantum_service': None,
        'quantum_region': None,
        'quantum_public_url': None,
        'quantum_admin_url': None,
        'quantum_internal_url': None,
    }
    if relation_trigger:
        rel_settings['relation_trigger'] = str(uuid.uuid4())
    relation_set(relation_id=rid, relation_settings=rel_settings)


@hooks.hook('identity-service-relation-changed')
def identity_changed():
    if 'identity-service' not in CONFIGS.complete_contexts():
        log('identity-service relation incomplete. Peer not ready?')
        return
    CONFIGS.write(NEUTRON_CONF)
    CONFIGS.write(METADATA_AGENT_INI)
    restart_services()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        juju_log('Unknown hook {} - skipping.'.format(e))
    assess_status(fake_register_configs())


if __name__ == '__main__':
    main()
