#!/usr/bin/env python3
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

from charmhelpers.fetch import (
    apt_install,
    apt_update,
)

from cplane_context import (
    get_shared_secret,
    nova_metadata_requirement,
)

from cplane_utils import (
    determine_packages,
    DHCP_AGENT_INI,
    restart_services,
    register_configs,
    NEUTRON_CONF,
    assess_status,
    fake_register_configs,
    ML2_CONFIG,
    change_hostname,
    METADATA_AGENT_INI,
)

hooks = Hooks()

CONFIGS = register_configs()


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
        'neutron-plugin': 'linuxbridge',
        'subordinate_configuration': json.dumps(principle_config),
        'metadata-shared-secret': get_shared_secret(),
    }
    relation_set(relation_settings=relation_info)

@hooks.hook('neutron-plugin-relation-changed')
def neutron_plugin_changed():
#    enable_nova_metadata, _ = nova_metadata_requirement()
#    if enable_nova_metadata:
    CONFIGS.write(METADATA_AGENT_INI)


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
    change_hostname()
    CONFIGS.write(ML2_CONFIG)
    CONFIGS.write(DHCP_AGENT_INI)
    restart_services()

@hooks.hook('install.real')
def install():
    apt_update(fatal=True)
    # disable_neutron_agent()
    pkgs = determine_packages()
    apt_install(pkgs, fatal=True)

@hooks.hook('neutron-plugin-api-relation-changed')
def neutron_plugin_api_changed():
    CONFIGS.write(NEUTRON_CONF)
    restart_services()


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        juju_log('Unknown hook {} - skipping.'.format(e))
    assess_status(fake_register_configs())


if __name__ == '__main__':
    main()
