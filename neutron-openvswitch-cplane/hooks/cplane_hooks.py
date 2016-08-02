#!/usr/bin/env python

import sys

from apt_pkg import version_compare

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log as juju_log,
    relation_get,
    relation_set
)
import json
import subprocess
import sys
import uuid

from charmhelpers.fetch import (
    apt_install,
    apt_update,
)

from cplane_utils import (
    is_neutron_api_ready,
    determine_packages,
    disable_neutron_agent,
    install_cplane_packages,
    cplane_config,
    metadata_agent_config,
    METADATA_AGENT_INI,
    set_cp_agent,
    manage_fip,
    restart_services,
    system_config,
    SYSTEM_CONF,
)

from cplane_network import (
    add_bridge,
    check_interface,
)

hooks = Hooks()

@hooks.hook('cplane-controller-relation-changed')
def cplane_controller_relation_changed():
    set_cp_agent()
    manage_fip()
    restart_services()


@hooks.hook('cplane-neutron-relation-changed')
def cplane_neutron_relation_changed():
    controller = relation_get('private-address')
    if controller:
        metadata_agent_config.update({'nova_metadata_ip': controller})
        metadata_agent_config.update({'auth_url': 'http://'+ controller + ':5000/v2.0'})
        cplane_config(metadata_agent_config, METADATA_AGENT_INI, 'DEFAULT')

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
    }
    relation_set(relation_settings=relation_info)
    restart_services()

@hooks.hook('amqp-relation-joined')
def amqp_joined(relation_id=None):
    relation_set(relation_id=relation_id,
                 username=config('rabbit-user'),
                 vhost=config('rabbit-vhost'))

@hooks.hook('config-changed')
def config_changed():
    cplane_config(metadata_agent_config, METADATA_AGENT_INI, 'DEFAULT')
    restart_services()
    set_cp_agent()
    cplane_config(system_config, SYSTEM_CONF, '')
    cmd = ['sysctl', '-p' ]
    subprocess.check_call(cmd)
    restart_services()

@hooks.hook('upgrade-charm')

@hooks.hook('install')
def install():
    apt_update(fatal=True)
#    disable_neutron_agent()
    pkgs = determine_packages()
    apt_install(pkgs, fatal=True)
    install_cplane_packages()
    add_bridge('br-ext', config('data-interface'))
    if check_interface(config('tun-interface')):
        add_bridge('br-tun', config('tun-interface'))
    else:
        juju_log('Tunnel interface doesnt exist, and will be used by default by Cplane controller')


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        juju_log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()
