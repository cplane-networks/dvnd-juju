#!/usr/bin/env python
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
)


from cplane_network import (
    add_bridge,
    check_interface,
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


@hooks.hook('config-changed')
def config_changed():
    set_cp_agent()
    cplane_config(system_config, SYSTEM_CONF, '')
    cmd = ['sysctl', '-p']
    subprocess.check_call(cmd)
    CONFIGS.write_all()
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
        log('Tunnel interface doesnt exist, and will be '
            'used by default by Cplane controller')


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()
