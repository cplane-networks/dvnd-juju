#!/usr/bin/env python
from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log as juju_log,
    relation_get,
    relation_set,
)
import json
import subprocess
import sys

from charmhelpers.fetch import (
    apt_install,
    apt_update,
)

from cplane_utils import (
    determine_packages,
    install_cplane_packages,
    cplane_config,
    metadata_agent_config,
    METADATA_AGENT_INI,
    set_cp_agent,
    manage_fip,
    restart_services,
    system_config,
    SYSTEM_CONF,
    get_shared_secret,
    NEUTRON_CONF,
    neutron_config,
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
    pass


@hooks.hook('neutron-plugin-api-relation-changed')
def neutron_plugin_api_changed():
    if not relation_get('neutron-api-ready'):
        juju_log('Relationship with neutron-api not yet complete')
        return
    metadata_agent_config.update({'auth_url': relation_get('auth_protocol') +
                                  '://' + relation_get('auth_host') + ':' +
                                  relation_get('service_port') + '/v2.0'})
    metadata_agent_config.update({'metadata_proxy_shared_secret':
                                  get_shared_secret()})
    metadata_agent_config.update({'admin_user':
                                  relation_get('service_username')})
    metadata_agent_config.update({'admin_password':
                                  relation_get('service_password')})
    metadata_agent_config.update({'admin_tenant_name':
                                  relation_get('service_tenant')})
    cplane_config(metadata_agent_config, METADATA_AGENT_INI, 'DEFAULT')
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
    cplane_config(metadata_agent_config, METADATA_AGENT_INI, 'DEFAULT')
    restart_services()
    set_cp_agent()
    cplane_config(system_config, SYSTEM_CONF, '')
    cmd = ['sysctl', '-p']
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
        juju_log('Tunnel interface doesnt exist, and will be \
                 used by default by Cplane controller')


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        juju_log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()
