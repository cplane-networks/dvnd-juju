#!/usr/bin/env python
from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log as juju_log,
    log,
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

from charmhelpers.contrib.openstack.ip import (
    canonical_url,
    PUBLIC, INTERNAL, ADMIN
)

from cplane_utils import (
    determine_packages,
    install_cplane_packages,
    cplane_config,
    METADATA_AGENT_INI,
    set_cp_agent,
    manage_fip,
    restart_services,
    system_config,
    SYSTEM_CONF,
    register_configs,
    restart_metadata_agent,
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
        'metadata-shared-secret': config('metadata-shared-secret'),
    }
    relation_set(relation_settings=relation_info)
    restart_services()


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
    CONFIGS.write(METADATA_AGENT_INI)
    restart_metadata_agent()


@hooks.hook('identity-service-relation-joined')
def identity_joined(rid=None, relation_trigger=False):

    public_url = '{}'.format(canonical_url(CONFIGS, PUBLIC))
    internal_url = '{}'.format(canonical_url(CONFIGS, INTERNAL))
    admin_url = '{}'.format(canonical_url(CONFIGS, ADMIN))

    rel_settings = {
        'service': 'neutron',
        'region': config('region'),
        'public_url': public_url,
        'admin_url': admin_url,
        'internal_url': internal_url,
    }

    if relation_trigger:
        rel_settings['relation_trigger'] = str(uuid.uuid4())
    relation_set(relation_id=rid, relation_settings=rel_settings)


@hooks.hook('identity-service-relation-changed')
def identity_service_changed():
    if 'identity-service' not in CONFIGS.complete_contexts():
        log('identity-service relation incomplete. Peer not ready?')
        return
    CONFIGS.write(METADATA_AGENT_INI)
    restart_metadata_agent()


@hooks.hook('identity-service-relation-broken',
            'amqp-relation-broken')
def relation_broken():
    CONFIGS.write_all()
    restart_metadata_agent()


@hooks.hook('config-changed')
def config_changed():
    set_cp_agent()
    cplane_config(system_config, SYSTEM_CONF, '')
    cmd = ['sysctl', '-p']
    subprocess.check_call(cmd)
    CONFIGS.write(METADATA_AGENT_INI)
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
