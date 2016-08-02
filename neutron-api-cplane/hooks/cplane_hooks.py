#!/usr/bin/env python

import sys

from apt_pkg import version_compare

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    config,
    log,
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
    register_configs,
    determine_packages,
    install_cplane_packages,
    cplane_config,
    neutron_config,
    create_link,
    restart_service,
    python_intall,
    migrate_db,
)

hooks = Hooks()


@hooks.hook('config-changed')
def config_changed():
    configs = register_configs()
    configs.write_all()
    import pkg_resources
    NEUTRON_ENTRY_POINT = "/usr/lib/python2.7/dist-packages/neutron-" + \
                          pkg_resources.get_distribution('neutron').version + \
                          ".egg-info/entry_points.txt"
    cplane_config(neutron_config, NEUTRON_ENTRY_POINT)

@hooks.hook('cplane-controller-relation-changed')
def cplane_controller_relation_changed():
    configs = register_configs()
    configs.write_all()

@hooks.hook('shared-db-relation-changed')
def share_db_relation_changed():
    migrate_db()

@hooks.hook('amqp-relation-joined')
def amqp_joined(relation_id=None):
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

@hooks.hook('install')
def install():
    apt_update(fatal=True)
    pkgs = determine_packages()
    apt_install(pkgs, fatal=True)
    install_cplane_packages()
    python_intall("bitarray")
    create_link()
    restart_service()



def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        juju_log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()
