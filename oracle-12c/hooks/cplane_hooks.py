#!/usr/bin/env python

from charmhelpers.core.hookenv import (
    Hooks,
    UnregisteredHookError,
    log as juju_log,
    config,
    relation_set,
    relation_ids,
    relation_get,
)
import sys
import os
import socket
import pickle
import json
import time

from charmhelpers.fetch import (
    yum_install,
    yum_update,
)

from cplane_utils import (
    determine_packages,
    group_add,
    user_add,
    disable_firewall,
    set_kernel_parameters,
    generate_host_string,
    config_host,
    process_data,
    check_all_nodes,
    send_data_to_slave,
    set_all_host_strings,
    generate_pub_ssh_key,
    flush_host,
    set_persistent_hostname,
    modify_oracle_grid_response_file,
    resize_swap_partition,
    set_ntpd_conf,
    save_name_server,
    set_name_server,
    create_oracle_dir,
    install_grid,
    install_root_scripts,
    send_notification,
    check_all_clustered_nodes,
    process_clustered_data,
    change_cluster_state,
    install_db,
    modify_oracle_db_response_file,
    install_db_root_scripts,
    pre_install,
    NODE_DATA_FILE,
    create_db,
    get_scan_str,
    set_oracle_env,
    check_node_state,
    download_cplane_packages,
    copy_oracle_package,
    get_db_status,

)

hooks = Hooks()


@hooks.hook('config-changed')
def config_changed():
    if config('slave-units-number'):
        set_name_server()


@hooks.hook('start')
def start():
    if not config('slave-units-number'):
        download_cplane_packages()
        copy_oracle_package()

        modify_oracle_db_response_file()
        if install_db():
            install_db_root_scripts()
            set_oracle_env()
            create_db()
            juju_log('Database is created and the listerner is started')


@hooks.hook('install.real')
def install():
    yum_update(fatal=True)
    pkgs = determine_packages()
    yum_install(pkgs, fatal=True)
    disable_firewall()
    group_add()
    user_add()
    set_kernel_parameters()

    cmd = "echo '#Added by cplane' >> /etc/hosts"
    os.system(cmd)
    set_persistent_hostname()
    if config('slave-units-number'):
        flush_host()
        config_host(generate_host_string('private'), 'private')
        config_host(generate_host_string('public'), 'public')
        config_host(generate_host_string('vip'), 'vip')
        generate_pub_ssh_key()
        resize_swap_partition()
        set_ntpd_conf()
    create_oracle_dir()


@hooks.hook('slave-relation-joined')
def slave_relation_joined():
    juju_log('Setting up the Hoststring in Slave in relation-joined')

    hostname = socket.gethostname()

    host_ssh_key = ''
    if os.path.exists(NODE_DATA_FILE):
        data = json.load(open(NODE_DATA_FILE))
        all_strings = data[hostname]
        host_ssh_key = all_strings['ssh_pub_key']

    relation_info = {
        'identity': hostname,
        'private-string': pickle.dumps(generate_host_string('private')),
        'public-string': pickle.dumps(generate_host_string('public')),
        'vip-string': pickle.dumps(generate_host_string('vip')),
        'host-ssh-key': pickle.dumps(host_ssh_key)
    }
    relation_set(relation_settings=relation_info)


@hooks.hook('slave-relation-changed')
def slave_relation_changed():
    juju_log('Setting up the Hoststring in Slave in relation-changes')
    set_all_host_strings()
    nameserver = relation_get('private-address')
    save_name_server(nameserver)
    set_name_server()


@hooks.hook('master-relation-joined')
def master_relation_joined():
    pass


@hooks.hook('master-relation-changed')
def master_relation_changed():
    if not relation_get('identity'):
        juju_log('Relationship with RAC-Slave not yet complete')
        return
    process_data()

    juju_log('Setting up the Hoststring in Master in relation-changed')
    if check_all_nodes():
        if check_node_state() is None:
            juju_log('Received data from Slaves')
            hostname = socket.gethostname()
            pre_install()
            change_cluster_state(hostname, "install")
            send_data_to_slave()
            modify_oracle_grid_response_file()
            modify_oracle_db_response_file()


@hooks.hook('upgradr-charm')
def upgrade_charm():
    pass


@hooks.hook('master-state-relation-joined')
def master_state_relation_joined():
    pass
#    hostname = socket.gethostname()
#    change_cluster_state(hostname, "initital")
#    send_notification("master-state", "initial")


@hooks.hook('master-state-relation-changed')
def master_state_relation_changed():
    if not relation_get('identity'):
        juju_log('Relationship with slave-state not yet complete')
        return
    process_clustered_data()
    state = relation_get('state')
    if check_all_clustered_nodes(state):
        if state == 'install':
            if install_grid():
                install_root_scripts()
                send_notification("master-state", "cluster")
        elif state == 'clustered':
            if install_db():
                install_db_root_scripts()
                send_notification("master-state", "database")
        elif state == 'final':
                send_notification("master-state", "final")
                set_oracle_env()
                create_db()
                for rid in relation_ids('oracle'):
                    oracle_relation_changed(relation_id=rid)
                juju_log("Oracle Rac 12C installation is succeeded on master")


@hooks.hook('slave-state-relation-joined')
def slave_state_relation_joined():
    pass


@hooks.hook('slave-state-relation-changed')
def slave_state_relation_changed():
    if not relation_get('identity'):
        juju_log('Relationship with master-state not yet complete')
        return
    if relation_get('state') == 'cluster':
        install_root_scripts()
        send_notification("slave-state", "clustered")
    if relation_get('state') == 'database':
        install_db_root_scripts()
        send_notification("slave-state", "final")
    if relation_get('state') == 'final':
        juju_log("Oracle Rac 12C installation is succeeded on slave")


@hooks.hook('oracle-relation-changed')
def oracle_relation_changed(relation_id=None):
    if config('slave-units-number'):
        if check_all_clustered_nodes('final'):
            relation_info = {
                'oracle-host': '{}-scan'.format(config('scan-name')),
                'db-service': '{}'.format(config('db-service')),
                'scan-string': pickle.dumps(get_scan_str()),
                'db-password': '{}'.format(config('db-password')),
                'db-path': '+DATA'
            }
            juju_log('Sending relation info to Cplane Controller')
            relation_set(relation_id=relation_id,
                         relation_settings=relation_info)
    else:
        hostname = socket.gethostname()
        relation_info = {
            'oracle-host': hostname,
            'db-service': '{}'.format(config('db-service')),
            'db-password': '{}'.format(config('db-password')),
            'db-path': '/u01/app/oracle/oradata/CPLANE/'
        }
        for num in range(0, 5):
            if get_db_status() is False:
                juju_log("Service is not registered with listener... \
                          Retry checking it after 60 sec")
                time.sleep(60)
            else:
                juju_log("Service is regitered with listener")
                juju_log('Sending relation info to Cplane Controller')
                relation_set(relation_id=relation_id,
                             relation_settings=relation_info)
                break


def main():
    try:
        hooks.execute(sys.argv)
    except UnregisteredHookError as e:
        juju_log('Unknown hook {} - skipping.'.format(e))


if __name__ == '__main__':
    main()
