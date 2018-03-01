#!/usr/bin/python
import subprocess
import sys
import os
from subprocess import PIPE


sys.path.append('hooks/')

import cplane_utils

from charmhelpers.core.hookenv import (
    config,
    log,
    action_set,
    action_fail,
)

from cplane_utils import (
    set_oracle_env,
    configure_oracle_client,
    set_oracle_host,

)


def execute_sql_command(connect_string, sql_command):
    session = subprocess.Popen(['sqlplus', '-S', connect_string], stdin=PIPE,
                               stdout=PIPE, stderr=PIPE)
    session.stdin.write(sql_command)
    return session.communicate()


def drop_cplane_data(args):
    connect_string = ''
    if config('jboss-db-on-host'):
        set_oracle_env()
        connect_string = 'sys/' + config('oracle-password') + \
                         '@localhost/XE as sysdba'
    else:
        configure_oracle_client()
        oracle_host = set_oracle_host()
        if oracle_host:
            host = cplane_utils.ORACLE_HOST + '/'
            connect_string = 'sys/' + cplane_utils.DB_PASSWORD \
                             + '@' + host + cplane_utils.DB_SERVICE + ' as' \
                             + ' sysdba'
        else:
            action_set({'result-map.message': "No Oracle Host found"})

    log("Dropping user and tables spaces from DB")
    log(connect_string)
    res = execute_sql_command(connect_string, "drop user admin cascade;")
    action_set({'result-map.message': res})
    res = execute_sql_command(connect_string, "drop tablespace cp_tabs \
including contents and datafiles cascade constraints;")
    action_set({'result-map.message': res})
    res = execute_sql_command(connect_string, "drop tablespace cp_tabm \
including contents and datafiles cascade constraints;")
    action_set({'result-map.message': res})
    res = execute_sql_command(connect_string, "drop tablespace cp_tabl \
including contents and datafiles cascade constraints;")
    action_set({'result-map.message': res})
    res = execute_sql_command(connect_string, "drop tablespace cp_inds \
including contents and datafiles cascade constraints;")
    action_set({'result-map.message': res})
    res = execute_sql_command(connect_string, "drop tablespace cp_indm \
including contents and datafiles cascade constraints;")
    action_set({'result-map.message': res})
    res = execute_sql_command(connect_string, "drop tablespace cp_indl \
including contents and datafiles cascade constraints;")
    action_set({'result-map.message': res})

ACTIONS = {"drop-cplane-data": drop_cplane_data}


def main(args):
    action_name = os.path.basename(args[0])
    try:
        action = ACTIONS[action_name]
    except KeyError:
        return "Action %s undefined" % action_name
    else:
        try:
            action(args)
        except Exception as e:
            action_fail(str(e))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
