import subprocess


from subprocess import PIPE
from collections import OrderedDict
import netifaces as ni
from charmhelpers.core.hookenv import (
    config,
    log,
    relation_get,
    relation_ids,
    related_units,
    unit_get,
    network_get_primary_address,
    is_leader,
    leader_get,
    leader_set,

)

from charmhelpers.fetch import (
    apt_install,
)

import os
import pwd
import commands
import time
import re
import json
import socket
import pickle
from charmhelpers.contrib.openstack.utils import (
    make_assess_status_func,
)

import charmhelpers.core.hookenv as hookenv


from cplane_package_manager import(
    CPlanePackageManager
)

from xml.dom import minidom

file_header = (
    '\n################################################\n',
    '# Added by Cplane controller\'s Oracle client  #\n',
    '################################################\n')

cplane_packages = OrderedDict([
    (config('oracle-version'), '0'),
    ('jboss', '0'),
    ('jdk', '0'),
    ('oracle-client-basic', config('oracle-client-basic')),
    ('oracle-sqlplus', config('oracle-sqlplus')),
    (config('controller-app-mode'), '-1')
])


if config('jboss-db-on-host') is False:
    del cplane_packages[config('oracle-version')]
elif config('jboss-db-on-host'):
    del cplane_packages['oracle-client-basic']
    del cplane_packages['oracle-sqlplus']


PACKAGES = ['alien', 'libaio1', 'zlib1g-dev', 'libxml2-dev',
            'libxml-libxml-perl', 'unzip', 'python-pexpect',
            'libyaml-perl']


CPLANE_URL = config('cp-package-url')

DVND_CONFIG = OrderedDict([
    ('multicast-port', 'multicastPort'),
    ('multicast-intf', 'multicastInterface'),
    ('unicast-port', 'unicastPort'),
    ('jboss-home', 'JBOSS_HOME'),
    ('db-user', 'DB_USERNAME'),
    ('db-password', 'DB_PASSWORD'),
    ('intall-reboot-scripts', 'JBOSS_INSTALL_REBOOT'),
    ('oracle-host', 'DB_HOSTNAME'),
    ('jboss-db-on-host', 'JBOSS_DB_ON_HOST'),
    ('enable-fip', 'GatewayBridgeFipExt'),
    ('production', 'PRODUCTION')
])

MSM_CONFIG = OrderedDict([
    ('jboss-home', 'JBOSS_HOME'),
    ('db-user', 'DB_USERNAME'),
    ('db-password', 'DB_PASSWORD'),
    ('intall-reboot-scripts', 'JBOSS_INSTALL_REBOOT'),
    ('oracle-host', 'DB_HOSTNAME'),
    ('jboss-db-on-host', 'JBOSS_DB_ON_HOST'),
])

ORACLE_HOST = ''
DB_SERVICE = ''
DB_PASSWORD = ''
DB_PATH = ''
JBOSS_DIR = '/opt/jboss'
CHARM_LIB_DIR = os.environ.get('CHARM_DIR', '') + "/lib/"
CPLANE_DIR = '/opt/cplane/bin'
DB_DIR = os.environ.get('CHARM_DIR', '') + "/lib/" + 'PKG/pkg/db_init/'
FILES_PATH = CHARM_LIB_DIR + '/filelink'
CONTROLLER_CONFIG = ''
if config('controller-app-mode') == 'dvnd':
    CONTROLLER_CONFIG = 'cplane-dvnd-config.yaml'
elif config('controller-app-mode') == 'msm':
    CONTROLLER_CONFIG = 'cplane-msm-config.yaml'
    cplane_packages[config('controller-app-mode')] = config('msm-version')

if not config('jboss-db-on-host'):
    REQUIRED_INTERFACES = {
        'oracle': ['oracle'],
    }
else:
    REQUIRED_INTERFACES = {}

SERVICES = []


def determine_packages():
    if get_os_release() == '16.04':
        PACKAGES.extend(['bc', 'unixodbc'])
    return PACKAGES


def download_cplane_packages():
    filename = {}
    cp_package = CPlanePackageManager(CPLANE_URL)
    for key, value in cplane_packages.items():
        filename[key] = cp_package.download_package(key, value)
        log('downloaded {} package'.format(filename[key]))
    json.dump(filename, open(FILES_PATH, 'w'))


def download_cplane_installer():
    filename = json.load(open(FILES_PATH))
    cp_package = CPlanePackageManager(CPLANE_URL)
    for key, value in cplane_packages.items():
        if key == config('controller-app-mode'):
            filename[key] = cp_package.download_package(key, value)
            log('downloaded {} package'.format(filename[key]))
    json.dump(filename, open(FILES_PATH, 'w'))


def oracle_configure_init():
    import pexpect
    if get_os_release() == '16.04':
        cmd = "sed -i 's/memory_target=*/#memory_target=/g' \
/u01/app/oracle/product/11.2.0/xe/config/scripts/init.ora"
        os.system(cmd)
        cmd = "sed -i 's/memory_target=*/#memory_target=/g' \
/u01/app/oracle/product/11.2.0/xe/config/scripts/initXETemp.ora"
        os.system(cmd)
    child = pexpect.spawn("/etc/init.d/oracle-xe configure", timeout=900)
    child.sendline(config('oracle-http-port'))
    child.sendline(config('oracle-listener-port'))
    child.sendline(config('oracle-password'))
    child.sendline(config('oracle-password'))
    child.sendline(config('oracle-db-enable'))
    child.timeout = 900
    child.expect(pexpect.EOF)
    log('{}'.format(child.before))


def prepare_env():
    cmd = ['ln', '-sf', '/usr/bin/awk', '/bin/awk']
    subprocess.check_call(cmd)
    cmd = ['mkdir', '/var/lock/subsys']
    if os.path.exists('/var/lock/subsys') == 0:
        subprocess.check_call(cmd)
    cmd = ['chmod', '-R', '777', '/var/lock/subsys']
    subprocess.check_call(cmd)
    cmd = ['mkdir', JBOSS_DIR]
    if os.path.exists(JBOSS_DIR) == 0:
        subprocess.check_call(cmd)
    cmd = ['mkdir', '/etc/rc.d']
    if os.path.exists('/etc/rc.d') == 0:
        subprocess.check_call(cmd)
    cmd = ['ln', '-sf', '/etc/init.d', '/etc/rc.d/init.d']
    subprocess.check_call(cmd)

    f = open("/etc/sysctl.d/10-network-security.conf", "a")
    f.write("net.core.wmem_max = 1048576\n")
    f.write("net.core.rmem_max = 26214400\n")
    f.close()
    cmd = ['sysctl', '-p', '/etc/sysctl.d/10-network-security.conf']
    subprocess.check_call(cmd)


def install_jboss():
    filename = json.load(open(FILES_PATH))
    saved_path = os.getcwd()
    os.chdir(JBOSS_DIR)
    cmd = ['cp', filename['jboss'], '.']
    subprocess.check_call(cmd)
    cmd = ['unzip', '-o', filename['jboss']]
    subprocess.check_call(cmd)
    os.chdir(saved_path)
    jboss_home = config('jboss-home')
    home_dir = pwd.getpwuid(os.getuid()).pw_dir
    with open('{}/.bashrc'.format(home_dir), 'a') as f:
        f.write('export JBOSS_HOME={}\n'.format(jboss_home))
    f.close()
    os.system('export JBOSS_HOME={}'.format(jboss_home))


def deb_convert_install(module):
    filename = json.load(open(FILES_PATH))
    saved_path = os.getcwd()
    os.chdir(CHARM_LIB_DIR)
    cmd = ['alien', '--scripts', '-d', '-i', filename[module]]
    subprocess.check_call(cmd)
    os.chdir(saved_path)
    options = "--fix-broken"
    apt_install(options, fatal=True)


def install_jdk():
    log('Installing JDK')
    deb_convert_install('jdk')
    java_dir = commands.getoutput("echo $(dirname $(dirname \
$(readlink -f $(which javac))))")
    home_dir = pwd.getpwuid(os.getuid()).pw_dir
    with open('{}/.bashrc'.format(home_dir), 'a') as f:
        f.write('export JAVA_HOME={}\n'.format(java_dir))
    f.close()
    os.system('export JAVA_HOME={}'.format(java_dir))


def install_oracle_client():
    log('Installing Oracle Client Basic')
    deb_convert_install('oracle-client-basic')
    log('Installing Oracle Sqlplus')
    deb_convert_install('oracle-sqlplus')


def configure_oracle_client():
    filename = json.load(open(FILES_PATH))
    cmd = 'ln -s /usr/bin/sqlplus64 /usr/bin/sqlplus'
    os.system(cmd)
    oracle_version = re.findall(u'instantclient([0-9.]+)', filename['oracle\
-client-basic'])[0]
    with open('/etc/ld.so.conf.d/oracle.conf',
              'w') as oracle_configuration_file:
        oracle_configuration_file.writelines(file_header)
        oracle_configuration_file.write('/usr/lib/oracle/{}/client64/\
lib\n'.format(oracle_version))
    cmd = 'ldconfig'
    os.system(cmd)

    with open('/etc/profile.d/oracle.sh', 'w') as oracle_env:
        oracle_env.write('export ORACLE_HOME=/usr/lib/oracle/''{}/\
client64\n'.format(oracle_version))

    home_dir = pwd.getpwuid(os.getuid()).pw_dir
    with open('{}/.bashrc'.format(home_dir), 'a') as bashrc:
        bashrc.write('export LD_LIBRARY_PATH=/usr/lib/oracle/''{}/\
client64/lib\n'.format(oracle_version))
        bashrc.write('export ORACLE_HOME=/usr/lib/oracle/''{}/\
client64\n'.format(oracle_version))
    cmd = 'export ORACLE_HOME=/usr/lib/oracle/{}/\
           client64'.format(oracle_version)
    os.system(cmd)

    cmd = 'export LD_LIBRARY_PATH=/usr/lib/oracle/{}/\
client64/lib'.format(oracle_version)
    os.system(cmd)


def install_oracle():
    log('Installing Oracle')
    deb_convert_install(config('oracle-version'))


def set_oracle_env():
    newenv = None
    pipe = subprocess.Popen(". /etc/profile.d/oracle_env.sh; python -c 'import os; \
                            print \"newenv = %r\" % os.environ'",
                            stdout=subprocess.PIPE, shell=True)
    exec(pipe.communicate()[0])
    os.environ.update(newenv)


def configure_oracle():
    cmd = ['cp', '/u01/app/oracle/product/11.2.0/xe/bin/oracle_env.sh',
           '/etc/profile.d/']
    subprocess.check_call(cmd)

    set_oracle_env()

    saved_path = os.getcwd()
    os.chdir('/u01/app/oracle/product/11.2.0/xe/network/admin')

    new_entry = "    (SID_DESC = \n      (SID_NAME = XE)\n      \
(ORACLE_HOME = /u01/app/oracle/product/11.2.0/xe)\n    )\n"
    fp = open("insert.txt", "w")
    fp.write("%s" % new_entry)
    fp.close()

    cmd = "sed -e '/(SID_D/ {:L;N;/\\n *)/bK;bL; :K;/'$(sed -n '; $ {g; s/^[^\
=]*=//; s/)//;p}' listener.ora)'/rinsert.txt' -e ';}' listener.ora > temp"
    os.system(cmd)

    cmd = ['rm', '-rf', 'insert.txt']
    subprocess.check_call(cmd)

    cmd = ['cp', 'temp', 'listener.ora']
    subprocess.check_call(cmd)

    cmd = ['rm', '-rf', 'temp']
    subprocess.check_call(cmd)

    os.chdir('/etc/init.d/')
    new_entry = "\nif [ -L /dev/shm ]; then\n    rm -rf /dev/shm\n    mkdir \
/dev/shm\n    mount -t tmpfs shmfs -o size=2048m /dev/shm\nfi\n"
    fp = open("insert.txt", "w")
    fp.write("%s" % new_entry)
    fp.close()

    cmd = "sed '/# Source fuction library/r insert.txt' oracle-xe > temp"
    os.system(cmd)

    cmd = ['rm', '-rf', 'insert.txt']
    subprocess.check_call(cmd)
    cmd = ['cp', 'temp', 'oracle-xe']
    subprocess.check_call(cmd)
    cmd = ['rm', '-rf', 'temp']
    subprocess.check_call(cmd)
    cmd = ['chmod', '+x', 'oracle-xe']
    subprocess.check_call(cmd)
    os.chdir(saved_path)
    oracle_configure_init()


def execute_sql_command(connect_string, sql_command):
    session = subprocess.Popen(['sqlplus', '-S', connect_string], stdin=PIPE,
                               stdout=PIPE, stderr=PIPE)
    session.stdin.write(sql_command)
    log('{}'.format(session.communicate()))


def configure_database():
    set_oracle_host()
    host = ORACLE_HOST + '/'
    log('Configuring the Database')
    connect_string = 'sys/' + DB_PASSWORD \
        + '@' + host + DB_SERVICE + ' as' + ' sysdba'
    if DB_SERVICE == 'XE':
        execute_sql_command(connect_string, "alter system set \
processes={} scope=spfile;".format(config('xe-db-process')))
        execute_sql_command(connect_string, "alter system set \
session_cached_cursors={} scope=spfile;".format(config('xe-db-ses-cach-cur')))
        execute_sql_command(connect_string, "alter system set \
session_max_open_files={} scope=spfile;".format(
                            config('xe-db-ses-max-op-file')))
        execute_sql_command(connect_string, "alter system set \
sessions={} scope=spfile;".format(config('xe-db-session')))
        execute_sql_command(connect_string, "alter system set \
license_max_sessions={} scope=spfile;".format(config('xe-db-lic-max-ses')))
        execute_sql_command(connect_string, "alter system set \
license_sessions_warning={} scope=spfile;".format(config('xe-db-lic-ses-war')))
        execute_sql_command(connect_string, "SHUTDOWN IMMEDIATE")
        execute_sql_command(connect_string, "STARTUP")


def prepare_database():
    saved_path = os.getcwd()
    set_oracle_host()
    os.chdir(DB_DIR)
    host = ORACLE_HOST + '/'
    log('preparing the Database')
    connect_string = 'system/' + DB_PASSWORD \
        + '@' + host + DB_SERVICE
    if DB_SERVICE == 'XE':
        execute_sql_command(connect_string, "@cp_create_ts {}".format(DB_PATH))
    else:
        set_data_source()
        log('Connect String for database is {}'.format(connect_string))
        log('Database location is  {}'.format(DB_PATH))
        execute_sql_command(connect_string, "@cp_create_ts {}".format(DB_PATH))

    connect_string = 'sys/' + DB_PASSWORD \
        + '@' + host + DB_SERVICE + ' as' + ' sysdba'
    execute_sql_command(connect_string, "@cp_create_user {} \
{}".format(config('db-user'), config('db-password')))
    connect_string = 'system/' + DB_PASSWORD \
        + '@' + host + DB_SERVICE
    execute_sql_command(connect_string, "grant \
resource to {};".format(config('db-user')))
    execute_sql_command(connect_string, "grant \
create view to {};".format(config('db-user')))

    cmd = 'sh install.sh {}/{}@{}{} 2>&1 | tee \
install.log'.format(config('db-user'), config('db-password'), host, DB_SERVICE)
    os.system(cmd)
    connect_string = '{}/{}@{}{}'.format(config('db-user'), config('db-\
password'), host, DB_SERVICE)
    execute_sql_command(connect_string, "@install_plsql")
    os.chdir(saved_path)


def load_config():
    if config('controller-app-mode') == 'dvnd':
        for key, value in DVND_CONFIG.items():
            if key == 'enable-fip':
                if(config(key)):
                    set_config(value, 'true', CONTROLLER_CONFIG)
                else:
                    set_config(value, 'false', CONTROLLER_CONFIG)
            else:
                set_config(value, config(key), CONTROLLER_CONFIG)
        set_config('multicastServerInterface', config('multicast-intf'),
                   CONTROLLER_CONFIG)
        if config('use-default-jboss-cluster') is False:
            hostname = socket.gethostname()
            cluster_name = 'cplane' + '-' + hostname
            set_config('JBOSS_CLUSTER_NAME', cluster_name,
                       CONTROLLER_CONFIG)
    elif config('controller-app-mode') == 'msm':
        for key, value in MSM_CONFIG.items():
            set_config(value, config(key), CONTROLLER_CONFIG)
        if config('use-default-jboss-cluster') is False:
            hostname = socket.gethostname()
            cluster_name = 'cplane' + '-' + hostname
            set_config('JBOSS_CLUSTER_NAME', cluster_name,
                       CONTROLLER_CONFIG)


def cplane_installer():
    filename = json.load(open(FILES_PATH))
    saved_path = os.getcwd()
    os.chdir(CHARM_LIB_DIR)
    cmd = ['unzip', '-o', filename[config('controller-app-mode')]]
    subprocess.check_call(cmd)
    load_config()
    set_oracle_host()
    if config('jboss-db-on-host') is False:
        set_config('DB_HOSTNAME', ORACLE_HOST, CONTROLLER_CONFIG)
        set_config('DB_SID', DB_SERVICE, CONTROLLER_CONFIG)
    os.chdir('PKG/pkg')
    cmd = ['tar', 'xvf', 'db_init.tar']
    subprocess.check_call(cmd)
    if DB_SERVICE is not 'XE':
        cmd = "cp {}/cp_wf.sql db_init/.".format(CHARM_LIB_DIR)
        os.system(cmd)
    os.chdir(CHARM_LIB_DIR + '/PKG')
    cmd = ['chmod', '+x', 'cpinstaller']
    subprocess.check_call(cmd)

    cmd = ['sh', 'cpinstaller', CONTROLLER_CONFIG]
    subprocess.check_call(cmd)
    os.chdir(saved_path)
    if DB_SERVICE is not 'XE':
        set_data_source()


def start_jboss_service():
    os.system('bash startJBossServer.sh')
    for num in range(0, 5):
        status = commands.getoutput('bash checkJBossServer.sh')
        if status == "JBoss server is not running!":
            log("JBoss is not yet started... Retry checking it after 60 sec")
            time.sleep(60)
        else:
            log("JBoss server is started")
            return True
    return False


def initialize_programs(install_type):
    if is_leader():
        import pexpect
        child = pexpect.spawn("bash startInitializePrograms.sh", timeout=1500)
        child.sendline(install_type)
        if install_type == 'I':
            child.sendline('y')
        child.timeout = 3000
        child.expect(pexpect.EOF)
        log('{}'.format(child.before))
        log("Initialize programs Completed")
        notify_clients()


def stop_jboss_service():
    saved_path = os.getcwd()
    os.chdir(CPLANE_DIR)
    os.system('bash stopJBossServer.sh')
    os.chdir(saved_path)


def start_services(install_type):
    saved_path = os.getcwd()
    os.chdir(CPLANE_DIR)

    status = False
    if is_leader() or is_leader_ready():
        status = start_jboss_service()

    if status is True:
        if install_type == 'reuse-db':
            initialize_programs('P')
        elif install_type == 'clean-db':
            initialize_programs('I')
        elif install_type == 'create-db':
            initialize_programs('I')
        if is_leader_ready():
            cmd = ['bash', 'startStartupPrograms.sh']
            subprocess.check_call(cmd)
            os.chdir(saved_path)
    else:
        log("Setup not completed")


def set_config(key, value, config_file):
    path = CHARM_LIB_DIR + 'PKG/' + config_file
    cmd = "sed -ie 's/{}:.*/{}: {}/g' {}". format(key, key, value, path)
    os.system(cmd)


def check_fip_mode():
    xmldoc = minidom.parse('/opt/cplane/bin/ovsConfig.xml')
    itemlist = xmldoc.getElementsByTagName('Option')
    for s in itemlist:
        if s.attributes['Name'].value == 'GatewayBridgeFipExt':
            return (s.attributes['Value'].value)


def get_upgrade_type():
    upgrade_type = commands.getoutput("cat $CHARM_DIR/config/upgrade-config | \
awk '{ print $2}'")
    return upgrade_type


def flush_upgrade_type():
    cmd = "echo upgrade-type: create-db > $CHARM_DIR/config/upgrade-config"
    os.system(cmd)


def clean_create_db():
    if config('jboss-db-on-host'):
        set_oracle_env()
    set_oracle_host()
    host = ORACLE_HOST + '/'
    saved_path = os.getcwd()
    os.chdir('{}/PKG/pkg/db_init'.format(CHARM_LIB_DIR))
    cmd = 'sh un_install.sh {}/{}@{}{} 2>&1 | tee install.log'\
          .format(config('db-user'), config('db-password'), host, DB_SERVICE)
    os.system(cmd)
    cmd = 'sh install.sh {}/{}@{}{} 2>&1 | tee install.log'\
          .format(config('db-user'), config('db-password'), host, DB_SERVICE)
    os.system(cmd)
    connect_string = '{}/{}@{}{}'.format(config('db-user'), config('db-\
password'), host, DB_SERVICE)
    execute_sql_command(connect_string, "@reinstall_plsql")
    os.chdir(saved_path)


def check_jboss_service():
    saved_path = os.getcwd()
    os.chdir(CPLANE_DIR)
    status = commands.getoutput('bash checkJBossServer.sh')
    ret_val = ''
    if status == "JBoss server is not running!":
        ret_val = False
    else:
        os.chdir(saved_path)
        return True

    if ret_val is False:
        time.sleep(150)
        status = commands.getoutput('bash checkJBossServer.sh')
        os.chdir(saved_path)
        if status == "JBoss server is not running!":
            return False
        else:
            return True


def run_cp_installer():
    saved_path = os.getcwd()
    os.chdir(CHARM_LIB_DIR)
    load_config()
    set_oracle_host()
    if config('jboss-db-on-host') is False:
        set_config('DB_HOSTNAME', ORACLE_HOST, CONTROLLER_CONFIG)
        set_config('DB_SID', DB_SERVICE, CONTROLLER_CONFIG)
    os.chdir('PKG')
    cmd = ['sh', 'cpinstaller', CONTROLLER_CONFIG]
    subprocess.check_call(cmd)
    os.chdir(saved_path)
    if DB_SERVICE is not 'XE':
        set_data_source()


def install_reboot_scripts():
    saved_path = os.getcwd()
    os.chdir(CPLANE_DIR)
    cmd = "sed -i -e 's/#!\/bin\/sh/#!\/bin\/bash/g' startInitialize\
           Programs.sh"
    os.system(cmd)
    cmd = "sed -i -e 's/#!\/bin\/sh/#!\/bin\/bash/g' startJBossServer.sh"
    os.system(cmd)
    cmd = "sed -i -e 's/#!\/bin\/sh/#!\/bin\/bash/g' startStartupPrograms.sh"
    os.system(cmd)
    os.chdir(saved_path)
    if config('jboss-db-on-host'):
        cmd = 'update-rc.d {} defaults 20 '.format(config('oracle-version'))
        os.system(cmd)
    cmd = 'update-rc.d cplane-controller defaults 30'
    os.system(cmd)


def set_oracle_host():
    global ORACLE_HOST
    global DB_SERVICE
    global DB_PASSWORD
    global DB_PATH
    if config('jboss-db-on-host'):
        DB_SERVICE = 'XE'
        DB_PASSWORD = config('oracle-password')
        ORACLE_HOST = 'localhost'
        DB_PATH = '/u01/app/oracle/oradata/XE/'
        return ORACLE_HOST
    for rid in relation_ids('oracle'):
        for unit in related_units(rid):
            oracle_host = relation_get(attribute='oracle-\
host', unit=unit, rid=rid)
            db_service = relation_get(attribute='db-\
service', unit=unit, rid=rid)
            raw_scan_string = relation_get(attribute='scan-string\
', unit=unit, rid=rid)
            db_password = relation_get(attribute='db-password\
', unit=unit, rid=rid)
            db_path = relation_get(attribute='db-path\
', unit=unit, rid=rid)
            if raw_scan_string:
                scan_string = pickle.loads(raw_scan_string)
                flush_host()
                for value in scan_string:
                    config_host(value, 'scan')
            if db_service:
                DB_SERVICE = db_service
            if db_password:
                DB_PASSWORD = db_password
            if db_path:
                DB_PATH = db_path
            if oracle_host:
                ORACLE_HOST = oracle_host
                return oracle_host
            else:
                return oracle_host


class UnconfiguredInterface(Exception):
    pass


def get_unit_ip(config_override='multicast-intf', address_family=ni.AF_INET):
    """Get the IP of this unit for cplane-controller relationship

    If the config override interface is configured use that address otherwise
    consult network-get for the correct address. As a last resort use the
    fallback interface.

    @param config_overide: The string name of the configuration value that can
                           override the use of network spaces
    @param address_family: The netifaces address familiy
                           i.e. for IPv4 AF_INET
                           Only used when config(config_override) is configured
    @returns: IP address for this unit for the cplane-controller relationship
    """

    # If the config override is not set to an interface use network-get
    # to leverage network spaces in MAAS 2.x
    if not config(config_override):
        try:
            return network_get_primary_address('cplane-controller')
        except NotImplementedError:
            # Juju 1.x enviornment
            return unit_get('private-address')

    interface = config(config_override)
    try:
        interface_config = ni.ifaddresses(interface).get(address_family)
        if interface_config:
            for link in interface_config:
                addr = link['addr']
                if addr:
                    return addr
    except ValueError as e:
        raise UnconfiguredInterface("Interface {} is invalid: {}"
                                    "".format(interface, e.message))
    raise UnconfiguredInterface("{} interface has no address in the "
                                "address family {}".format(interface,
                                                           address_family))


def flush_host():
    host_file = "/etc/hosts"
    cmd = ("sed -i '/#Added by cplane/q' {}".format(host_file))
    os.system(cmd)
    cmd = "echo '\n# SCAN' >> /etc/hosts"
    os.system(cmd)


def config_host(host_string, address_type):
    if host_string:
        host_file = "/etc/hosts"
        if address_type == 'scan':
            cmd = ("sed -i '/# SCAN/a{}' {}".format(host_string, host_file))
            os.system(cmd)


def check_jboss_status():
    status = commands.getoutput('bash /opt/cplane/bin/checkJBossServer.sh')
    if status == "JBoss server is not running!":
        return False
    elif status == "JBoss server is running!":
        return True


def assess_status(configs):
    assess_status_func(configs)()
    if config('controller-app-mode') == 'dvnd':
        hookenv.application_version_set(config('cplane-version'))
    else:
        hookenv.application_version_set(str(config('msm-version')))


def assess_status_func(configs):
    required_interfaces = REQUIRED_INTERFACES.copy()
    return make_assess_status_func(
        configs, required_interfaces, services=SERVICES
    )


class FakeOSConfigRenderer(object):
    def complete_contexts(self):
        interfaces = []
        for key, values in REQUIRED_INTERFACES.items():
            for value in values:
                for rid in relation_ids(value):
                    for unit in related_units(rid):
                        interfaces.append(value)
        return interfaces

    def get_incomplete_context_data(self, interfaces):
        return {}


def fake_register_configs():
    return FakeOSConfigRenderer()


def get_os_release():
    ubuntu_release = commands.getoutput('lsb_release -r')
    return ubuntu_release.split()[1]


def is_leader_ready():
    db_status = leader_get('status')
    if db_status == 'db_created':
        log('Response from leader for DB status {}'.format(db_status))
        return True
    else:
        log('Waiting from leader for DB status {}'.format(db_status))
        return False


def notify_clients():
    if is_leader():
        leader_set({'status': "db_created"})


def is_oracle_relation_joined():
    oracle_host = ''
    for rid in relation_ids('oracle'):
        for unit in related_units(rid):
            oracle_host = relation_get(attribute='oracle-\
host', unit=unit, rid=rid)

    if oracle_host:
        return True
    else:
        return False


def set_data_source():
    if DB_SERVICE != 'XE':
        log('Configuring cplane-OracleDB-ds.xml file')
        cmd = "sed -i 's/:{}/\/{}/g' /opt/jboss/jboss-6.1.0.Final/server/all/\
deploy/cplane-OracleDB-ds.xml".format(DB_SERVICE, DB_SERVICE)
        os.system(cmd)
        log('Configuring quartz.properties file')
        cmd = "sed -i 's/:{}/\/{}/g' /opt/jboss/jboss-6.1.0.Final/server/all/\
conf/quartz.properties".format(DB_SERVICE, DB_SERVICE)
        os.system(cmd)
