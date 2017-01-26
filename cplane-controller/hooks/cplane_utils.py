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
    (config('controller-app-mode'), '0')
])

if config('jboss-db-on-host') == 'n':
    del cplane_packages[config('oracle-version')]
elif config('jboss-db-on-host') == 'y':
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
    ('jboss-db-on-host', 'JBOSS_DB_ON_HOST')
])

ORACLE_HOST = ''
JBOSS_DIR = '/opt/jboss'
CHARM_LIB_DIR = os.environ.get('CHARM_DIR', '') + "/lib/"
CPLANE_DIR = '/opt/cplane/bin'
DB_DIR = os.environ.get('CHARM_DIR', '') + "/lib/" + 'PKG/pkg/db_init/'
FILES_PATH = CHARM_LIB_DIR + '/filelink'


def determine_packages():
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
    child = pexpect.spawn("/etc/init.d/oracle-xe configure", timeout=300)
    child.sendline(config('oracle-http-port'))
    child.sendline(config('oracle-listener-port'))
    child.sendline(config('oracle-password'))
    child.sendline(config('oracle-password'))
    child.sendline(config('oracle-db-enable'))
    child.timeout = 300
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


def prepare_database():
    saved_path = os.getcwd()
    set_oracle_host()
    os.chdir(DB_DIR)
    host = ORACLE_HOST + '/'
    log('preparing the Database')
    connect_string = 'system/' + config('oracle-\
password') + '@' + host + 'XE'
    execute_sql_command(connect_string, "@cp_create_ts /\
u01/app/oracle/oradata/XE/")
    execute_sql_command(connect_string, "@cp_create_user {} \
{}".format(config('db-user'), config('db-password')))
    execute_sql_command(connect_string, "grant \
resource to {};".format(config('db-user')))
    execute_sql_command(connect_string, "grant \
create view to {};".format(config('db-user')))

    cmd = 'sh install.sh {}/{}@{}XE 2>&1 | tee \
install.log'.format(config('db-user'), config('db-password'), host)
    os.system(cmd)
    connect_string = '{}/{}@{}XE'.format(config('db-user'), config('db-\
password'), host)
    execute_sql_command(connect_string, "@install_plsql")
    os.chdir(saved_path)


def load_config():
    if config('controller-app-mode') == 'dvnd':
        for key, value in DVND_CONFIG.items():
            set_config(value, config(key), 'cplane-dvnd-config.yaml')
        set_config('multicastServerInterface', config('multicast-intf'),
                   'cplane-dvnd-config.yaml')
        if config('use-default-jboss-cluster') == 'n':
            hostname = socket.gethostname()
            cluster_name = 'cplane' + '-' + hostname
            set_config('JBOSS_CLUSTER_NAME', cluster_name,
                       'cplane-dvnd-config.yaml')


def cplane_installer():
    filename = json.load(open(FILES_PATH))
    saved_path = os.getcwd()
    os.chdir(CHARM_LIB_DIR)
    cmd = ['unzip', '-o', filename[config('controller-app-mode')]]
    subprocess.check_call(cmd)
    load_config()
    set_oracle_host()
    if config('jboss-db-on-host') == 'n':
        set_config('DB_HOSTNAME', ORACLE_HOST, 'cplane-dvnd-config.yaml')
    os.chdir('PKG/pkg')
    cmd = ['tar', 'xvf', 'db_init.tar']
    subprocess.check_call(cmd)

    os.chdir(CHARM_LIB_DIR + '/PKG')
    cmd = ['chmod', '+x', 'cpinstaller']
    subprocess.check_call(cmd)

    cmd = ['sh', 'cpinstaller', 'cplane-dvnd-config.yaml']
    subprocess.check_call(cmd)
    os.chdir(saved_path)


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
    import pexpect
    child = pexpect.spawn("bash startInitializePrograms.sh", timeout=1500)
    child.sendline(install_type)
    if install_type == 'I':
        child.sendline('y')
    child.timeout = 3000
    child.expect(pexpect.EOF)
    log('{}'.format(child.before))
    log("Initialize programs Completed")


def stop_jboss_service():
    saved_path = os.getcwd()
    os.chdir(CPLANE_DIR)
    os.system('bash stopJBossServer.sh')
    os.chdir(saved_path)


def start_services(install_type):
    saved_path = os.getcwd()
    os.chdir(CPLANE_DIR)

    status = start_jboss_service()

    if status is True:
        if install_type == 'reuse-db':
            initialize_programs('P')
        elif install_type == 'clean-db':
            initialize_programs('I')
        elif install_type == 'create-db':
            initialize_programs('I')

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
    if config('jboss-db-on-host') == 'y':
        set_oracle_env()
    set_oracle_host()
    host = ORACLE_HOST + '/'
    saved_path = os.getcwd()
    os.chdir('{}/PKG/pkg/db_init'.format(CHARM_LIB_DIR))
    cmd = 'sh un_install.sh {}/{}@{}XE 2>&1 | tee install.log'\
          .format(config('db-user'), config('db-password'), host)
    os.system(cmd)
    cmd = 'sh install.sh {}/{}@{}XE 2>&1 | tee install.log'\
          .format(config('db-user'), config('db-password'), host)
    os.system(cmd)
    connect_string = '{}/{}@{}XE'.format(config('db-user'), config('db-\
password'), host)
    execute_sql_command(connect_string, "@reinstall_plsql")
    os.chdir(saved_path)


def check_jboss_service():
    saved_path = os.getcwd()
    os.chdir(CPLANE_DIR)
    status = commands.getoutput('bash checkJBossServer.sh')
    if status == "JBoss server is not running!":
        return False
    else:
        return True
    os.chdir(saved_path)


def run_cp_installer():
    saved_path = os.getcwd()
    os.chdir(CHARM_LIB_DIR)
    load_config()
    set_oracle_host()
    if config('jboss-db-on-host') == 'n':
        set_config('DB_HOSTNAME', ORACLE_HOST, 'cplane-dvnd-config.yaml')
    os.chdir('PKG')
    cmd = ['sh', 'cpinstaller', 'cplane-dvnd-config.yaml']
    subprocess.check_call(cmd)
    os.chdir(saved_path)


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
    if config('jboss-db-on-host') == 'y':
        cmd = 'update-rc.d {} defaults 20 '.format(config('oracle-version'))
        os.system(cmd)
    cmd = 'update-rc.d cplane-controller defaults 30'
    os.system(cmd)


def set_oracle_host():
    global ORACLE_HOST
    if config('jboss-db-on-host') == 'y':
        ORACLE_HOST = 'localhost'
        return ORACLE_HOST
    for rid in relation_ids('oracle'):
        for unit in related_units(rid):
            oracle_host = relation_get(attribute='oracle-\
host', unit=unit, rid=rid)
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
