import subprocess


from subprocess import PIPE
from collections import OrderedDict
from charmhelpers.core.hookenv import (
    config,
    log,
)

from charmhelpers.fetch import (
    apt_install,
)

import os
import pwd
import commands
import time

from cplane_package_manager import(
    CPlanePackageManager
)

from xml.dom import minidom

cplane_packages = OrderedDict([
    (config('oracle-version'), '0'),
    ('jboss', '0'),
    ('jdk', '0'),
    (config('controller-app-mode'), '0')
])


PACKAGES = ['alien', 'libaio1', 'zlib1g-dev', 'libxml2-dev',
            'libxml-libxml-perl', 'unzip', 'python-pexpect',
            'libyaml-perl']

CPLANE_URL = config('cp-package-url')

DVND_CONFIG = OrderedDict([
    ('multicast-port', 'multicastPort'),
    ('multicast-intf', 'multicastInterface'),
    ('unicast-port', 'unicastPort'),
    ('multicast-srv-intf', 'multicastServerInterface'),
    ('jboss-home', 'JBOSS_HOME'),
    ('db-user', 'DB_USERNAME'),
    ('db-password', 'DB_PASSWORD')
])

filename = {}

JBOSS_DIR = '/opt/jboss'
CHARM_LIB_DIR = os.environ.get('CHARM_DIR', '') + "/lib/"
CPLANE_DIR = '/opt/cplane/bin'


def determine_packages():
    return PACKAGES


def download_cplane_packages():
    cp_package = CPlanePackageManager(CPLANE_URL)
    for key, value in cplane_packages.items():
        filename[key] = cp_package.download_package(key, value)
        print 'downloaded', filename[key]


def download_cplane_installer():
    cp_package = CPlanePackageManager(CPLANE_URL)
    for key, value in cplane_packages.items():
        if key == config('controller-app-mode'):
            filename[key] = cp_package.download_package(key, value)
            print 'downloaded', filename[key]


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
    print child.before


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


def install_jboss():
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
    print session.communicate()


def prepare_database():
    connect_string = 'system/' + config('oracle-password') + '@XE'
    execute_sql_command(connect_string,
                        "@cp_create_ts /u01/app/oracle/oradata/XE/")
    execute_sql_command(connect_string,
                        "@cp_create_user {} {}".format(config('db-user'),
                                                       config('db-password')))
    execute_sql_command(connect_string,
                        "grant resource to {};".format(config('db-user')))
    execute_sql_command(connect_string,
                        "grant create view to {};".format(config('db-user')))

    cmd = 'sh install.sh {}/{}@XE 2>&1 | tee install.log'\
          .format(config('db-user'), config('db-password'))
    os.system(cmd)

    connect_string = '{}/{}@XE'.format(config('db-user'),
                                       config('db-password'))
    execute_sql_command(connect_string, "@install_plsql")


def cplane_installer(install_type):
    saved_path = os.getcwd()
    os.chdir(CHARM_LIB_DIR)
    cmd = ['unzip', '-o', filename[config('controller-app-mode')]]
    subprocess.check_call(cmd)

    load_config()

    os.chdir('PKG/pkg')
    cmd = ['tar', 'xvf', 'db_init.tar']
    subprocess.check_call(cmd)

    if install_type == 'install':
        os.chdir('db_init')
        prepare_database()

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
    child.timeout = 1500
    child.expect(pexpect.EOF)
    print child.before
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

        cmd = ['bash', 'startStartupPrograms.sh']
        subprocess.check_call(cmd)
        os.chdir(saved_path)
    else:
        log("Setup not completed")


def set_config(key, value, config_file):
    path = CHARM_LIB_DIR + '/PKG/' + config_file
    cmd = "sed -ie 's/{}:.*/{}: {}/g' {}". format(key, key, value, path)
    os.system(cmd)


def load_config():
    if config('controller-app-mode') == 'dvnd':
        for key, value in DVND_CONFIG.items():
            set_config(value, config(key), 'cplane-dvnd-config.yaml')


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


def clean_create_db():
    set_oracle_env()
    saved_path = os.getcwd()
    os.chdir('{}/PKG/pkg/db_init'.format(CHARM_LIB_DIR))
    cmd = 'sh un_install.sh {}/{}@XE 2>&1 | tee install.log'\
          .format(config('db-user'), config('db-password'))
    os.system(cmd)
    cmd = 'sh install.sh {}/{}@XE 2>&1 | tee install.log'\
          .format(config('db-user'), config('db-password'))
    os.system(cmd)
    connect_string = '{}/{}@XE'.format(config('db-user'),
                                       config('db-password'))
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
    os.chdir('PKG')
    cmd = ['sh', 'cpinstaller', 'cplane-dvnd-config.yaml']
    subprocess.check_call(cmd)
    os.chdir(saved_path)
