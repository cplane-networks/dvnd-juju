import os
import subprocess
import json
import re
import pwd
import pickle

from subprocess import PIPE

from collections import OrderedDict
from charmhelpers.contrib.openstack.utils import os_release
from charmhelpers.contrib.openstack import templating
from charmhelpers.core.hookenv import (
    config,
    log,
    relation_ids,
    relation_get,
    related_units,
    relation_set,
    unit_get,
)

from charmhelpers.contrib.openstack.utils import (
    make_assess_status_func,
)
import cplane_context
import charmhelpers.core.hookenv as hookenv

from cplane_package_manager import(
    CPlanePackageManager
)

from charmhelpers.fetch import (
    apt_install,
)

from charmhelpers.core.host import (
    mkdir,
    chownr,
)

from charmhelpers.contrib.python.packages import (
    pip_install,
)

TEMPLATES = 'templates/'
CHARM_LIB_DIR = os.environ.get('CHARM_DIR', '') + "/lib/"

KEYSTONE_CONFIG = '/etc/keystone/keystone.conf'
FILES_PATH = CHARM_LIB_DIR + '/filelink'

file_header = (
    '\n################################################\n',
    '# Added by Cplane controller\'s Oracle client  #\n',
    '################################################\n')


cplane_packages = OrderedDict([
    ('authenticate-cplane', -1),
    ('oracle-client-basic', config('oracle-client-basic')),
    ('oracle-sqlplus', config('oracle-sqlplus')),
])


if config('db-on-host'):
    del cplane_packages['oracle-client-basic']
    del cplane_packages['oracle-sqlplus']


PACKAGES = ['libssl-dev', 'apache2', 'apache2-utils', 'alien',
            'libexpat1', 'ssl-cert', 'apache2-dev', 'libapache2-mod-wsgi']

PIP_PACKAGES = ['cx-Oracle==7.0.0', 'mod_wsgi', 'six']

CPLANE_URL = config('cp-package-url')

if config('db-on-host') is False:
    REQUIRED_INTERFACES = {
        'database': ['oracle'],
    }
else:
    REQUIRED_INTERFACES = {}

SERVICES = ['apache2']
ORACLE_HOST = ''
DB_SERVICE = ''
DB_PASSWORD = ''
DB_PATH = ''


def determine_packages():
    return PACKAGES


def determine_pip_packages():
    return PIP_PACKAGES


def register_configs(release=None):
    resources = OrderedDict([
        (KEYSTONE_CONFIG, {
            'services': ['keystone'],
            'contexts': [cplane_context.CplaneKeystoneContext(
                         set_oracle_host(), DB_SERVICE)]
        })
    ])
    release = os_release('keystone')
    configs = templating.OSConfigRenderer(templates_dir=TEMPLATES,
                                          openstack_release=release)
    for cfg, rscs in resources.iteritems():
        configs.register(cfg, rscs['contexts'])
    return configs


def download_cplane_packages():
    filename = {}
    cp_package = CPlanePackageManager(CPLANE_URL)
    for key, value in cplane_packages.items():
        filename[key] = cp_package.download_package(key, value)
        log('downloaded {} package'.format(filename[key]))
    json.dump(filename, open(FILES_PATH, 'w'))


def install_cplane_packages():
    filename = json.load(open(FILES_PATH))
    saved_path = os.getcwd()
    os.chdir(CHARM_LIB_DIR)
    cmd = ['tar', '-xvf', filename["authenticate-cplane"], '-C', CHARM_LIB_DIR]
    subprocess.check_call(cmd)
    os.chdir(saved_path)


def prepare_env():
    saved_path = os.getcwd()
    os.chdir('{}'.format(CHARM_LIB_DIR + "oracle_keystone"))
    cmd = "useradd --home-dir /var/lib/keystone --create-home \
--system --shell /bin/false keystone"
    os.system(cmd)
    mkdir("/var/log/keystone")
    mkdir("/etc/keystone")
    chownr("/var/log/keystone", 'keystone', 'keystone')
    chownr("/var/lib/keystone", 'keystone', 'keystone')
    chownr("/etc/keystone", 'keystone', 'keystone')

    cmd = "cp ./etc/keystone.conf.sample /etc/keystone/keystone.conf"
    os.system(cmd)
    cmd = "cp ./etc/keystone-paste.ini /etc/keystone/keystone-paste.ini"
    os.system(cmd)
    cmd = "cp ./etc/default_catalog.templates /etc/keystone/\
default_catalog.templates"
    os.system(cmd)
    cmd = "cp ./etc/logging.conf.sample /etc/keystone/logging.conf"
    os.system(cmd)
    cmd = "cp ./etc/policy.v3cloudsample.json /etc/keystone/policy.json"
    os.system(cmd)
    cmd = "cp ./etc/sso_callback_template.html /etc/keystone/\
sso_callback_template.html"
    os.system(cmd)
    cmd = "cp ./httpd/wsgi-keystone.conf /etc/apache2/sites-available/\
keystone.conf"
    os.system(cmd)
    cmd = "cp ./httpd/wsgi-keystone.conf /etc/apache2/sites-enabled/\
keystone.conf"
    os.system(cmd)
    os.chdir(saved_path)


def install_keystone():
    saved_path = os.getcwd()
    os.chdir('{}'.format(CHARM_LIB_DIR + "oracle_keystone"))
    pip_install('.')
    os.chdir(saved_path)
    with open("/etc/apache2/apache2.conf", "a") as apache_conf:
        apache_conf.write("ServerName {}".format(unit_get('private-address')))


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


def set_oracle_host():
    global ORACLE_HOST
    global DB_SERVICE
    global DB_PASSWORD
    global DB_PATH
    if config('db-on-host'):
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


def create_domain():
    cmd = "openstack --os-username admin \
--os-password password \
--os-project-name admin \
--os-user-domain-name Default \
--os-project-domain-name Default \
--os-auth-url http://localhost:35357/v3 \
--os-identity-api-version 3 \
project create --domain default   \
--description 'Service Project' service"

    os.system(cmd)
    cmd = "openstack --os-username admin \
--os-password password \
--os-project-name admin \
--os-user-domain-name Default \
--os-project-domain-name Default \
--os-auth-url http://localhost:35357/v3 \
--os-identity-api-version 3 \
role create user"
    os.system(cmd)


def deb_convert_install(module):
    filename = json.load(open(FILES_PATH))
    saved_path = os.getcwd()
    os.chdir(CHARM_LIB_DIR)
    cmd = ['alien', '--scripts', '-d', '-i', filename[module]]
    subprocess.check_call(cmd)
    os.chdir(saved_path)
    options = "--fix-broken"
    apt_install(options, fatal=True)


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


def execute_sql_command(connect_string, sql_command):
    session = subprocess.Popen(['sqlplus', '-S', connect_string], stdin=PIPE,
                               stdout=PIPE, stderr=PIPE)
    session.stdin.write(sql_command)
    log('{}'.format(session.communicate()))


def create_ketstone_user():
    set_oracle_host()
    host = ORACLE_HOST + '/'
    log('Creating keystone user')
    connect_string = 'sys/' + DB_PASSWORD \
        + '@' + host + DB_SERVICE + ' as' + ' sysdba'
    execute_sql_command(connect_string, "create user {} \
identified by {};".format(config('database-user'),
                          config('database-password')))
    execute_sql_command(connect_string, "grant all privileges to {} \
identified by {};".format(config('database-user'),
                          config('database-password')))


def configure_keystone():
    cmd = 'su -s /bin/sh -c "keystone-manage db_sync" keystone'
    os.system(cmd)
    cmd = 'keystone-manage fernet_setup --keystone-user keystone \
--keystone-group keystone'
    os.system(cmd)
    cmd = 'keystone-manage credential_setup --keystone-user keystone \
--keystone-group keystone'
    os.system(cmd)
    private_ip = unit_get('private-address')
    cmd = 'keystone-manage bootstrap --bootstrap-password password \
--bootstrap-admin-url http://{}:35357/v3/ \
--bootstrap-internal-url http://{}:5000/v3/ \
--bootstrap-public-url http://{}:5000/v3/ \
--bootstrap-region-id RegionOne'.format(private_ip, private_ip, private_ip)
    os.system(cmd)


def send_active_notification():
    relation_info = {
        'keystone-active': True 
    }
    for rid in relation_ids('auth'):
        relation_set(relation_id=rid,
                     relation_settings=relation_info)

def restart_service():
    cmd = ['service', 'apache2', 'restart']
    subprocess.check_call(cmd)


def assess_status(configs):
    assess_status_func(configs)()
    hookenv.application_version_set(
        config('cplane-version'))


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
