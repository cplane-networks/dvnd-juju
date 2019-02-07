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

NEUTRON_CONFIG = '/etc/neutron/neutron.conf'
ML2_CONFIG_INI = '/etc/neutron/plugins/ml2/ml2_conf.ini'

FILES_PATH = CHARM_LIB_DIR + '/filelink'

file_header = (
    '\n################################################\n',
    '# Added by Cplane controller\'s Oracle client  #\n',
    '################################################\n')


cplane_packages = OrderedDict([
    ('network-cplane', -1),
    ('oracle-client-basic', config('oracle-client-basic')),
    ('oracle-sqlplus', config('oracle-sqlplus')),
    ('cplane-neutron-plugin', -1),
    ('cplane-neutronclient-extension', -1),
    ('cplane-nova-extension', -1),
])


if config('db-on-host'):
    del cplane_packages['oracle-client-basic']
    del cplane_packages['oracle-sqlplus']


PACKAGES = ['libssl-dev', 'alien', 'python-urllib3', 'build-essential', 'python-bitarray']

PIP_PACKAGES = ['cx-Oracle', 'six', 'python-memcached', 'pyopenssl']

CPLANE_URL = config('cp-package-url')

if config('db-on-host') is False:
    REQUIRED_INTERFACES = {
        'database': ['oracle'],
        'keystone': ['auth'],
    }
else:
    REQUIRED_INTERFACES = {
        'keystone': ['auth'],
    }


SERVICES = ['neutron-server']
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
        (NEUTRON_CONFIG, {
            'services': ['neutron'],
            'contexts': [cplane_context.CplaneNeutronContext(
                         set_oracle_host(), DB_SERVICE)]
        }),
        (ML2_CONFIG_INI, {
            'services': ['neutron-server'],
            'contexts': [cplane_context.CplaneMl2Context(), ]
        }),
    ])
    release = os_release('neutron-server')
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
    cmd = ['tar', '-xvf', filename["network-cplane"], '-C', CHARM_LIB_DIR]
    subprocess.check_call(cmd)
    os.chdir(saved_path)


def prepare_env():
    saved_path = os.getcwd()
    os.chdir('{}'.format(CHARM_LIB_DIR + "oracle_neutron"))
    cmd = "useradd --home-dir /var/lib/neutron --create-home \
--system --shell /bin/false neutron"
    os.system(cmd)
    mkdir("/var/log/neutron")
    mkdir("/etc/neutron")
    mkdir("/etc/neutron/rootwrap.d")
    mkdir("/etc/neutron/plugins/ml2")

    chownr("/var/log/neutron", 'neutron', 'neutron')
    chownr("/var/lib/neutron", 'neutron', 'neutron')
    chownr("/etc/neutron", 'neutron', 'neutron')
    chownr("/etc/neutron", 'neutron', 'neutron')
    chownr("/etc/neutron/plugins", 'neutron', 'neutron')    
    os.chmod("/var/log/neutron", 0o766)
    os.system(cmd)

    
    cmd = "./tools/generate_config_file_samples.sh"
    os.system(cmd)


    cmd = "cp etc/api-paste.ini /etc/neutron/api-paste.ini"
    os.system(cmd)
    cmd = "cp etc/policy.json /etc/neutron/policy.json"
    os.system(cmd)
    cmd = "cp etc/rootwrap.conf /etc/rootwrap.conf"
    os.system(cmd)
    cmd = "cp -R etc/neutron/rootwrap.d/* /etc/neutron/rootwrap.d/"
    os.system(cmd)
    cmd = "cp etc/rootwrap.conf /etc/neutron/rootwrap.conf"
    os.system(cmd)
    os.chdir(saved_path)


def install_neutron():
    saved_path = os.getcwd()
    os.chdir('{}'.format(CHARM_LIB_DIR + "oracle_neutron"))
    pip_install('.')
    os.chdir(saved_path)


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


def create_openstack_neutron_user():
    keystone_ip = get_auth_url()
    
    cmd = "openstack --os-username admin \
--os-password password \
--os-project-name admin \
--os-user-domain-name Default \
--os-project-domain-name Default \
--os-auth-url http://{}:35357/v3 \
--os-identity-api-version 3 \
user create --domain default   \
--password password neutron".format(keystone_ip)
    if keystone_ip:
        os.system(cmd)
    cmd = "openstack --os-username admin \
--os-password password \
--os-project-name admin \
--os-user-domain-name Default \
--os-project-domain-name Default \
--os-auth-url http://{}:35357/v3 \
--os-identity-api-version 3 \
role add --project service --user neutron admin".format(keystone_ip)
    if keystone_ip:
        os.system(cmd)


def create_openstack_neutron_service():
    keystone_ip = get_auth_url()
    cmd = "openstack --os-username admin \
--os-password password \
--os-project-name admin \
--os-user-domain-name Default \
--os-project-domain-name Default \
--os-auth-url http://{}:35357/v3 \
--os-identity-api-version 3 \
service create --name neutron --description 'OpenStack Networking' network".format(keystone_ip)
    if keystone_ip:
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


def create_neutron_user():
    set_oracle_host()
    host = ORACLE_HOST + '/'
    log('Creating neutron user')
    connect_string = 'sys/' + DB_PASSWORD \
        + '@' + host + DB_SERVICE + ' as' + ' sysdba'
    execute_sql_command(connect_string, "create user {} \
identified by {};".format(config('database-user'),
                          config('database-password')))
    execute_sql_command(connect_string, "grant all privileges to {} \
identified by {};".format(config('database-user'),
                          config('database-password')))


def configure_neutron():
    cmd = "su -s /bin/sh -c 'neutron-db-manage --config-file /etc/neutron/neutron.conf \
--config-file /etc/neutron/plugins/ml2/ml2_conf.ini upgrade head' neutron"
    os.system(cmd)

def create_neutron_endpoint():
    keystone_ip = get_auth_url()
    private_ip = unit_get('private-address')
    cmd = "openstack --os-username admin \
--os-password password \
--os-project-name admin \
--os-user-domain-name Default \
--os-project-domain-name Default \
--os-auth-url http://{}:35357/v3 \
--os-identity-api-version 3 \
endpoint create  --region RegionOne network public \
http://{}:9696".format(keystone_ip, private_ip)
    if keystone_ip:
        os.system(cmd)

    cmd = "openstack --os-username admin \
--os-password password \
--os-project-name admin \
--os-user-domain-name Default \
--os-project-domain-name Default \
--os-auth-url http://{}:35357/v3 \
--os-identity-api-version 3 \
endpoint create  --region RegionOne network internal \
http://{}:9696".format(keystone_ip, private_ip)
    if keystone_ip:
        os.system(cmd)

    cmd = "openstack --os-username admin \
--os-password password \
--os-project-name admin \
--os-user-domain-name Default \
--os-project-domain-name Default \
--os-auth-url http://{}:35357/v3 \
--os-identity-api-version 3 \
endpoint create  --region RegionOne network admin \
http://{}:9696".format(keystone_ip, private_ip)
    if keystone_ip:
        os.system(cmd)


def get_auth_url():
    keystone_ip = ''
    for rid in relation_ids('auth'):
        for unit in related_units(rid):
            keystone_ip = relation_get(attribute='private-address', unit=unit, rid=rid)
    if keystone_ip:
        return keystone_ip
    else:
        return ''

def restart_service():
    cmd = ['service', 'neutron-server', 'restart']
    subprocess.check_call(cmd)


def copy_neutron_files():
    cmd = 'cp bin/neutron_sudoers /etc/sudoers.d/neutron_sudoers'
    os.system(cmd)
    os.chmod('/etc/sudoers.d/neutron_sudoers', 0o440)
    os.chmod('/etc/sudoers.d', 0o750)
    cmd = "echo 'NEUTRON_PLUGIN_CONFIG="'"/etc/neutron/plugins/ml2/ml2_conf.ini"'"' > /etc/default/neutron-server"
    os.system(cmd)
    cmd = 'cp bin/neutron-server.conf /etc/init/neutron-server.conf'
    os.system(cmd)
    cmd = 'cp bin/neutron-server /etc/init.d/neutron-server'
    os.system(cmd)
    os.chmod('/etc/init.d/neutron-server', 0o755)
    os.system(cmd)
    cmd  = 'systemctl daemon-reload'
    os.system(cmd)
    cmd = 'systemctl enable neutron-server.service'
    os.system(cmd)
    cmd = 'systemctl start neutron-server.service' 

def post_oracle_keystone_calls():
    keystone_status = ''
    oracle_status = ''
    for rid in relation_ids('auth'):
        for unit in related_units(rid):
            keystone_status = relation_get(attribute='keystone-active', unit=unit, rid=rid)
    if config('db-on-host') is True: 
        oracle_status = 'True'
    else:
        for rid in relation_ids('oracle'):
            for unit in related_units(rid):
                oracle_status = 'True'       
    if keystone_status == 'True' and oracle_status == 'True':
        create_openstack_neutron_user()
        create_openstack_neutron_service()
        configure_neutron()
        create_neutron_endpoint()
        restart_service()

def install_cplane_neutron():
    cp_package = CPlanePackageManager(CPLANE_URL)
    for key, value in cplane_packages.items():
        filename = cp_package.download_package(key, value)
        if key == "neutronclient":
            cmd = ['tar', '-xvf', filename, '-C',
                   '/usr/lib/python2.7/dist-packages/']
            subprocess.check_call(cmd)
        elif key == "oracle-client-basic" or key == "oracle-sqlplus" or key == "network-cplane":
            pass
        else:
            cmd = ['dpkg', '-i', filename]
            subprocess.check_call(cmd)
            options = "--fix-broken"
    cmd = 'cp /usr/lib/python2.7/dist-packages/neutron/extensions/* /usr/local/lib/python2.7/dist-packages/neutron/extensions/.'
    os.system(cmd)
def add_controller_ip():
    cplane_controller = ''
    for rid in relation_ids('cplane-controller'):
        for unit in related_units(rid):
            mport = relation_get(attribute='mport', unit=unit, rid=rid)
            data = relation_get(rid=rid, unit=unit)
            if cplane_controller == '':
                cplane_controller = data['private-address']
            else:
                cplane_controller = (cplane_controller + ',' +
                                     data['private-address'])
            if mport:
                cmd = "sed -ie 's/cplane_controller_hosts.*/cplane_controller_\
hosts = {}/g' /etc/neutron/plugins/ml2/ml2_conf.ini".format(cplane_controller)
                os.system(cmd)
                restart_service()

    
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
