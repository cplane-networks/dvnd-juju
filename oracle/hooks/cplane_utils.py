import subprocess
import commands


from collections import OrderedDict
from charmhelpers.core.hookenv import (
    config,
    log,
    relation_ids,
    related_units,

)

from charmhelpers.fetch import (
    apt_install,
)

import os

from cplane_package_manager import(
    CPlanePackageManager
)

from charmhelpers.contrib.openstack.utils import (
    make_assess_status_func,
)

import charmhelpers.core.hookenv as hookenv


cplane_packages = OrderedDict([
    (config('oracle-version'), '0')
])


PACKAGES = ['alien', 'libaio1', 'python-pexpect']


CPLANE_URL = config('cp-package-url')

DVND_CONFIG = OrderedDict([
    ('db-user', 'DB_USERNAME'),
    ('db-password', 'DB_PASSWORD'),
])

filename = {}

CHARM_LIB_DIR = os.environ.get('CHARM_DIR', '') + "/lib/"

REQUIRED_INTERFACES = {}
SERVICES = []


def determine_packages():
    if get_os_release() == '16.04':
        PACKAGES.extend(['bc', 'unixodbc'])
    return PACKAGES


def download_cplane_packages():
    cp_package = CPlanePackageManager(CPLANE_URL)
    for key, value in cplane_packages.items():
        filename[key] = cp_package.download_package(key, value)
        log('downloaded {} package'.format(filename[key]))


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


def deb_convert_install(module):
    saved_path = os.getcwd()
    os.chdir(CHARM_LIB_DIR)
    cmd = ['alien', '--scripts', '-d', '-i', filename[module]]
    subprocess.check_call(cmd)
    os.chdir(saved_path)
    options = "--fix-broken"
    apt_install(options, fatal=True)


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


def install_reboot_scripts():
    cmd = 'update-rc.d {} defaults 20 '.format(config('oracle-version'))
    os.system(cmd)


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


def get_os_release():
    ubuntu_release = commands.getoutput('lsb_release -r')
    return ubuntu_release.split()[1]
