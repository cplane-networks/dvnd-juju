import os
import subprocess
import socket
import fcntl
import struct
import json
import pickle
import commands
import time
from netaddr import IPNetwork
import netifaces
import ipaddr

from subprocess import PIPE
from collections import OrderedDict
from charmhelpers.core.hookenv import (
    config,
    relation_ids,
    relation_get,
    related_units,
    relation_set,
    unit_private_ip,
    log as juju_log,
    log,
    local_unit,
    unit_get,
)


from cplane_package_manager import(
    CPlanePackageManager
)

cplane_packages = OrderedDict([
    (config('oracle-version'), '0'),
    ('oracle-12c-db', '0'),
])

if not config('slave-units-number'):
    del cplane_packages[config('oracle-version')]


CHARM_LIB_DIR = os.environ.get('CHARM_DIR', '') + "/lib/"
FILES_PATH = CHARM_LIB_DIR + '/filelink'
CPLANE_URL = config('cp-package-url')


GROUPS = OrderedDict([('oinstall', 54321),
                      ('dba', 54322),
                      ('oper', 54323)])

PARAMETERS = OrderedDict([('fs.file-max', 6815744),
                          ('kernel.sem', "250 32000 100 128"),
                          ('kernel.shmmni', 4096),
                          ('kernel.shmall', 1073741824),
                          ('kernel.shmmax', 4398046511104),
                          ('net.core.rmem_default', 262144),
                          ('net.core.rmem_max', 4194304),
                          ('net.core.wmem_default', 262144),
                          ('net.core.wmem_max', 1048576),
                          ('fs.aio-max-nr', 1048576),
                          ('net.ipv4.ip_local_port_range', "9000 65500")])


PACKAGES = ['ntp',
            'dnsmasq',
            'binutils',
            'compat-libcap1',
            'compat-libstdc++-33',
            'compat-libstdc++-33.i686',
            'gcc',
            'gcc-c++',
            'glibc',
            'glibc.i686',
            'glibc-devel',
            'glibc-devel.i686',
            'ksh',
            'libgcc',
            'libgcc.i686',
            'libstdc++',
            'libstdc++.i686',
            'libstdc++-devel',
            'libstdc++-devel.i686',
            'libaio',
            'libaio.i686',
            'libaio-devel',
            'libaio-devel.i686',
            'libXext',
            'libXext.i686',
            'libXtst',
            'libXtst.i686',
            'libX11',
            'libX11.i686',
            'libXau',
            'libXau.i686',
            'libxcb',
            'libxcb.i686',
            'libXi',
            'libXi.i686',
            'make',
            'sysstat',
            'unixODBC',
            'unixODBC-devel',
            'epel-release',
            'python34']

NODE_DATA_FILE = os.environ.get('CHARM_DIR', '') + '/node_data'
NODE_CLUSTER_FILE = os.environ.get('CHARM_DIR', '') + '/node_cluster'
GRID_RSP_FILE = '{}/grid/response/grid_\
install.rsp'.format(os.path.expanduser('~oracle'))
DB_RSP_FILE = '{}/database/response/db_\
install.rsp'.format(os.path.expanduser('~oracle'))
NETCA_RSP_FILE = '{}/database/response/netca\
.rsp'.format(os.path.expanduser('~oracle'))


def download_cplane_packages():
    filename = {}
    cp_package = CPlanePackageManager(CPLANE_URL)
    for key, value in cplane_packages.items():
        filename[key] = cp_package.download_package(key, value)
        log('downloaded {} package'.format(filename[key]))
    json.dump(filename, open(FILES_PATH, 'w'))


def determine_packages():
    return PACKAGES


def group_add():
    for group_name, group_id in GROUPS.items():
        cmd = ['groupadd', '-g', '{}'.format(group_id), group_name]
        subprocess.check_call(cmd)


def user_add():
    cmd = ['useradd', '-u', '54321', '-g', 'oinstall', '-G', 'dba,oper',
           'oracle']
    subprocess.check_call(cmd)


def disable_firewall():
    '''cmd = ['systemctl', 'stop', 'postfix', 'firewalld', 'NetworkManager']
    subprocess.check_call(cmd)
    cmd = ['systemctl', 'disable', 'postfix', 'firewalld', 'NetworkManager']
    subprocess.check_call(cmd)
    cmd = ['systemctl', 'mask', 'NetworkManager']
    subprocess.check_call(cmd)
    yum_purge('postfix', fatal = True)
    yum_purge('NetworkManager', fatal = True)
    yum_purge('NetworkManager-libnm', fatal = True)'''

    cmd = ['setenforce', '0']
    subprocess.check_call(cmd)
    cmd = "sed -i 's/enforcing/disabled/g' /etc/selinux/config /etc/\
selinux/config"
    os.system(cmd)


def set_kernel_parameters():
    f = open("/etc/sysctl.conf", "a")
    for key, value in PARAMETERS.items():
        f.write("{} = {}\n".format(key, value))
    f.close()

    limit_conf = "/etc/security/limits.conf"
    data = []
    data.append("{:16}{:8}{:16}{}".format('oracle', 'soft', 'nofile', 1024))
    data.append("{:16}{:8}{:16}{}".format('oracle', 'soft', 'nofile', 1024))
    data.append("{:16}{:8}{:16}{}".format('oracle', 'hard', 'nofile', 65536))
    data.append("{:16}{:8}{:16}{}".format('oracle', 'soft', 'nproc', 2047))
    data.append("{:16}{:8}{:16}{}".format('oracle', 'hard', 'nproc', 16384))
    data.append("{:16}{:8}{:16}{}".format('oracle', 'soft', 'stack', 10240))
    data.append("{:16}{:8}{:16}{}".format('oracle', 'hard', 'stack', 32768))

    for lines in data:
        cmd = ("sed -i '/# End of file/i{}' {}".format(lines, limit_conf))
        os.system(cmd)
    cmd = "sysctl -p"
    os.system(cmd)


def get_ip(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(
        s.fileno(),
        0x8915,  # SIOCGIFADDR
        struct.pack('256s', str(ifname[:15]))
    )[20:24])


def generate_host_string(address_type):
    data = OrderedDict()
    all_strings = {}

    hostname = socket.gethostname()
    domain_name = config('domain-name')

    if address_type == 'private':
        private_address = get_ip(config('private-interface'))
        host_string = private_address + '\t' + hostname + "-priv." + \
            domain_name + '\t' + hostname + "-priv"
    elif address_type == 'public':
        public_address = unit_private_ip()
        host_string = public_address + '\t' + hostname + "." + \
            domain_name + '\t' + hostname
    elif address_type == 'vip':
        service_name = local_unit()
        unit_id = service_name.split('/')[1]
        vip = ipaddr.IPAddress(config('vip-range')) + int(unit_id)
        host_string = format(vip) + '\t' + hostname + "-vip." + \
            domain_name + '\t' + hostname + "-vip"

    if os.path.exists(NODE_DATA_FILE):
        data = json.load(open(NODE_DATA_FILE))
        all_strings = data[hostname]

    all_strings[address_type] = host_string
    data[hostname] = all_strings
    json.dump(data, open(NODE_DATA_FILE, 'w'))
    return host_string


def generate_pub_ssh_key():
    data = OrderedDict()
    all_strings = {}
    hostname = socket.gethostname()
    cmd = "su - oracle -c 'ssh-keygen -t rsa -N \"\" -f ~/.ssh/id_rsa'"
    os.system(cmd)
    cmd = "su - oracle -c 'cat ~/.ssh/id_rsa.pub'"
    key = commands.getoutput(cmd)
    cmd = "echo {} | sed 's/\r//'".format(key)
    public_key = commands.getoutput(cmd)

    if os.path.exists(NODE_DATA_FILE):
        data = json.load(open(NODE_DATA_FILE))
        all_strings = data[hostname]
    all_strings['ssh_pub_key'] = public_key
    data[hostname] = all_strings
    json.dump(data, open(NODE_DATA_FILE, 'w'))
    return public_key


def flush_host():
    host_file = "/etc/hosts"
    cmd = ("sed -i '/#Added by cplane/q' {}".format(host_file))
    os.system(cmd)
    cmd = "echo '\n# Private' >> /etc/hosts"
    os.system(cmd)
    cmd = "echo '\n# Public' >> /etc/hosts"
    os.system(cmd)
    cmd = "echo '\n# Virtual' >> /etc/hosts"
    os.system(cmd)
    cmd = "echo '\n# SCAN' >> /etc/hosts"
    os.system(cmd)


def config_host(host_string, address_type):
    if host_string:
        cmd = ''
        host_file = "/etc/hosts"
        if address_type == 'private':
            cmd = ("sed -i '/# Private/a{}' {}".format(host_string, host_file))
        if address_type == 'public':
            cmd = ("sed -i '/# Public/a{}' {}".format(host_string, host_file))
        if address_type == 'vip':
            cmd = ("sed -i '/# Virtual/a{}' {}".format(host_string, host_file))
        if address_type == 'scan':
            cmd = ("sed -i '/# SCAN/a{}' {}".format(host_string, host_file))
        os.system(cmd)


def config_ssh_key(ssh_pub_key):
    if ssh_pub_key:
        path = '/home/oracle/.ssh'
        cmd = "mkdir {}".format(path)
        if os.path.exists(path) == 0:
            os.system(cmd)
        cmd = ['chmod', '-R', '700', path]
        subprocess.check_call(cmd)
        sshkey_file = '{}/authorized_keys'.format(path)
        f = open(sshkey_file, 'a')
        f.write('\n{}\n'.format(ssh_pub_key))
        cmd = ['chmod', '-R', '600', sshkey_file]
        subprocess.check_call(cmd)
        cmd = ['chown', '-R', 'oracle.oinstall', path]
        subprocess.check_call(cmd)


def process_data():
    identity = ""
    data = OrderedDict()
    all_strings = {}

    for rid in relation_ids('master'):
        for unit in related_units(rid):
            identity = relation_get(attribute='identity\
', unit=unit, rid=rid)
            raw_private_string = relation_get(attribute='private-string\
', unit=unit, rid=rid)
            raw_public_string = relation_get(attribute='public-string\
', unit=unit, rid=rid)
            raw_vip_string = relation_get(attribute='vip-string\
', unit=unit, rid=rid)
            raw_ssh_key = relation_get(attribute='host-ssh-key\
', unit=unit, rid=rid)

            juju_log('Relation confirmed from {}'.format(identity))

            if identity:
                data = json.load(open(NODE_DATA_FILE))
                if identity in data.keys():
                    pass
                else:
                    all_strings['private'] = pickle.loads(raw_private_string)
                    all_strings['public'] = pickle.loads(raw_public_string)
                    all_strings['vip'] = pickle.loads(raw_vip_string)
                    all_strings['ssh_pub_key'] = pickle.loads(raw_ssh_key)
                    data[identity] = all_strings

                    juju_log('Storing node {} data {}'.format(identity,
                                                              data[identity]))
                    json.dump(data, open(NODE_DATA_FILE, 'w'))


def check_all_nodes():
    data = json.load(open(NODE_DATA_FILE))
    if len(data) == config("slave-units-number") + 1:
        return True
    else:
        return False


def append_scan_ip():
    domain_name = config('domain-name')

    scan_ip_string = []
    scan_name = config('scan-name')
    scan_ip = ipaddr.IPAddress(config('scan-ip-range'))
    scan_ip_1 = format(scan_ip) + '\t' + scan_name + "-scan." + \
        domain_name + '\t' + scan_name + "-scan"
    scan_ip_2 = format(scan_ip + 1) + '\t' + scan_name + "-scan." + \
        domain_name + '\t' + scan_name + "-scan"
    scan_ip_3 = format(scan_ip + 2) + '\t' + scan_name + "-scan." + \
        domain_name + '\t' + scan_name + "-scan"

    scan_ip_string.append(scan_ip_1)
    scan_ip_string.append(scan_ip_2)
    scan_ip_string.append(scan_ip_3)
    return scan_ip_string


def send_data_to_slave():
    hostname = socket.gethostname()
    data = OrderedDict()
    private_string = []
    public_string = []
    vip_string = []
    scan_string = []
    ssh_pub_key = []

    data = json.load(open(NODE_DATA_FILE))
    all_strings = data[hostname]
    scan_string = append_scan_ip()
    all_strings['scan'] = scan_string
    data[hostname] = all_strings
    json.dump(data, open(NODE_DATA_FILE, 'w'))

    for node, string in data.items():
        private_string.append(string['private'])
        public_string.append(string['public'])
        vip_string.append(string['vip'])
        ssh_pub_key.append(string['ssh_pub_key'])

    for rid in relation_ids('master'):
        relation_info = {
            'private-string': pickle.dumps(private_string),
            'public-string': pickle.dumps(public_string),
            'vip-string': pickle.dumps(vip_string),
            'scan-string': pickle.dumps(scan_string),
            'ssh-pub-key': pickle.dumps(ssh_pub_key)
        }
        relation_set(rid, relation_settings=relation_info)

    flush_host()

    for value in private_string:
        config_host(value, 'private')
    for value in public_string:
        config_host(value, 'public')
        add_ssh_known_host(value)
    for value in vip_string:
        config_host(value, 'vip')
    for value in scan_string:
        config_host(value, 'scan')
    for value in ssh_pub_key:
        config_ssh_key(value)


def save_name_server(nameserver):
    hostname = socket.gethostname()
    data = OrderedDict()
    data = json.load(open(NODE_DATA_FILE))
    all_strings = data[hostname]
    all_strings['nameserver'] = nameserver
    data[hostname] = all_strings
    json.dump(data, open(NODE_DATA_FILE, 'w'))


def set_all_host_strings():
    private_string = []
    public_string = []
    vip_string = []
    scan_string = []
    ssh_pub_key = []

    for rid in relation_ids('slave'):
        for unit in related_units(rid):
            if relation_get(attribute='private-string\
', unit=unit, rid=rid):
                private_string = pickle.loads(relation_get(attribute='private-\
string', unit=unit, rid=rid))
                public_string = pickle.loads(relation_get(attribute='public-\
string', unit=unit, rid=rid))
                vip_string = pickle.loads(relation_get(attribute='vip-string\
', unit=unit, rid=rid))
                scan_string = pickle.loads(relation_get(attribute='scan-string\
', unit=unit, rid=rid))
                ssh_pub_key = pickle.loads(relation_get(attribute='ssh-pub-key\
', unit=unit, rid=rid))

    if private_string:
        flush_host()
        for value in private_string:
            config_host(value, 'private')

        for value in public_string:
            config_host(value, 'public')
            add_ssh_known_host(value)

        for value in vip_string:
            config_host(value, 'vip')

        for value in scan_string:
            config_host(value, 'scan')

        for value in ssh_pub_key:
            config_ssh_key(value)

        set_disk_permission()

        send_notification("slave-state", 'install')


def modify_oracle_grid_response_file():
    data = json.load(open(NODE_DATA_FILE))
    hostname = socket.gethostname()
    node_string = []
    for node, value in data.items():
        public = value['public']
        node_public = public.split()[1]
        vip = value['vip']
        node_vip = vip.split()[1]
        node_string.append("{}:{},".format(node_public, node_vip))

    oracle_host_name = data[hostname]['public'].split()[1]
    scan_name = data[hostname]['scan'][0].split()[2]
    cluster_nodes = ''.join(node_string)
    cmd = "sed -i '/^ORACLE_HOSTNAME/c\ORACLE_HOSTNAME={}' \
{}".format(oracle_host_name, GRID_RSP_FILE)
    os.system(cmd)
    cmd = "sed -i '/^oracle.install.crs.config.gpnp.scanName/c\oracle.\
install.crs.config.gpnp.scanName={}' {}".format(scan_name, GRID_RSP_FILE)
    os.system(cmd)
    cmd = "sed -i '/^oracle.install.crs.config.clusterNodes/c\oracle.install.\
crs.config.clusterNodes={}' {}".format(cluster_nodes[:-1], GRID_RSP_FILE)
    os.system(cmd)
    network_string = generate_network_list()
    cmd = "sed -i '/^oracle.install.crs.config.networkInterfaceList/c\oracle.\
install.crs.config.networkInterfaceList={}' {}".format(network_string,
                                                       GRID_RSP_FILE)
    os.system(cmd)
    cmd = "sed -i '/^oracle.install.asm.SYSASMPassword/c\oracle.install.asm.\
SYSASMPassword={}' {}".format(config('asm-sys-password'), GRID_RSP_FILE)
    os.system(cmd)
    cmd = "sed -i '/^oracle.install.asm.monitorPassword/c\oracle.install.asm.\
monitorPassword={}' {}".format(config('asm-snmp-password'), GRID_RSP_FILE)
    os.system(cmd)
    cmd = "sed -i '/^oracle.install.crs.config.clusterName/c\oracle.install.\
crs.config.clusterName={}' {}".format(scan_name, GRID_RSP_FILE)
    os.system(cmd)
    cmd = "sed -i '/^oracle.install.asm.diskGroup.disks=/c\oracle.install.\
asm.diskGroup.disks={}' {}".format(config('asm-disk-group'), GRID_RSP_FILE)
    os.system(cmd)


def generate_network_list():
    data = json.load(open(NODE_DATA_FILE))
    node_pub_ip = []
    node_pri_ip = []
    hostname = socket.gethostname()
    node_pri_ip = data[hostname]['private'].split()[0]
    node_pub_ip = data[hostname]['public'].split()[0]
    cmd = 'netstat -ie | grep -B1 {} | head -n2'.format(node_pub_ip)
    public_string = commands.getoutput(cmd)
    intf_public = public_string.split()[0]
    intf_public = intf_public.split(':')[0]
    mask_public = netifaces.ifaddresses(intf_public)[2][0]['netmask']
    pub_subnet_addr = str(IPNetwork('{}/{}'.format(node_pub_ip,
                                                   mask_public)).cidr)[:-3]

    cmd = 'netstat -ie | grep -B1 {} | head -n2'.format(node_pri_ip)
    private_string = commands.getoutput(cmd)
    intf_private = private_string.split()[0]
    intf_private = intf_private.split(':')[0]
    mask_private = netifaces.ifaddresses(intf_private)[2][0]['netmask']
    pri_subnet_addr = str(IPNetwork('{}/{}'.format(node_pri_ip,
                                                   mask_private)).cidr)[:-3]
    network_string = '{}:{}:1,{}:{}:2'.format(intf_public, pub_subnet_addr,
                                              intf_private, pri_subnet_addr)
    return network_string


def set_persistent_hostname():
    hostname = socket.gethostname()
    hostname = hostname.split('.maas')[0]
    cmd = ("echo {} > '/etc/hostname'".format(hostname))
    os.system(cmd)

    cmd = ("hostnamectl set-hostname {}".format(hostname))
    os.system(cmd)

    cmd = ("echo 'HOSTNAME='{} >> '/etc/sysconfig/network'".format(hostname))
    os.system(cmd)

    cmd = ("echo 'preserve_hostname: true' >> '/etc/cloud/\
cloud.cfg'".format(hostname))
    os.system(cmd)


def copy_oracle_package():
    filename = json.load(open(FILES_PATH))
    if config('slave-units-number'):
        cmd = "cp {} /home/oracle/.".format(filename[config('oracle-version')])
        os.system(cmd)

        cmd = "chown oracle.oinstall /home/oracle/oracle-12c-grid.tar"
        os.system(cmd)

        cmd = ("su - oracle -c 'tar -xvf oracle-12c-grid.tar'")
        os.system(cmd)

        cmd = ("su - oracle -c 'rm -f oracle-12c-grid.tar'")
        os.system(cmd)

    cmd = "cp {} /home/oracle/.".format(filename['oracle-12c-db'])
    os.system(cmd)

    cmd = "chown oracle.oinstall /home/oracle/oracle-12c-db.tar"
    os.system(cmd)

    cmd = ("su - oracle -c 'tar -xvf oracle-12c-db.tar'")
    os.system(cmd)

    cmd = ("su - oracle -c 'rm -f oracle-12c-db.tar'")
    os.system(cmd)


def resize_swap_partition():
    cmd = "swapon -s | tail -n1"
    swap_string = commands.getoutput(cmd)
    if swap_string == '':
        swap_name = ''
    else:
        swap_name = swap_string.split()[0]
    print swap_name
    if swap_name:
        swap_mem = int(swap_string.split()[2])/1024
        print swap_mem
        if swap_mem < 8096:
            act_swap_mem = 8096 - swap_mem
            cmd = "dd if=/dev/zero of=/home/oracle/swapspace bs=1M \
count={}".format(act_swap_mem)
            os.system(cmd)
    else:
        cmd = "dd if=/dev/zero of=/home/oracle/swapspace bs=1M count=8096"
        os.system(cmd)
    cmd = "mkswap /home/oracle/swapspace"
    os.system(cmd)
    cmd = "swapon /home/oracle/swapspace"
    os.system(cmd)
    cmd = "echo '/home/oracle/swapspace  none   swap   sw   0   0' >> /etc/\
fstab"
    os.system(cmd)


def set_ntpd_conf():
    cmd = "sed 's/-g/-x -p \/var\/run\/ntpd.pid/' -i /etc/sysconfig/ntpd"
    os.system(cmd)

    cmd = "systemctl enable ntpd.service"
    os.system(cmd)

    cmd = "sed -i '/^ExecStart=/c\ExecStart=/usr/sbin/ntpd $OPTIONS' /usr/\
lib/systemd/system/ntpd.service"
    os.system(cmd)

    cmd = "systemctl daemon-reload"
    os.system(cmd)

    cmd = 'service ntpd stop'
    os.system(cmd)
    cmd = 'service ntpd start'
    os.system(cmd)


def add_ssh_known_host(public):
    node = public.split()[2]
    cmd = ("su - oracle -c 'ssh-keyscan -H {} >> .ssh/\
known_hosts'".format(node))
    os.system(cmd)
    cmd = ("su - oracle -c 'ssh oracle@{} ls'".format(node))
    os.system(cmd)


def enable_dns_masq():
    cmd = 'cp /etc/resolv.conf /etc/resolv.dnsmasq'
    os.system(cmd)
    cmd = "sed -i '/^ExecStart/ s/$/ -r \/etc\/resolv.dnsmasq/' /usr/lib/\
systemd/system/dnsmasq.service"
    os.system(cmd)

    cmd = "systemctl enable dnsmasq.service"
    os.system(cmd)

    cmd = "systemctl daemon-reload"
    os.system(cmd)

    cmd = 'service dnsmasq stop'
    os.system(cmd)
    cmd = 'service dnsmasq start'
    os.system(cmd)


def set_name_server():
    hostname = socket.gethostname()
    data = json.load(open(NODE_DATA_FILE))
    all_strings = data[hostname]
    if 'nameserver' in all_strings.keys():
        name_server = all_strings['nameserver']
        if name_server:
            cmd = "sed -i '/nameserver/c\\nameserver {}' /etc/\
resolv.conf".format(name_server)
            os.system(cmd)


def set_disk_permission():
    log("Setting the disk owner")
    cmd = "partprobe"
    os.system(cmd)
    time.sleep(10)
    create_udev_rules()
    cmd = "partprobe"
    os.system(cmd)
    time.sleep(10)


def create_oracle_dir():
    cmd = "mkdir /u01"
    os.system(cmd)
    cmd = "chown oracle.oinstall /u01"
    os.system(cmd)


def install_grid():
    logfile = "/home/oracle/log/grid_install"
    if os.path.exists("/home/oracle/log") == 0:
        cmd = ("su - oracle -c 'mkdir log'")
        os.system(cmd)

    install_logs = open(logfile, 'w')
    cmd = "./grid/runInstaller -silent -responseFile {} -showProgress \
-ignorePrereq -waitforcompletion".format(GRID_RSP_FILE)
    subprocess.Popen(['su', '-', 'oracle', '-c', cmd], stdout=install_logs)

    while True:
        if os.system("grep 'FATAL' {}".format(logfile)) == 0:
            log("The grid installation is not successful")
            cmd = commands.getoutput("grep 'A log of this session is \
currently saved as' {}".format(logfile))
            if cmd:
                err_line = cmd.split(':')[1]
                err_log = err_line.split(' ')[1]
                cmd = "cp {} /home/oracle/log/.".format(err_log[:-1])
                os.system(cmd)
            return False
        elif os.system("grep 'As a root user, execute the following \
script(s):' {}".format(logfile)) == 0:
            log("The grid installation is successful")
            return True


def install_db():
    logfile = "/home/oracle/log/db_install"
    if os.path.exists("/home/oracle/log") == 0:
        cmd = ("su - oracle -c 'mkdir log'")
        os.system(cmd)

    install_logs = open(logfile, 'w')
    cmd = "./database/runInstaller -silent -responseFile {} -showProgress \
-ignorePrereq -waitforcompletion".format(DB_RSP_FILE)
    subprocess.Popen(['su', '-', 'oracle', '-c', cmd], stdout=install_logs)

    while True:
        if os.system("grep 'FATAL' {}".format(logfile)) == 0:
            log("The DB installation is not successful")
            cmd = commands.getoutput("grep 'A log of this session is \
currently saved as' {}".format(logfile))
            if cmd:
                err_line = cmd.split(':')[1]
                err_log = err_line.split(' ')[1]
                cmd = "cp {} /home/oracle/log/.".format(err_log[:-1])
                os.system(cmd)
            return False
        elif os.system("grep 'As a root user, execute the following \
script(s):' {}".format(logfile)) == 0:
            log("The DB installation is successful")
            return True


def install_root_scripts():
    hostname = socket.gethostname()

    cmd = "/u01/app/oraInventory/orainstRoot.sh"
    os.system(cmd)

    cmd = "/u01/app/12.1.0.2/grid/root.sh"
    os.system(cmd)
    change_cluster_state(hostname, "clustered")


def change_cluster_state(hostname, state):
    all_strings = {}
    data = {}
    if os.path.exists(NODE_CLUSTER_FILE):
        data = json.load(open(NODE_CLUSTER_FILE))
        if hostname in data.keys():
            all_strings = data[hostname]
    all_strings['identity'] = hostname
    all_strings['state'] = state
    data[hostname] = all_strings
    json.dump(data, open(NODE_CLUSTER_FILE, 'w'))


def send_notification(relation, state):
    juju_log('Sending notification')

    hostname = socket.gethostname()
    for rid in relation_ids(relation):
        relation_info = {
            'identity': hostname,
            'state': state
        }
        relation_set(rid, relation_settings=relation_info)


def check_all_clustered_nodes(state):
    if os.path.exists(NODE_CLUSTER_FILE) == 0:
        return False
    data = json.load(open(NODE_CLUSTER_FILE))
    count = 0
    for key, node in data.items():
        if node['state'] == state:
            count = count + 1

    if len(data) == config("slave-units-number") + 1 and len(data) == count:
        return True
    else:
        return False


def check_node_state():
    if os.path.exists(NODE_CLUSTER_FILE) == 0:
        return None
    hostname = socket.gethostname()
    data = json.load(open(NODE_CLUSTER_FILE))
    if 'state' in data[hostname].keys():
        return data[hostname]['state']
    else:
        return None


def process_clustered_data():
    identity = ""

    for rid in relation_ids('master-state'):
        for unit in related_units(rid):
            identity = relation_get(attribute='identity\
', unit=unit, rid=rid)
            state = relation_get(attribute='state\
', unit=unit, rid=rid)

            juju_log('Relation confirmed from {}'.format(identity))

            if identity:
                change_cluster_state(identity, state)


def modify_oracle_db_response_file():
    hostname = socket.gethostname()
    if config('slave-units-number'):
        data = json.load(open(NODE_DATA_FILE))
        node_string = []
        for node, value in data.items():
            public = value['public']
            node_public = public.split()[2]
            node_string.append("{},".format(node_public))

        cluster_nodes = ''.join(node_string)
        oracle_host_name = data[hostname]['public'].split()[1]
        cmd = "sed -i '/^ORACLE_HOSTNAME/c\ORACLE_HOSTNAME={}' \
{}".format(oracle_host_name, DB_RSP_FILE)
        os.system(cmd)
        cmd = "sed -i '/^oracle.install.db.CLUSTER_NODES/c\oracle.install.db.\
CLUSTER_NODES={}' {}".format(cluster_nodes[:-1], DB_RSP_FILE)
        os.system(cmd)
    else:
        cmd = "sed -i '/^ORACLE_HOSTNAME/c\ORACLE_HOSTNAME={}' \
{}".format(hostname, DB_RSP_FILE)
        os.system(cmd)
        cmd = "sed -i '/^oracle.install.db.CLUSTER_NODES/c\oracle.install.db.\
CLUSTER_NODES={}' {}".format("", DB_RSP_FILE)
        os.system(cmd)


def install_db_root_scripts():
    hostname = socket.gethostname()
    cmd = "/u01/app/oracle/product/12.1.0.2/db_1/root.sh"
    os.system(cmd)
    change_cluster_state(hostname, "final")


def create_partition():
    disk_string = config('asm-disk-group')
    asm_disk = disk_string.split(',')
    for disk in asm_disk:
        juju_log("Checking disk partition for  {}".format(disk))
        if os.path.exists(disk):
            juju_log("Found partition {}, so wipe the partition".format(disk))
        else:
            juju_log("Creating disk partition {}".format(disk))
            cmd = "echo -e 'o\nn\np\n1\n\n\nw' | fdisk {}".format(disk[:-1])
            os.system(cmd)
        cmd = "fdisk -l {} | tail -n1".format(disk[:-1])
        disk_file = commands.getoutput(cmd)
        count = disk_file.split()[3]
        if count[len(count)-1] == '+':
            count = count[:-1]
        count = int(count)/1024
        cmd = "dd if=/dev/zero of={} bs=1M count={}".format(disk, count)
        os.system(cmd)


def pre_install():
    if config('manage-partition'):
        create_partition()
    set_disk_permission()
    download_cplane_packages()
    copy_oracle_package()
    enable_dns_masq()
    nameserver = unit_get('private-address')
    save_name_server(nameserver)
    set_name_server()


def create_db():
    import re
    if config('slave-units-number'):
        data = OrderedDict()
        data = json.load(open(NODE_DATA_FILE))
        nodes_string = []
        for node, value in data.items():
            nodes_string.append("{},".format(node))
        nodes = ''.join(nodes_string)
    path = '/home/oracle/database/response/db_install.rsp'
    if os.path.exists(path):
        with open('{}'.format(path), 'r') as f:
            for line in f:
                if re.match("ORACLE_HOME", line):
                    break
    ORACLE_PATH = '{}'.format(line.split('=')[1])
#   cmd = "export ORACLE_HOME = {}".format(ORACLE_PATH)
#   os.system(cmd)
    oracle_bin = "{}/bin/".format(ORACLE_PATH.split('\n')[0])
    if config('slave-units-number'):
        cmd = "su - oracle -c '{}dbca -silent -createDatabase -templateName \
General_Purpose.dbc -gdbName {} -adminManaged -sysPassword {} \
-systemPassword {} -emConfiguration NONE -storageType ASM -diskGroupName DATA \
-nodelist {} -totalMemory 2400'".format(oracle_bin, config('db-service'),
                                        config('db-password'),
                                        config('db-password'),
                                        nodes[:-1])
        os.system(cmd)
    else:
        cmd = "su - oracle -c '{}dbca -silent -createDatabase -templateName \
General_Purpose.dbc -gdbName {} -adminManaged -sysPassword {} \
-systemPassword {} -emConfiguration NONE \
-totalMemory 2400'".format(oracle_bin, config('db-service'),
                           config('db-password'),
                           config('db-password'))
        os.system(cmd)
        cmd = "su - oracle -c '{}netca -silent -responseFile \
/home/oracle/database/response/netca.rsp'".format(oracle_bin)
        os.system(cmd)


def get_scan_str():
    hostname = socket.gethostname()
    data = OrderedDict()
    data = json.load(open(NODE_DATA_FILE))
    all_strings = data[hostname]
    return all_strings['scan']


def set_oracle_env():
    cmd = "echo '#!/bin/bash' >> /etc/profile.d/oracle_env.sh"
    os.system(cmd)

    if config('slave-units-number'):
        cmd = "echo 'export ORACLE_HOME=/u01/app/12.1.0.2/grid' >> /etc/profile.d/\
oracle_env.sh"
        os.system(cmd)
    else:
        cmd = "echo 'export ORACLE_HOME=/u01/app/oracle/product/12.1.0.2/db_1' >> \
/etc/profile.d/oracle_env.sh"
        os.system(cmd)

    cmd = "echo 'export PATH=$PATH:$ORACLE_HOME/bin' >> /etc/profile.d/\
oracle_env.sh"
    os.system(cmd)
    if config('slave-units-number'):
        cmd = "echo 'export ORACLE_SID=+ASM1' >> /etc/profile.d/oracle_env.sh"
        os.system(cmd)
    else:
        cmd = "echo 'export ORACLE_SID=CPLANE' >> /etc/profile.d/oracle_env.sh"
        os.system(cmd)
    cmd = "chown oracle.oinstall /etc/profile.d/oracle_env.sh"
    os.system(cmd)
    cmd = "chmod +x /etc/profile.d/oracle_env.sh"
    os.system(cmd)


def create_udev_rules():
    disk_string = config("asm-disk-group")
    cmd = "echo 'options=-g' >> '/etc/scsi_id.config'"
    os.system(cmd)
    rule_path = '/lib/udev/rules.d/99-systemd.rules'
    disk_uuid = []
    for disk in disk_string.split(','):
        cmd = "/lib/udev/scsi_id -g -u -d {}".format(disk)
        disk_uuid.append(commands.getoutput(cmd))

    for idx in disk_uuid:
        rule_string = 'KERNEL=="sd?1", SUBSYSTEM=="block", PROGRAM=="/lib/\
udev/scsi_id -g -u -d /dev/$parent", RESULT=="{}", OWNER="oracle", GROUP=\
"oinstall", MODE="0660"'.format(idx)
        cmd = "sed -i '/LABEL=/i{}' {}".format(rule_string, rule_path)
        os.system(cmd)


def get_db_status():
    cmd = "su - oracle -c 'lsnrctl status'"
    res = commands.getoutput(cmd)
    juju_log('lsnrctl status:  {}'.format(res))
    if config('db-service') in res:
        return True
    else:
        return False


def execute_sql_command(connect_string, sql_command):
    session = subprocess.Popen("su - oracle  -c 'sqlplus -S {}'".format(
                               connect_string), shell=True, stdin=PIPE,
                               stdout=PIPE, stderr=PIPE)
    session.stdin.write(sql_command)
    log('{}'.format(session.communicate()))


def configure_database():
    log('Configuring the Database')
    host = None

    if config('slave-units-number'):
        host = config('scan-name') + '-scan/'
    else:
        host = socket.gethostname()

    connect_string = 'sys/' + config('db-password') + '@' \
        + host + config('db-service') + ' as' + ' sysdba'
    execute_sql_command(connect_string, "alter system set \
processes={} scope=spfile;".format(config('rac-db-process')))
    execute_sql_command(connect_string, "alter system set \
session_cached_cursors={} scope=spfile;".format(config('rac-db-ses-cach-cur')))
    execute_sql_command(connect_string, "alter system set \
session_max_open_files={} scope=spfile;".format(
                        config('rac-db-ses-max-op-file')))
    execute_sql_command(connect_string, "alter system set \
sessions={} scope=spfile;".format(config('rac-db-session')))
    os.system("su - oracle -c 'srvctl stop database -d {}'".format(
              config('db-service')))
    os.system("su - oracle -c 'srvctl start database -d {}'".format(
              config('db-service')))
