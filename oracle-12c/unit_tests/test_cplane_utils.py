#!/usr/bin/python
from test_utils import CharmTestCase, unittest

from mock import MagicMock, patch, call
import charmhelpers.contrib.openstack.templating as templating
from charmhelpers.core import hookenv
hookenv.config = MagicMock()
import cplane_utils
import socket
import commands
from collections import OrderedDict
import json
import os


templating.OSConfigRenderer = MagicMock()

from cplane_package_manager import(
    CPlanePackageManager
)


TO_PATCH = [
    'config',
    'log',
    'open',
    'unit_get',
    'unit_private_ip',
    'local_unit',
    'get_ip',
]


cplane_install_package = OrderedDict([
    ('oracle-12c', '0'),
])

NODE_DATA_FILE = 'node_data'
GRID_RSP_FILE = 'grid.rsp'
FILENAME = 'filename'


class CplaneUtilsTest(CharmTestCase):

    data = {}

    def setUp(self):
        super(CplaneUtilsTest, self).setUp(cplane_utils, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.unit_get.return_value = '127.0.0.1'
        self.unit_private_ip.return_value = '127.0.0.1'
        self.local_unit.return_value = 'test/0'
        self.get_ip.return_value = '127.0.0.1'
        data = OrderedDict()
        all_string = {}
        hostname = socket.gethostname()
        all_string["public"] = 'unit_test'
        all_string["private"] = 'unit_test'
        all_string["scan"] = 'unit_test'
        data[hostname] = all_string
        json.dump(data, open(NODE_DATA_FILE, 'w'))
        self.data = data

    def tearDown(self):
        super(CplaneUtilsTest, self).tearDown()
        if os.path.exists(NODE_DATA_FILE):
            cmd = "rm {}".format(NODE_DATA_FILE)
            os.system(cmd)

    def test_determine_packages(self):
        self.assertEqual(cplane_utils.determine_packages(),
                         ['ntp', 'dnsmasq', 'binutils', 'compat-libcap1',
                          'compat-libstdc++-33', 'compat-libstdc++-33.i686',
                          'gcc', 'gcc-c++', 'glibc', 'glibc.i686', 'glibc-\
devel', 'glibc-devel.i686', 'ksh', 'libgcc', 'libgcc.i686', 'libstdc++', '\
libstdc++.i686', 'libstdc++-devel', 'libstdc++-devel.i686', 'libaio', 'libaio.\
i686', 'libaio-devel', 'libaio-devel.i686', 'libXext', 'libXext.i686', '\
libXtst', 'libXtst.i686', 'libX11', 'libX11.i686', 'libXau', 'libXau.i686', '\
libxcb', 'libxcb.i686', 'libXi', 'libXi.i686', 'make', 'sysstat', '\
unixODBC', 'unixODBC-devel'])

    @patch.object(cplane_utils.CPlanePackageManager, "_create_log")
    @patch.object(cplane_utils.CPlanePackageManager, "_get_pkg_json")
    @patch.object(CPlanePackageManager, "download_package")
    @patch("json.dump")
    def test_download_cplane_packages(self, m_json_dump, m_download_package,
                                      m_get_pkg_json, m_create_log):
        cplane_utils.CPLANE_URL = 'https://www.dropbox.com/s/h2edle1o0jj1btt/\
cplane_metadata.json?dl=1'
        cplane_utils.cplane_packages = cplane_install_package
        cplane_utils.download_cplane_packages()
        m_download_package.assert_called_with('oracle-12c', '0')

    @patch("subprocess.check_call")
    def test_group_add(self, m_check_call):
        cplane_utils.group_add()
        calls = [call(['groupadd', '-g', '54321', 'oinstall']),
                 call(['groupadd', '-g', '54322', 'dba']),
                 call(['groupadd', '-g', '54323', 'oper'])]
        m_check_call.assert_has_calls(calls)

    @patch("subprocess.check_call")
    def test_user_add(self, m_check_call):
        cplane_utils.user_add()
        m_check_call.assert_called_with(['useradd', '-u', '54321', '-g',
                                         'oinstall', '-G', 'dba,oper',
                                         'oracle'])

    @patch("subprocess.check_call")
    @patch("os.system")
    def test_disable_firewall(self, m_system, m_check_call):
        cplane_utils.disable_firewall()
        m_check_call.assert_called_with(['setenforce', '0'])
        m_system.assert_called_with("sed -i 's/enforcing/disabled/g' /etc/\
selinux/config /etc/selinux/config")

    @patch("os.system")
    def test_set_kernel_parameters(self, m_system):
        cplane_utils.set_kernel_parameters()
        cplane_utils.limit_conf = "/etc/security/limits.conf"
        m_system("sysctl -p")

    @patch("json.dump")
    @patch("json.load")
    def test_generate_host_string(self, m_json_load, m_json_dump):
        cplane_utils.generate_host_string('private')

    @patch("os.system")
    @patch("json.dump")
    @patch("commands.getoutput")
    @patch("json.load")
    def test_generate_pub_ssh_key(self, m_json_load, m_getoutput,
                                  m_json_dump, m_system):
        key = 'unit test'
        data = json.load(open(NODE_DATA_FILE))
        m_getoutput.return_value = key
        cplane_utils.NODE_DATA_FILE = NODE_DATA_FILE
        m_json_load.return_value = data
        cplane_utils.generate_pub_ssh_key()
        m_system.assert_called_with("su - oracle -c 'ssh-keygen -\
t rsa -N \"\" -f ~/.ssh/id_rsa'")
        m_getoutput.assert_called_with("echo {} | sed 's/\r//'".format(key))

    @patch("os.system")
    def test_flush_host(self, m_system):
        host_file = "/etc/hosts"
        cplane_utils.flush_host()
        m_system.assert_has_calls([call("sed -i '/#Added by cplane/q' \
{}".format(host_file)), call("echo '\n# Private' >> /etc/hosts"), call("echo \
'\n# Public' >> /etc/hosts"), call("echo '\n# Virtual' >> /etc/hosts"), call("\
echo '\n# SCAN' >> /etc/hosts")])

    @patch.object(cplane_utils.os.path, "exists")
    @patch("os.system")
    @patch("subprocess.check_call")
    def test_config_ssh_key(self, m_check_call, m_system, m_os_path_exists):
        path = '/home/oracle/.ssh'
        m_os_path_exists.return_value = False
        cplane_utils.config_ssh_key('value')
        m_system.assert_called_with("mkdir {}".format(path))
        m_check_call.assert_has_calls([call(['chmod', '-R', '700', path]),
                                      call(['chown', '-R', 'oracle.oinstall',
                                           path])], any_order=True)

    def test_append_scan_ip(self):
        self.test_config.set('scan-name', '127.0.0.1')
        cplane_utils.append_scan_ip()

    @patch("cplane_utils.create_partition")
    @patch("cplane_utils.set_disk_permission")
    @patch("cplane_utils.download_cplane_packages")
    @patch("cplane_utils.copy_oracle_package")
    @patch("cplane_utils.enable_dns_masq")
    @patch("cplane_utils.save_name_server")
    @patch("cplane_utils.set_name_server")
    def test_pre_install(self, m_set_name_server, m_save_name_server,
                         m_enable_dns_masq, m_copy_oracle_package,
                         m_download_cplane_packages, m_set_disk_permission,
                         m_create_partition):
        self.test_config.set('manage-partition', 'true')
        cplane_utils.pre_install()
        m_create_partition.assert_called_with()
        m_set_disk_permission.assert_called_with()
        m_download_cplane_packages.assert_called_with()
        m_copy_oracle_package.assert_called_with()
        m_enable_dns_masq.assert_called_with()
        m_save_name_server.assert_called_with('127.0.0.1')
        m_set_name_server.assert_called_with()

    @patch("os.system")
    @patch("cplane_utils.generate_network_list")
    @patch("json.load")
    def test_modify_oracle_grid_response_file(self, m_json_load,
                                              m_generate_network_list,
                                              m_system):
        hostname = socket.gethostname()
        scan_str = []
        scan_str.append("Scan1 ip for {}".format(hostname))
        scan_str.append("Scan2 ip for {}".format(hostname))
        scan_str.append("Scan3 ip for {}".format(hostname))

        data = self.data
        data[hostname]['public'] = "unit test for {}".format(hostname)
        data[hostname]['scan'] = scan_str
        data[hostname]['vip'] = "unit test for {}".format(hostname)
        cplane_utils.NODE_DATA_FILE = NODE_DATA_FILE
        cplane_utils.GRID_RSP_FILE = GRID_RSP_FILE
        m_json_load.return_value = data
        oracle_host_name = data[hostname]['public'].split()[1]
        scan_name = data[hostname]['scan'][0].split()[2]

        m_generate_network_list.return_value = "eth0:127.0.0.1"
        self.test_config.set('asm-sys-password', 'Cplane01')
        self.test_config.set('asm-snmp-password', 'Cplane01')
        self.test_config.set('asm-disk-group', '/dev/sdb1,/dev/sdc1,/dev/sdd1')
        cplane_utils.modify_oracle_grid_response_file()
        m_system.assert_has_calls([call("sed -i '/^ORACLE_HOSTNAME/c\ORACLE_\
HOSTNAME={}' {}".format(oracle_host_name, GRID_RSP_FILE)), call("sed -i '/\
^oracle.install.crs.config.gpnp.scanName/c\oracle.install.crs.config.gpnp.\
scanName={}' {}".format(scan_name, GRID_RSP_FILE)), call("sed -i '/^oracle.\
install.asm.SYSASMPassword/c\oracle.install.asm.SYSASMPassword=Cplane01' \
{}".format(GRID_RSP_FILE)), call("sed -i '/^oracle.install.asm.\
monitorPassword/c\oracle.install.asm.monitorPassword=Cplane01' \
{}".format(GRID_RSP_FILE)), call("sed -i '/^oracle.install.crs.\
config.clusterName/c\oracle.install.crs.config.clusterName=\
{}' {}".format(scan_name, GRID_RSP_FILE)), call("sed -i '/^oracle.\
install.asm.diskGroup.disks=/c\oracle.install.asm.diskGroup.disks=/dev/sdb1,\
/dev/sdc1,/dev/sdd1' {}".format(GRID_RSP_FILE))], any_order=True)

    @patch("os.system")
    def test_set_persistent_hostname(self, m_system):
        hostname = socket.gethostname()
        hostname = hostname.split('.maas')[0]
        cplane_utils.set_persistent_hostname()
        calls = [call("echo {} > '/etc/hostname'".format(hostname)),
                 call("hostnamectl set-hostname {}".format(hostname)),
                 call("echo 'HOSTNAME='{} >> '/etc/sysconfig/\
network'".format(hostname)),
                 call("echo 'preserve_hostname: true' >> '/etc/\
cloud/cloud.cfg'".format(hostname))]
        m_system.assert_has_calls(calls, any_order=True)

    @patch("json.load")
    @patch("os.system")
    def test_copy_oracle_package(self, m_system, m_json_load):
        filename = OrderedDict()
        filename['oracle-12c'] = 'test'
        filename['oracle-12c-db'] = 'test'
        m_json_load.return_value = filename
        cplane_utils.copy_oracle_package()
        calls = [call("cp test /home/oracle/."),
                 call("chown oracle.oinstall /home/oracle/\
oracle-12c-grid.tar"),
                 call("su - oracle -c 'tar -xvf oracle-12c-grid.tar'"),
                 call("cp {} /home/oracle/.".format(filename['oracle-\
12c-db'])),
                 call("chown oracle.oinstall /home/oracle/oracle-12c-db.tar"),
                 call("su - oracle -c 'tar -xvf oracle-12c-db.tar'")]
        m_system.assert_has_calls(calls, any_order=True)

    @patch("os.system")
    @patch("string.split")
    def test_resize_swap_partition_withfile(self, m_split, m_system):
        cmd = "swapon -s | tail -n1"
        swap_string = commands.getoutput(cmd)
        swap_name = swap_string.split()[0]
        if swap_name:
            swap_mem = int(swap_string.split()[2])/1024
            if swap_mem < 8096:
                act_swap_mem = 8096 - swap_mem
        cplane_utils.resize_swap_partition()
        calls = [call("dd if=/dev/zero of=/home/oracle/\
swapspace bs=1M count={}".format(act_swap_mem)),
                 call("mkswap /home/oracle/swapspace"),
                 call("swapon /home/oracle/swapspace"),
                 call("echo '/home/oracle/swapspace  none   swap   \
sw   0   0' >> /etc/fstab")]
        m_system.assert_has_calls(calls, any_order=True)

    @patch("commands.getoutput")
    @patch("os.system")
    @patch("string.split")
    def test_resize_swap_partition_without_file(self, m_split,
                                                m_system, m_getoutput):
        m_split.return_value = False
        cplane_utils.resize_swap_partition()
        calls = [call("dd if=/dev/zero of=/home/oracle/\
swapspace bs=1M count=8096"),
                 call("mkswap /home/oracle/swapspace"),
                 call("swapon /home/oracle/swapspace"),
                 call("echo '/home/oracle/swapspace  none   swap   \
sw   0   0' >> /etc/fstab")]
        m_system.assert_has_calls(calls, any_order=True)

    @patch("os.system")
    def test_set_ntpd_conf(self, m_system):
        cplane_utils.set_ntpd_conf()
        calls = [call("sed 's/-g/-x -p \/var\/run\/ntpd.pid/\
' -i /etc/sysconfig/ntpd"),
                 call("systemctl enable ntpd.service"),
                 call("sed -i '/^ExecStart=/c\ExecStart=/usr/sbin/\
ntpd $OPTIONS' /usr/lib/systemd/system/ntpd.service"),
                 call("systemctl daemon-reload"),
                 call('service ntpd stop'), call('service ntpd start')]
        m_system.assert_has_calls(calls, any_order=True)

    @patch("os.system")
    def test_enable_dns_masq(self, m_system):
        cplane_utils.enable_dns_masq()
        calls = [call('cp /etc/resolv.conf /etc/resolv.dnsmasq'),
                 call("sed -i '/^ExecStart/ s/$/ -r \/etc\/resolv.dnsmasq/\
' /usr/lib/systemd/system/dnsmasq.service"),
                 call("systemctl enable dnsmasq.service"),
                 call("systemctl daemon-reload"),
                 call('service dnsmasq stop'),
                 call('service dnsmasq start')]
        m_system.assert_has_calls(calls, any_order=True)

    @patch("os.system")
    def test_set_disk_permission(self, m_system):
        cplane_utils.set_disk_permission()
        m_system.assert_called_with("partprobe")

    @patch("os.system")
    def test_create_oracle_dir(self, m_system):
        cplane_utils.create_oracle_dir()
        m_system.assert_has_calls([call("mkdir /u01"),
                                  call("chown oracle.oinstall /u01")],
                                  any_order=True)

    @patch("os.system")
    @patch("cplane_utils.change_cluster_state")
    def test_install_root_scripts(self, m_change_cluster_state, m_system):
        hostname = socket.gethostname()
        cplane_utils.install_root_scripts()
        m_change_cluster_state.assert_called_with(hostname, "clustered")
        m_system.assert_has_calls([call("/u01/app/oraInventory/\
orainstRoot.sh"),
                                  call("/u01/app/12.1.0.2/grid/root.sh")],
                                  any_order=True)

    @patch("os.system")
    @patch("cplane_utils.change_cluster_state")
    def test_install_db_root_scripts(self, m_change_cluster_state, m_system):
        hostname = socket.gethostname()
        cplane_utils.install_db_root_scripts()
        m_change_cluster_state.assert_called_with(hostname, "final")
        m_system.assert_called_with("/u01/app/oracle/product/12.1.0.2/\
db_1/root.sh")

suite = unittest.TestLoader().loadTestsFromTestCase(CplaneUtilsTest)
unittest.TextTestRunner(verbosity=2).run(suite)
