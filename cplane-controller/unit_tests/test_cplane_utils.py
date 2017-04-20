#!/usr/bin/python
from test_utils import CharmTestCase, unittest

from mock import MagicMock, patch, call
import charmhelpers.contrib.openstack.templating as templating
from charmhelpers.core import hookenv
hookenv.config = MagicMock()
import cplane_utils
import commands
from collections import OrderedDict

templating.OSConfigRenderer = MagicMock()

TO_PATCH = [
    'apt_install',
    'config',
    'open',
    'log',
    'unit_get',
    'network_get_primary_address',
    'ni',
]

cplane_install_package = OrderedDict([
    ('dvnd', '0')
])

CPLANE_URL = 'http://192.168.7.113/cplane_metadata.json'


class CplaneUtilsTest(CharmTestCase):
    def setUp(self):
        super(CplaneUtilsTest, self).setUp(cplane_utils, TO_PATCH)
        self.config.side_effect = self.test_config.get

    def tearDown(self):
        super(CplaneUtilsTest, self).tearDown()

    def test_determine_packages(self):
        self.assertEqual(cplane_utils.determine_packages(),
                         ['alien', 'libaio1', 'zlib1g-dev', 'libxml2-dev',
                          'libxml-libxml-perl', 'unzip', 'python-pexpect',
                          'libyaml-perl'])

    @patch("subprocess.check_call")
    def test_prepare_env(self, m_check_call):
        cplane_utils.JBOSS_DIR = '.'
        cplane_utils.prepare_env()
        m_check_call.assert_called_with(['ln', '-sf', '/etc/init.d', '/etc/\
rc.d/init.d'])

    @patch.object(cplane_utils.os.path, "exists")
    @patch("subprocess.check_call")
    def test_prepare_env_jboss_not_exist(self, m_check_call, m_os_path_exists):
        cplane_utils.JBOSS_DIR = '/opt/jboss'
        m_os_path_exists.return_value = False
        cplane_utils.prepare_env()
        m_check_call.assert_has_calls(
            [call(['ln', '-sf', '/usr/bin/awk', '/bin/awk']),
             call(['mkdir', '/var/lock/subsys']),
             call(['chmod', '-R', '777', '/var/lock/subsys']),
             call(['mkdir', '/opt/jboss']),
             call(['mkdir', '/etc/rc.d']),
             call(['ln', '-sf', '/etc/init.d', '/etc/rc.d/init.d'])],
            any_order=True)

    @patch("commands.getoutput")
    def test_get_upgrade_type(self, m_getoutput):
        cplane_utils.get_upgrade_type()
        m_getoutput.assert_called_with("cat $CHARM_DIR/config/upgrade-config \
| awk '{ print $2}'")

    @patch.object(cplane_utils.CPlanePackageManager, "_create_log")
    @patch.object(cplane_utils.CPlanePackageManager, "_get_pkg_json")
    @patch.object(cplane_utils.CPlanePackageManager, "download_package")
    @patch("json.dump")
    def test_download_cplane_packages(self, m_json_dump, m_download_package,
                                      m_get_pkg_json, m_create_log):
        cplane_utils.CPLANE_URL = CPLANE_URL
        cplane_utils.cplane_packages = cplane_install_package
        cplane_utils.download_cplane_packages()
        m_download_package.assert_called_with('dvnd', '0')

    @patch.object(cplane_utils.CPlanePackageManager, "_create_log")
    @patch.object(cplane_utils.CPlanePackageManager, "_get_pkg_json")
    @patch.object(cplane_utils.CPlanePackageManager, "download_package")
    @patch("json.load")
    @patch("json.dump")
    def test_download_cplane_installer(self, m_json_dump, m_json_load,
                                       m_download_package, m_get_pkg_json,
                                       m_create_log):
        cplane_utils.CPLANE_URL = CPLANE_URL
        cplane_utils.cplane_packages = cplane_install_package
        self.test_config.set('controller-app-mode', 'dvnd')
        cplane_utils.download_cplane_installer()
        m_download_package.assert_called_with('dvnd', '0')

    @patch('pexpect.spawn')
    def test_oracle_configure_init(self, m_spawn):
        cplane_utils.oracle_configure_init()
        m_spawn.assert_called_with('/etc/init.d/oracle-xe configure',
                                   timeout=300)

    @patch("subprocess.check_call")
    @patch("os.system")
    @patch("json.load")
    def test_install_jboss(self, m_json_load, m_system, m_check_call):
        commands.getoutput("echo test > test.txt")
        cplane_utils.JBOSS_DIR = '.'
        data = {'jboss': 'test.txt'}
        m_json_load.return_value = data
        cplane_utils.JBOSS_DIR = '.'
        cplane_utils.install_jboss()
        m_check_call.assert_called_with(['unzip', '-o', 'test.txt'])
        m_system.assert_called_with('export JBOSS_HOME=/opt/jboss/\
jboss-6.1.0.Final')
        commands.getoutput("rm -f  test.txt")

    @patch("subprocess.check_call")
    @patch('json.load')
    def test_deb_convert_install(self, m_json_load, m_check_call):
        cplane_utils.CHARM_LIB_DIR = '.'
        data = {'jboss': 'test.txt'}
        m_json_load.return_value = data
        cplane_utils.deb_convert_install('jboss')
        m_check_call.assert_called_with(['alien', '--scripts', '-d',
                                        '-i', 'test.txt'])

    @patch("subprocess.check_call")
    @patch("cplane_utils.deb_convert_install")
    @patch("os.system")
    @patch("commands.getoutput")
    def test_install_jdk(self, m_getoutput, m_system, m_deb_convert_install,
                         m_check_call):
        m_getoutput.return_value = "/opt/jdk"
        cplane_utils.install_jdk()
        m_getoutput.assert_called_with('echo $(dirname $(dirname $(readlink\
 -f $(which javac))))')
        m_deb_convert_install.assert_called_with('jdk')
        m_system.assert_called_with('export JAVA_HOME=/opt/jdk')

    @patch("cplane_utils.deb_convert_install")
    def test_install_oracle(self, m_deb_convert_install):
        cplane_utils.install_oracle()
        m_deb_convert_install.assert_called_with('oracle-xe')

    @patch("subprocess.check_call")
    @patch("cplane_utils.set_oracle_env")
    @patch("os.chdir")
    @patch("os.system")
    @patch("cplane_utils.oracle_configure_init")
    def test_configure_oracle(self, m_oracle_configure_init, m_system,
                              m_chdir, m_set_oracle_env, m_check_call):
        cplane_utils.configure_oracle()
        m_check_call.assert_called_with(['chmod', '+x', 'oracle-xe'])

    @patch("subprocess.Popen")
    def test_execute_sql_command(self, m_Popen):
        cplane_utils.execute_sql_command("systes/password@XE", "ls")
        m_Popen.assert_called_with(['sqlplus', '-S',
                                   'systes/password@XE'], stderr=-1,
                                   stdin=-1, stdout=-1)

    @patch("cplane_utils.execute_sql_command")
    @patch("os.system")
    @patch("cplane_utils.set_oracle_host")
    def test_prepare_database(self, m_set_oracle_host, m_system,
                              m_execute_sql_command):
        cplane_utils.DB_DIR = '.'
        cplane_utils.prepare_database()
        m_set_oracle_host.assert_called_with()
        m_system.assert_called_with('sh install.sh admin/admin@localhost/\
 2>&1 | tee install.log')
        m_execute_sql_command.assert_called_with('admin/admin@localhost/',
                                                 '@install_plsql')
        m_system.assert_called_with('sh install.sh admin/admin@{}/ 2>&1 \
| tee install.log'.format(cplane_utils.ORACLE_HOST))
        m_execute_sql_command.assert_called_with('admin/admin@{}/\
'.format(cplane_utils.ORACLE_HOST), '@install_plsql')

    @patch("subprocess.check_call")
    @patch("cplane_utils.load_config")
    @patch("cplane_utils.prepare_database")
    @patch("os.chdir")
    @patch("json.load")
    @patch("json.dump")
    @patch("cplane_utils.set_oracle_host")
    @patch("cplane_utils.set_config")
    def test_cplane_installer_install(self, m_set_config, m_set_oracle_host,
                                      m_json_dump, m_json_load, m_chdir,
                                      m_prepare_database, m_load_config,
                                      m_check_call):
        cplane_utils.cplane_installer()
        m_set_oracle_host.assert_called_with()
        m_check_call.assert_called_with(['sh', 'cpinstaller',
                                        'cplane-dvnd-config.yaml'])

    @patch("subprocess.check_call")
    @patch("cplane_utils.load_config")
    @patch("cplane_utils.prepare_database")
    @patch("os.chdir")
    @patch("json.load")
    @patch("json.dump")
    @patch("cplane_utils.set_oracle_host")
    @patch("cplane_utils.set_config")
    def test_cplane_installer_upgrade(self, m_set_config, m_set_oracle_host,
                                      m_json_dump, m_json_load, m_chdir,
                                      m_prepare_database, m_load_config,
                                      m_check_call):
        cplane_utils.cplane_installer()
        m_set_oracle_host.assert_called_with()
        m_check_call.assert_called_with(['sh', 'cpinstaller',
                                        'cplane-dvnd-config.yaml'])

    @patch("os.system")
    @patch("commands.getoutput")
    def test_start_jboss_service(self, m_getoutput, m_system):
        m_getoutput.return_value = "JBoss server is running!"
        cplane_utils.start_jboss_service()
        m_system.assert_called_with('bash startJBossServer.sh')
        m_getoutput.assert_called_with('bash checkJBossServer.sh')

    @patch('pexpect.spawn')
    def test_initialize_programs(self, m_spawn):
        cplane_utils.initialize_programs('I')
        m_spawn.assert_called_with('bash startInitializePrograms.sh',
                                   timeout=1500)

    @patch("os.chdir")
    @patch("os.system")
    def test_stop_jboss_service(self, m_system, m_chdir):
        cplane_utils.CPLANE_DIR = '.'
        cplane_utils.stop_jboss_service()
        m_system.assert_called_with('bash stopJBossServer.sh')

    @patch("os.chdir")
    @patch("subprocess.check_call")
    @patch("cplane_utils.start_jboss_service")
    @patch("cplane_utils.initialize_programs")
    def test_start_services_reuse_db(self, m_initialize_program,
                                     m_start_jboss_service, m_check_call,
                                     m_chdir):
        m_start_jboss_service.return_value = True
        cplane_utils.start_services('reuse-db')
        m_start_jboss_service.assert_called_with()
        m_initialize_program.assert_called_with('P')
        m_check_call.assert_called_with(['bash', 'startStartupPrograms.sh'])

    @patch("os.chdir")
    @patch("subprocess.check_call")
    @patch("cplane_utils.start_jboss_service")
    @patch("cplane_utils.initialize_programs")
    def test_start_services_clean_db(self, m_initialize_program,
                                     m_start_jboss_service, m_check_call,
                                     m_chdir):
        m_start_jboss_service.return_value = True
        cplane_utils.start_services('clean-db')
        m_start_jboss_service.assert_called_with()
        m_initialize_program.assert_called_with('I')
        m_check_call.assert_called_with(['bash', 'startStartupPrograms.sh'])

    @patch("os.system")
    def test_set_config(self, m_system):
        cplane_utils.set_config('test', 'test', 'test.txt')
        m_system.assert_called_with("sed -ie 's/test:.*/test: test/\
g' .PKG/test.txt")

    @patch("cplane_utils.set_config")
    def test_load_config_default_jbooss_cluster(self, m_set_config):
        self.test_config.set('use-default-jboss-cluster', 'y')
        cplane_utils.load_config()
        m_set_config.assert_called_with('multicastServerInterface',
                                        'br-eth2',
                                        'cplane-dvnd-config.yaml')

    @patch("cplane_utils.set_config")
    def test_load_config_diff_jbooss_cluster(self, m_set_config):
        self.test_config.set('use-default-jboss-cluster', 'n')
        cplane_utils.load_config()
#        hostname = socket.gethostname()
        m_set_config.assert_called_with('multicastServerInterface', 'br-eth2',
                                        'cplane-dvnd-config.yaml'),

    @patch("commands.getoutput")
    def test_check_fip_mode(self, m_getoutput):
        cplane_utils.get_upgrade_type()
        m_getoutput.assert_called_with("cat $CHARM_DIR/config/upgrade-config \
| awk '{ print $2}'")

    @patch("cplane_utils.set_oracle_env")
    @patch("os.chdir")
    @patch("os.system")
    @patch("cplane_utils.execute_sql_command")
    @patch("cplane_utils.set_oracle_host")
    def test_clean_create_db(self, m_set_oracle_host, m_execute_sql_command,
                             m_system, m_chdir, m_set_oracle_env):
        cplane_utils.ORACLE_HOST = 'localhost'
        cplane_utils.clean_create_db()
#        m_set_oracle_env.assert_called_with()
        m_set_oracle_host.assert_called_with()
        m_system.assert_called_with('sh install.sh admin/admin@localhost/\
 2>&1 | tee install.log')
        m_execute_sql_command.assert_called_with('admin/admin@localhost/',
                                                 '@reinstall_plsql')
        m_system.assert_called_with('sh install.sh admin/admin@localhost/\
 2>&1 | tee install.log'.format(cplane_utils.ORACLE_HOST))
        m_execute_sql_command.assert_called_with('admin/admin@localhost/',
                                                 '@reinstall_plsql')

    @patch("os.chdir")
    @patch("commands.getoutput")
    def test_check_jboss_service(self, m_getoutput, m_chdir):
        cplane_utils.CPLANE_DIR = '.'
        cplane_utils.check_jboss_service()
        m_getoutput.assert_called_with('bash checkJBossServer.sh')

    @patch("os.chdir")
    @patch("cplane_utils.load_config")
    @patch("subprocess.check_call")
    @patch("cplane_utils.set_oracle_host")
    @patch("cplane_utils.set_config")
    def test_run_cp_installer(self, m_set_config, m_set_oracle_host,
                              m_check_call, m_load_config, m_chdir):
        cplane_utils.run_cp_installer()
        m_load_config.assert_called_with()
        m_set_oracle_host.assert_called_with()
        m_check_call.assert_called_with(['sh', 'cpinstaller', 'cplane-dvnd-\
config.yaml'])

    def test_get_unit_ip(self):
        SPACES_ADDRESS = '10.100.1.1'
        NI_ADDRESS = '192.168.2.2'
        DEFAULT_ADDRESS = '172.16.3.3'
        self.unit_get.return_value = DEFAULT_ADDRESS
        self.ni.ifaddresses.return_value = None

        _config = {'multicast-intf': None}
        self.config.side_effect = lambda key: _config.get(key)

        # Network spaces address
        self.network_get_primary_address.return_value = SPACES_ADDRESS
        self.assertEqual(SPACES_ADDRESS, cplane_utils.get_unit_ip())
        (self.network_get_primary_address.
            assert_called_with('cplane-controller'))

        # Default unit_get address
        self.network_get_primary_address.side_effect = NotImplementedError
        self.assertEqual(DEFAULT_ADDRESS, cplane_utils.get_unit_ip())
        self.unit_get.assert_called_with('private-address')

        # multicast-intf address
        self.ni.ifaddresses.return_value = {2: [{'addr': NI_ADDRESS}]}
        _config = {'multicast-intf': 'eth0'}
        self.config.side_effect = lambda key: _config.get(key)
        self.assertEqual(NI_ADDRESS, cplane_utils.get_unit_ip())
        self.ni.ifaddresses.assert_called_with('eth0')

        # Interface configured with multicast-intf has no IP
        self.ni.ifaddresses.return_value = {4: [{'addr': NI_ADDRESS}]}
        with self.assertRaises(cplane_utils.UnconfiguredInterface):
            cplane_utils.get_unit_ip()

        # Invalid interface configured with muilticast-intf
        self.ni.ifaddresses.side_effect = ValueError
        with self.assertRaises(cplane_utils.UnconfiguredInterface):
            cplane_utils.get_unit_ip()


suite = unittest.TestLoader().loadTestsFromTestCase(CplaneUtilsTest)
unittest.TextTestRunner(verbosity=2).run(suite)
