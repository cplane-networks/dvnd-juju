#!/usr/bin/python
from test_utils import CharmTestCase, unittest

from mock import MagicMock, patch, call
import charmhelpers.contrib.openstack.templating as templating
from charmhelpers.core import hookenv
hookenv.config = MagicMock()
import cplane_utils

templating.OSConfigRenderer = MagicMock()

from cplane_package_manager import(
    CPlanePackageManager
)

from collections import OrderedDict
from charmhelpers.core.hookenv import config

TO_PATCH = [
    'apt_install',
    'config',
    'open',
    'log'
]


cplane_install_package = OrderedDict([
    (config('oracle-version'), '0')
])


class CplaneUtilsTest(CharmTestCase):

    def setUp(self):
        super(CplaneUtilsTest, self).setUp(cplane_utils, TO_PATCH)
        self.config.side_effect = self.test_config.get

    def tearDown(self):
        super(CplaneUtilsTest, self).tearDown()

    @patch.object(cplane_utils, "get_os_release")
    def test_determine_packages(self, m_get_os_release):
        m_get_os_release.return_value = '14.04'
        self.assertEqual(cplane_utils.determine_packages(),
                         ['alien', 'libaio1', 'python-pexpect'])

    @patch.object(cplane_utils.CPlanePackageManager, "_create_log")
    @patch.object(cplane_utils.CPlanePackageManager, "_get_pkg_json")
    @patch.object(CPlanePackageManager, "download_package")
    def test_download_cplane_packages(self, m_download_package,
                                      m_get_pkg_json, m_create_log):
        cplane_utils.CPLANE_URL = 'https://www.dropbox.com/s/h2edle1o0jj1btt/\
cplane_metadata.json?dl=1'
        cplane_utils.cplane_packages = cplane_install_package
        cplane_utils.download_cplane_packages()
        m_download_package.assert_called_with(config('oracle-version'), '0')

    @patch('pexpect.spawn')
    def test_oracle_configure_init(self, m_spawn):
        cplane_utils.oracle_configure_init()
        m_spawn.assert_called_with('/etc/init.d/oracle-xe configure',
                                   timeout=900)

    @patch("subprocess.check_call")
    def test_deb_convert_install(self, m_check_call):
        cplane_utils.CHARM_LIB_DIR = '.'
        cplane_utils.filename['jboss'] = 'test.txt'
        cplane_utils.deb_convert_install('jboss')
        m_check_call.assert_called_with(['alien', '--scripts', '-d',
                                        '-i', 'test.txt'])

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

    @patch("commands.getoutput")
    def test_get_os_release(self, m_getoutput):
        cplane_utils.get_os_release()
        self.assertEqual(m_getoutput.call_args,
                         call('lsb_release -r'))

suite = unittest.TestLoader().loadTestsFromTestCase(CplaneUtilsTest)
unittest.TextTestRunner(verbosity=2).run(suite)
