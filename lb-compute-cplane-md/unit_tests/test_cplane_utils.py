#!/usr/bin/python
from mock import MagicMock, patch, call
from test_utils import CharmTestCase, unittest
from charmhelpers.core import hookenv
from charmhelpers.contrib.openstack import utils
hookenv.config = MagicMock()
utils.os_release = MagicMock()
import cplane_utils
import charmhelpers.contrib.openstack.templating as templating
templating.OSConfigRenderer = MagicMock()

TO_PATCH = [
    'config',
    'os_release',

]


class CplaneUtilsTest(CharmTestCase):

    def setUp(self):
        super(CplaneUtilsTest, self).setUp(cplane_utils, TO_PATCH)

    def tearDown(self):
        super(CplaneUtilsTest, self).tearDown()
        call(["rm", "-f", "/tmp/cplane.ini"])

    def test_determine_packages(self):
        self.assertEqual(cplane_utils.determine_packages(),
                         ['sysfsutils', 'neutron-metadata-agent',
                          'python-neutronclient', 'crudini', 'conntrack',
                          'neutron-plugin-ml2',
                          'neutron-plugin-linuxbridge-agent'])

    @patch("subprocess.check_call")
    def test_crudini_set(self, m_check_call):
        cplane_utils.crudini_set('/tmp/cplane.ini', 'DEFAULT', 'TEST',
                                 'CPLANE')
        self.assertEqual(m_check_call.call_args,
                         call(['crudini', '--set',
                               '/tmp/cplane.ini',
                               'DEFAULT', 'TEST', 'CPLANE']))

    def test_register_configs(self):
        class _mock_OSConfigRenderer():
            def __init__(self, templates_dir=None, openstack_release=None):
                self.configs = []
                self.ctxts = []

            def register(self, config, ctxt):
                self.configs.append(config)
                self.ctxts.append(ctxt)

        self.os_release.return_value = 'liberty'
        templating.OSConfigRenderer.side_effect = _mock_OSConfigRenderer
        _regconfs = cplane_utils.register_configs()
        confs = ['/etc/neutron/neutron.conf',
                 '/etc/neutron/metadata_agent.ini',
                 '/etc/neutron/plugins/ml2/linuxbridge_agent.ini']
        self.assertItemsEqual(_regconfs.configs, confs)

    @patch("subprocess.check_call")
    def test_restart_services(self, m_check_call):
        cplane_utils.restart_services()
        self.assertEqual(m_check_call.call_args,
                         call(['service', 'neutron-metadata-agent',
                               'restart']))

    @patch("subprocess.check_call")
    def test_remove_sql_lite(self, m_check_call):
        cplane_utils.remove_sql_lite()
        self.assertEqual(m_check_call.call_args,
                         call(['rm', '-f', '/var/lib/nova/nova.sqlite']))

    def test_resource_map(self):
        self.os_release.return_value = 'liberty'
        _map = cplane_utils.resource_map()
        svcs = ['neutron']
        confs = [cplane_utils.NEUTRON_CONF]
        [self.assertIn(q_conf, _map.keys()) for q_conf in confs]
        self.assertEqual(_map[cplane_utils.NEUTRON_CONF]['services'], svcs)

    @patch("subprocess.check_call")
    def test_disable_bridge_fw(self, m_check_call):
        cplane_utils.disable_bridge_fw()
        self.assertEqual(m_check_call.call_args,
                         call(['service', 'ebtables', 'stop']))


suite = unittest.TestLoader().loadTestsFromTestCase(CplaneUtilsTest)
unittest.TextTestRunner(verbosity=2).run(suite)
