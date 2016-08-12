#!/usr/bin/python
from test_utils import CharmTestCase, unittest
import cplane_utils

from mock import MagicMock, call, patch
import charmhelpers.contrib.openstack.templating as templating

templating.OSConfigRenderer = MagicMock()


TO_PATCH = [
    'apt_install',
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
                         ['neutron-plugin-ml2', 'crudini', 'python-dev'])

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
        confs = ['/etc/neutron/plugins/ml2/ml2_conf.ini']
        self.assertItemsEqual(_regconfs.configs, confs)

    @patch("subprocess.check_call")
    def test_crudini_set(self, m_check_call):
        cplane_utils.crudini_set('/tmp/cplane.ini', 'DEFAULT', 'TEST',
                                 'CPLANE')
        self.assertEqual(m_check_call.call_args,
                         call(['crudini', '--set',
                               '/tmp/cplane.ini',
                               'DEFAULT', 'TEST', 'CPLANE']))

    @patch("subprocess.check_call")
    def test_create_link(self, m_check_call):
        cplane_utils.create_link()
        calls = [call(['rm', '-f', '/etc/neutron/plugin.ini']),
                 call(['ln', '-s', '/etc/neutron/plugins/ml2/ml2_conf.ini',
                       '/etc/neutron/plugin.ini'])]
        m_check_call.assert_has_calls(calls)

    @patch("subprocess.check_call")
    def test_restart_service(self, m_check_call):
        cplane_utils.restart_service()
        m_check_call.assert_called_with(['service',
                                         'neutron-server',
                                         'restart'])

suite = unittest.TestLoader().loadTestsFromTestCase(CplaneUtilsTest)
unittest.TextTestRunner(verbosity=2).run(suite)
