#!/usr/bin/python
from test_utils import CharmTestCase, unittest

from mock import MagicMock, call, patch
import charmhelpers.contrib.openstack.templating as templating
from charmhelpers.core import hookenv
hookenv.config = MagicMock()
import cplane_utils

templating.OSConfigRenderer = MagicMock()


TO_PATCH = [
    'apt_install',
    'os_release',
    'config',
    'open'
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

    @patch("json.load")
    @patch("json.dump")
    def test_configure_policy(self, m_json_dump, m_json_load):
        data = {}
        self.open.return_value = None
        m_json_load.return_value = data
        cplane_utils.configure_policy()
        m_json_dump.assert_called_with({'update_floatingip_quota': 'rule:admin\
_or_owner', 'delete_ogr': 'rule:admin_only', 'get_floating\
ip_quotas': '', 'get_ogrs': '', 'update_ogr': 'rule:admin_or_owner', 'get_\
ogr': '', 'create_floatingip:floating_ip_address': 'rule:admin_or_owner', 'get\
_floatingip_quota': 'rule:admin_or_owner'}, None, indent=4)
suite = unittest.TestLoader().loadTestsFromTestCase(CplaneUtilsTest)
unittest.TextTestRunner(verbosity=2).run(suite)
