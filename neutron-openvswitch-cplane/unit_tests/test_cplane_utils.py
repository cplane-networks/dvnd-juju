#!/usr/bin/python
from mock import MagicMock, patch, call
from test_utils import CharmTestCase, unittest
from charmhelpers.core import hookenv
hookenv.config = MagicMock()
import cplane_utils


TO_PATCH = [
    'relation_ids',
    'related_units',
    'relation_get',
    'juju_log',
    'config',
    'add_bridge',
    'check_interface',
]


class CplaneUtilsTest(CharmTestCase):

    def setUp(self):
        super(CplaneUtilsTest, self).setUp(cplane_utils, TO_PATCH)
        self.relation_ids.return_value = ['random_rid']
        self.related_units.return_value = ['random_unit']
        self.relation_get.return_value = True
        self.config.return_value = 'random_interface'

    def tearDown(self):
        super(CplaneUtilsTest, self).tearDown()
        call(["rm", "-f", "/tmp/cplane.ini"])

    def test_determine_packages(self):
        self.assertEqual(cplane_utils.determine_packages(),
                         ['neutron-metadata-agent', 'neutron-plugin-ml2',
                          'crudini', 'dkms', 'iputils-arping', 'dnsmasq'])

    @patch("subprocess.check_call")
    def test_crudini_set(self, m_check_call):
        cplane_utils.crudini_set('/tmp/cplane.ini', 'DEFAULT', 'TEST',
                                 'CPLANE')
        self.assertEqual(m_check_call.call_args,
                         call(['crudini', '--set',
                               '/tmp/cplane.ini',
                               'DEFAULT', 'TEST', 'CPLANE']))

    def test_manage_fip(self):

        # Check for correct fip interface
        self.check_interface.return_value = True

        cplane_utils.manage_fip()

        self.relation_ids.assert_called_with('cplane-controller')
        self.related_units.assert_called_with('random_rid')
        self.relation_get.assert_called_with(attribute='fip-mode',
                                             unit='random_unit',
                                             rid='random_rid')
        self.config.assert_called_with('fip-interface')
        self.check_interface.assert_called_with('random_interface')
        self.add_bridge.assert_called_with('br-fip', 'random_interface')

        # Check for incorrect fip interface
        self.check_interface.return_value = False

        cplane_utils.manage_fip()

        self.relation_ids.assert_called_with('cplane-controller')
        self.related_units.assert_called_with('random_rid')
        self.relation_get.assert_called_with(attribute='fip-mode',
                                             unit='random_unit',
                                             rid='random_rid')
        self.config.assert_called_with('fip-interface')
        self.check_interface.assert_called_with('random_interface')
        self.juju_log.assert_called_with('Fip interface doesnt exist, and \
                    will be used by default by Cplane controller')

    @patch("subprocess.check_call")
    def test_set_cp_agent(self, m_check_call):
        # Check if valid port is returned
        self.relation_get.return_value = "9000"
        cplane_utils.set_cp_agent()

        self.relation_ids.assert_called_with('cplane-controller')
        self.related_units.assert_called_with('random_rid')
        self.relation_get.assert_called_with('private-address')
        self.assertEqual(m_check_call.call_args,
                         call(['cp-agentd', 'set-config',
                              'log-level=file:random_interface']))

        # Check if invallid port is returned

        self.relation_get.return_value = "0"
        cplane_utils.set_cp_agent()

        self.relation_ids.assert_called_with('cplane-controller')
        self.related_units.assert_called_with('random_rid')
        self.relation_get.assert_called_with('private-address')
        self.assertEqual(m_check_call.call_args,
                         call(['cp-agentd', 'set-config',
                               'log-level=file:random_interface']))

    @patch("subprocess.check_call")
    def test_restart_services(self, m_check_call):
        cplane_utils.restart_services()
        self.assertEqual(m_check_call.call_args, call(['update-rc.d',
                                                       'cp-agentd', 'enable']))

    @patch("subprocess.check_call")
    def test_restart_cp_agentd(self, m_check_call):
        cplane_utils.restart_cp_agentd()
        self.assertEqual(m_check_call.call_args,
                         call(['service', 'cp-agentd',
                               'restart']))

suite = unittest.TestLoader().loadTestsFromTestCase(CplaneUtilsTest)
unittest.TextTestRunner(verbosity=2).run(suite)
