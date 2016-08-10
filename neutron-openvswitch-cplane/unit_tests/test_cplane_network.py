#!/usr/bin/python
from mock import patch, call
from test_utils import CharmTestCase, unittest
import cplane_network
import netifaces as ni

TO_PATCH = [
]


class CplaneNetworkTest(CharmTestCase):

    def setUp(self):
        super(CplaneNetworkTest, self).setUp(cplane_network, TO_PATCH)

    def tearDown(self):
        super(CplaneNetworkTest, self).tearDown()
        call(["rm", "-f", "/tmp/cplane.ini"])

    @patch("subprocess.check_call")
    def test_create_br_ext(self, m_check_call):

        gateway = ni.gateways()
        gw = gateway['default'][ni.AF_INET][0]
        cplane_network.create_br_ext('lo')
        self.assertEqual(m_check_call.call_args,
                         call(['route', 'add', 'default', 'gw', gw]))

    @patch("subprocess.check_call")
    def test_restart_network_service(self, m_check_call):

        cplane_network.restart_network_service('lo', 'lo')
        self.assertEqual(m_check_call.call_args, call(['ifup', 'lo', ]))

    def test_check_interface(self):
        # check for valid interface
        self.assertEqual(cplane_network.check_interface('lo'), True)

        # check for invalid interface
        self.assertEqual(cplane_network.check_interface('cplane'), False)

suite = unittest.TestLoader().loadTestsFromTestCase(CplaneNetworkTest)
unittest.TextTestRunner(verbosity=2).run(suite)
