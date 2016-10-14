#!/usr/bin/python
from mock import patch, call
from test_utils import CharmTestCase, unittest
import cplane_network
import netifaces as ni

TO_PATCH = [
]

NI_OUTPUT = {'ethX': {17: [{'broadcast': 'ff:ff:ff:ff:ff:ff',
                            'addr': 'e5:59:e5:41:19:88'}],
                      2: [{'broadcast': '10.0.63.255',
                           'netmask': '255.255.192.0',
                           'addr': '10.0.1.4'}],
                      10: [{'netmask': 'ffff:ffff:ffff:ffff::',
                            'addr': 'fe80::e559:e5ff:fe41:1988%br-eth0'}]}}
NI_OUTPUT_NO_AF = {'ethX': {17: [{'broadcast': 'ff:ff:ff:ff:ff:ff',
                                  'addr': 'e5:59:e5:41:19:88'}],
                            10: [{'netmask': 'ffff:ffff:ffff:ffff::',
                                  'addr': 'fe80::e559:e5ff:fe41:1988%br-eth0'}]
                            }}
NI_EXPECTED = {2: [{'broadcast': '10.0.63.255',
                    'netmask': '255.255.192.0',
                    'addr': '10.0.1.4'}]}


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

    @patch.object(cplane_network, 'ni')
    def test_get_int_config(self, m_ni):
        m_ni.interfaces.return_value = NI_OUTPUT
        m_ni.ifaddresses.return_value = NI_OUTPUT['ethX']
        self.assertEqual(cplane_network.get_int_config('ethX'),
                         NI_EXPECTED[ni.AF_INET])

    @patch.object(cplane_network, 'ni')
    def test_get_int_config_no_int(self, m_ni):
        m_ni.interfaces.return_value = NI_OUTPUT
        with self.assertRaises(cplane_network.InterfaceConfigurationException):
            cplane_network.get_int_config('ethY')

    @patch.object(cplane_network, 'ni')
    def test_get_int_config_no_af(self, m_ni):
        m_ni.interfaces.return_value = NI_OUTPUT_NO_AF
        m_ni.ifaddresses.return_value = NI_OUTPUT_NO_AF['ethX']
        with self.assertRaises(cplane_network.InterfaceConfigurationException):
            cplane_network.get_int_config('ethX')


suite = unittest.TestLoader().loadTestsFromTestCase(CplaneNetworkTest)
unittest.TextTestRunner(verbosity=2).run(suite)
