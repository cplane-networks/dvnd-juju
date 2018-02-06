#!/usr/bin/python
from test_utils import CharmTestCase, unittest
import cplane_context

from mock import patch

TO_PATCH = [
    'config',
    'log',
    'os_release',
    'relation_ids',
    'relation_get',
    'related_units',
]

IDENTITY_CONTEXT = {
    'auth_port': '5000',
    'auth_protocol': 'http',
    'service_port': '5000',
    'service_protocol': 'http',
    'service_tenant': 'admin',
    'service_username': 'admin',
    'service_password': 'openstack',
    'service_host': 'keystone_host',
    'auth_host': 'keystone_host',
    'api_version': '2.0',
    'region': 'region'
}


class GeneralTest(CharmTestCase):

    def setUp(self):
        super(GeneralTest, self).setUp(cplane_context, TO_PATCH)
        self.config.side_effect = self.test_config.get

    def tearDown(self):
        super(GeneralTest, self).tearDown()

    def test_get_overlay_network_type(self):
        self.test_config.set('overlay-network-type', 'gre')
        self.assertEquals(cplane_context.get_overlay_network_type(), 'gre')

    def test_get_l3ha(self):
        self.test_config.set('enable-l3ha', True)
        self.test_config.set('l2-population', False)
        self.os_release.return_value = 'juno'
        self.assertEquals(cplane_context.get_l3ha(), True)

    def test_get_l3ha_prejuno(self):
        self.test_config.set('enable-l3ha', True)
        self.test_config.set('l2-population', False)
        self.os_release.return_value = 'icehouse'
        self.assertEquals(cplane_context.get_l3ha(), False)

    def test_l2population(self):
        self.test_config.set('l2-population', True)
        self.test_config.set('neutron-plugin', 'ovs')
        self.assertEquals(cplane_context.get_l2population(), True)

    def test_l2population_nonovs(self):
        self.test_config.set('l2-population', True)
        self.test_config.set('neutron-plugin', 'cplane')
        self.assertEquals(cplane_context.get_l2population(), False)

    def test_get_dvr(self):
        self.test_config.set('enable-dvr', True)
        self.test_config.set('enable-l3ha', False)
        self.test_config.set('overlay-network-type', 'vxlan')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', True)
        self.os_release.return_value = 'juno'
        self.assertEquals(cplane_context.get_dvr(), True)

    def test_get_dvr_explicit_off(self):
        self.test_config.set('enable-dvr', False)
        self.test_config.set('enable-l3ha', False)
        self.test_config.set('overlay-network-type', 'vxlan')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', True)
        self.os_release.return_value = 'juno'
        self.assertEquals(cplane_context.get_dvr(), False)

    def test_get_dvr_prejuno(self):
        self.test_config.set('enable-dvr', True)
        self.test_config.set('enable-l3ha', False)
        self.test_config.set('overlay-network-type', 'vxlan')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', True)
        self.os_release.return_value = 'icehouse'
        self.assertEquals(cplane_context.get_dvr(), False)

    def test_get_dvr_gre(self):
        self.test_config.set('enable-dvr', True)
        self.test_config.set('enable-l3ha', False)
        self.test_config.set('overlay-network-type', 'gre')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', True)
        self.os_release.return_value = 'juno'
        self.assertEquals(cplane_context.get_dvr(), False)

    def test_get_dvr_gre_kilo(self):
        self.test_config.set('enable-dvr', True)
        self.test_config.set('enable-l3ha', False)
        self.test_config.set('overlay-network-type', 'gre')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', True)
        self.os_release.return_value = 'kilo'
        self.assertEquals(cplane_context.get_dvr(), True)

    def test_get_dvr_vxlan_kilo(self):
        self.test_config.set('enable-dvr', True)
        self.test_config.set('enable-l3ha', False)
        self.test_config.set('overlay-network-type', 'vxlan')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', True)
        self.os_release.return_value = 'kilo'
        self.assertEquals(cplane_context.get_dvr(), True)

    def test_get_dvr_l3ha_on(self):
        self.test_config.set('enable-dvr', True)
        self.test_config.set('enable-l3ha', True)
        self.test_config.set('overlay-network-type', 'vxlan')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', False)
        self.os_release.return_value = 'juno'
        self.assertEquals(cplane_context.get_dvr(), False)

    def test_get_dvr_l2pop(self):
        self.test_config.set('enable-dvr', True)
        self.test_config.set('enable-l3ha', False)
        self.test_config.set('overlay-network-type', 'vxlan')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', False)
        self.os_release.return_value = 'juno'
        self.assertEquals(cplane_context.get_dvr(), False)


class IdentityServiceContext(CharmTestCase):

    def setUp(self):
        super(IdentityServiceContext, self).setUp(cplane_context, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.relation_get.side_effect = self.test_relation.get
        self.host_uuid = 'e46e530d-18ae-4a67-9ff0-e6e2ba7c60a7'

    def test_identity_context(self):
        self.relation_ids.return_value = 'neutron-plugin-api:0'
        self.related_units.return_value = 'neutron-api/0'
        self.test_relation.set(IDENTITY_CONTEXT)
        ids_ctxt = cplane_context.IdentityServiceContext()
        id_data = {'auth_port': '5000',
                   'auth_protocol': 'http',
                   'service_port': '5000',
                   'service_protocol': 'http',
                   'service_tenant': 'admin',
                   'service_username': 'admin',
                   'service_password': 'openstack',
                   'service_host': 'keystone_host',
                   'auth_host': 'keystone_host',
                   'api_version': '2.0',
                   'auth_region': 'region'}
        self.assertEquals(ids_ctxt(), id_data)

    def test_ids_ctxt_no_rels(self):
        self.related_units.return_value = None
        ids_ctxt = cplane_context.IdentityServiceContext()
        self.assertEquals(ids_ctxt(), {})


class NeutronCCContextTest(CharmTestCase):

    def setUp(self):
        super(NeutronCCContextTest, self).setUp(cplane_context, TO_PATCH)
        self.config.side_effect = self.test_config.get
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('neutron-security-groups', True)
        self.test_config.set('debug', True)
        self.test_config.set('verbose', True)

    def tearDown(self):
        super(NeutronCCContextTest, self).tearDown()

    @patch.object(cplane_context.NeutronCCContext, 'network_manager')
    @patch.object(cplane_context.NeutronCCContext, 'plugin')
    @patch('__builtin__.__import__')
    def test_neutroncc_context_no_setting(self, _import, plugin, nm):
        plugin.return_value = None
        ctxt_data = {
            'overlay_network_type': 'gre',
            'enable_dvr': False,
            'vlan_ranges': 'physnet1:1000:2000',
            'l2_population': True,
            'l3_ha': False,
            'debug': True,
            'external_network': 'ext_net',
            'verbose': True
        }
        napi_ctxt = cplane_context.NeutronCCContext()
        with patch.object(napi_ctxt, '_ensure_packages'):
            self.assertEquals(ctxt_data, napi_ctxt())

    @patch.object(cplane_context.NeutronCCContext, 'network_manager')
    @patch.object(cplane_context.NeutronCCContext, 'plugin')
    @patch('__builtin__.__import__')
    def test_neutroncc_context_vxlan(self, _import, plugin, nm):
        plugin.return_value = None
        self.test_config.set('flat-network-providers', 'physnet2 physnet3')
        self.test_config.set('overlay-network-type', 'vxlan')
        ctxt_data = {
            'overlay_network_type': 'vxlan',
            'enable_dvr': False,
            'vlan_ranges': 'physnet1:1000:2000',
            'network_providers': 'physnet2,physnet3',
            'l2_population': True,
            'l3_ha': False,
            'debug': True,
            'external_network': 'ext_net',
            'verbose': True
        }

        napi_ctxt = cplane_context.NeutronCCContext()
        with patch.object(napi_ctxt, '_ensure_packages'):
            self.assertEquals(ctxt_data, napi_ctxt())

    @patch.object(cplane_context.NeutronCCContext, 'network_manager')
    @patch.object(cplane_context.NeutronCCContext, 'plugin')
    @patch('__builtin__.__import__')
    def test_neutroncc_context_l3ha(self, _import, plugin, nm):
        plugin.return_value = None
        self.test_config.set('enable-l3ha', True)
        self.test_config.set('overlay-network-type', 'gre')
        self.test_config.set('neutron-plugin', 'ovs')
        self.test_config.set('l2-population', False)
        self.os_release.return_value = 'juno'
        ctxt_data = {
            'overlay_network_type': 'gre',
            'enable_dvr': False,
            'vlan_ranges': 'physnet1:1000:2000',
            'l2_population': False,
            'l3_ha': True,
            'debug': True,
            'external_network': 'ext_net',
            'verbose': True
        }

        napi_ctxt = cplane_context.NeutronCCContext()
        with patch.object(napi_ctxt, '_ensure_packages'):
            self.assertEquals(ctxt_data, napi_ctxt())

    def test_neutroncc_context_manager(self):
        napi_ctxt = cplane_context.NeutronCCContext()
        self.assertEquals(napi_ctxt.network_manager, 'neutron')
        self.assertEquals(napi_ctxt.plugin, 'ovs')
        self.assertEquals(napi_ctxt.neutron_security_groups, True)


suite = unittest.TestLoader().loadTestsFromTestCase(GeneralTest)
unittest.TextTestRunner(verbosity=2).run(suite)
suite = unittest.TestLoader().loadTestsFromTestCase(IdentityServiceContext)
unittest.TextTestRunner(verbosity=2).run(suite)
suite = unittest.TestLoader().loadTestsFromTestCase(NeutronCCContextTest)
unittest.TextTestRunner(verbosity=2).run(suite)
