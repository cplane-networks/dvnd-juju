#!/usr/bin/python
from test_utils import CharmTestCase, unittest
import cplane_context

TO_PATCH = [
    'context',
    'config',
]


class CplaneContextTest(CharmTestCase):

    def setUp(self):
        super(CplaneContextTest, self).setUp(cplane_context, TO_PATCH)
        self.config.side_effect = self.test_config.get

    def tearDown(self):
        super(CplaneContextTest, self).tearDown()

    def test_get_overlay_network_type(self):
        self.test_config.set('overlay-network-type', 'gre')
        self.assertEquals(cplane_context.get_overlay_network_type(), 'gre')

suite = unittest.TestLoader().loadTestsFromTestCase(CplaneContextTest)
unittest.TextTestRunner(verbosity=2).run(suite)
