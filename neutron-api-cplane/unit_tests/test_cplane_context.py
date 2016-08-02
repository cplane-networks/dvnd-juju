#!/usr/bin/python
from test_utils import CharmTestCase
import cplane_utils 
import cplane_context
import charmhelpers

import json
from mock import MagicMock, patch, call
from collections import OrderedDict


TO_PATCH = [
    'config',
    'relation_get',
    'relation_ids',
]

class CplaneContextTest(CharmTestCase):

    def setUp(self):
        super(CplaneContextTest, self).setUp(cplane_context, TO_PATCH)
        self.relation_get.side_effect = self.test_relation.get
        self.config.side_effect = self.test_config.get

    def tearDown(self):
        super(CplaneContextTest, self).tearDown()

    def test_get_overlay_network_type(self):
        self.test_config.set('overlay-network-type', 'gre')
        self.assertEquals(cplane_context.get_overlay_network_type(), 'gre')

if __name__ == '__main__':
    unittest.main()

