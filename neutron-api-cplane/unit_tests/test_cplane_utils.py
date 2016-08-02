#!/usr/bin/python
from test_utils import CharmTestCase
import cplane_utils 
import charmhelpers
import charmhelpers.core.services.helpers as helpers

import json
from mock import MagicMock, patch, call
from collections import OrderedDict
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
  
    def test_crudini_set(self):
        call(["echo", "[DEFAULT]", ">", "/tmp/cplane.init"])
        call(["echo", "TEST = TEST", ">>", "/tmp/cplane.init"]) 
        cplane_utils.crudini_set('/tmp/cplane.ini', 'DEFAULT', 'TEST', 'CPLANE')
        self.assertEqual('TEST = CPLANE' in open('/tmp/cplane.ini').read(), True)

#The actual file doesnt exist, so it should fail and is considered as negetive test
    def test_create_link(self):
        self.assertRaises(cplane_utils.subprocess.CalledProcessError, lambda: list(cplane_utils.create_link()))
  
#The actual process doesnt exist, so it should fail and is considered as negetive test 
#This test may ask for the password as there is a service restart command
    def test_restart_service(self):
        self.assertRaises(cplane_utils.subprocess.CalledProcessError, lambda: list(cplane_utils.restart_service()))


if __name__ == '__main__':
    unittest.main()

