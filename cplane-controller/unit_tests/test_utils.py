#!/usr/bin/python
import logging
import unittest
import os
import yaml
from mock import patch


def load_config():
    '''
    Check if the config.yaml file exists
    '''
    config = None
    f = __file__
    while config is None:
        d = os.path.dirname(f)
        if os.path.isfile(os.path.join(d, 'config.yaml')):
            config = os.path.join(d, 'config.yaml')
            break
        f = d

    if not config:
        logging.error('Could not find config.yaml in any parent directory '
                      'of %s. ' % file)
        raise Exception

    return yaml.safe_load(open(config).read())['options']


def get_default_config():
    '''
    Load default charm config from config.yaml return as a dict.
    If no default is set in config.yaml, its value is None.
    '''
    default_config = {}
    config = load_config()
    for k, v in config.iteritems():
        if 'default' in v:
            default_config[k] = v['default']
        else:
            default_config[k] = None
    return default_config


class CharmTestCase(unittest.TestCase):
    def setUp(self, obj, patches):
        super(CharmTestCase, self).setUp()
        self.patches = patches
        self.obj = obj
        self.test_config = TestConfig()
        self.test_relation = TestRelation()
        self.patch_all()

    def patch(self, method):
        _m = patch.object(self.obj, method)
        mock = _m.start()
        self.addCleanup(_m.stop)
        return mock

    def patch_all(self):
        for method in self.patches:
            setattr(self, method, self.patch(method))


class TestConfig(object):

    def __init__(self):
        self.config = get_default_config()

    def get(self, attr=None):
        if not attr:
            return self.get_all()
        try:
            return self.config[attr]
        except KeyError:
            return None

    def get_all(self):
        return self.config

    def set(self, attr, value):
            if attr not in self.config:
                raise KeyError
            self.config[attr] = value


class TestRelation(object):

    def __init__(self, relation_data={}):
        self.relation_data = relation_data

    def set(self, relation_data):
        self.relation_data = relation_data

    def get(self, attribute=None, unit=None, rid=None):
        if attribute is None:
            return self.relation_data
        elif attribute in self.relation_data:
            return self.relation_data[attribute]
        return None
