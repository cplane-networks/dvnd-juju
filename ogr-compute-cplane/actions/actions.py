#!/usr/bin/python
import os
import sys
import commands

sys.path.append('hooks/')

from charmhelpers.core.hookenv import (
    action_fail,
    action_get,
    action_set,
)

from cplane_utils import download_ogr_image


def neutron_agent_list(args):
    cmd = "su - ubuntu -c 'source nova.rc && neutron agent-list'"
    res = commands.getoutput(cmd)
    action_set({'result-map.message': res})


def neutron_agent_show(args):
    agent_id = action_get('id')
    cmd = "su - ubuntu -c 'source nova.rc && neutron agent-show {}'"\
          .format(agent_id)
    res = commands.getoutput(cmd)
    action_set({'result-map.message': res})


def create_ogr_zone(args):
    aggr_name = action_get('aggregate-name')
    avail_zone = action_get('avail-zone')
    ogr_compute = action_get('ogr-compute')

    cmd = "su - ubuntu -c 'source nova.rc && nova aggregate-create {} {}'"\
          .format(aggr_name, avail_zone)
    commands.getoutput(cmd)
    cmd = "su - ubuntu -c 'source nova.rc && nova aggregate-add-host {} {}'"\
          .format(aggr_name, ogr_compute)
    commands.getoutput(cmd)

    cmd = "su - ubuntu -c 'source nova.rc && nova aggregate-details {}'"\
          .format(aggr_name)
    res = commands.getoutput(cmd)
    action_set({'result-map.message': res})


def delete_ogr_zone(args):
    aggr_name = action_get('aggregate-name')
    ogr_compute = action_get('ogr-compute')

    cmd = "su - ubuntu -c 'source nova.rc && nova aggregate-remove-host {} {}\
'".format(aggr_name, ogr_compute)
    res = commands.getoutput(cmd)
    cmd = "su - ubuntu -c 'source nova.rc && nova aggregate-delete {}'"\
          .format(aggr_name)
    res = commands.getoutput(cmd)
    action_set({'result-map.message': res})


def ogr_zone_detail(args):
    aggr_name = action_get('aggregate-name')

    cmd = "su - ubuntu -c 'source nova.rc && nova aggregate-details {}'"\
          .format(aggr_name)
    res = commands.getoutput(cmd)
    action_set({'result-map.message': res})


def create_network(args):
    net_name = action_get('net-name')
    net_type = action_get('net-type')
    phys_net = action_get('phys-net')

    cmd = "su - ubuntu -c 'source nova.rc && neutron net-create {} \
--provider:network_type={} --provider:physical_network={}'"\
          .format(net_name, net_type, phys_net)
    res = commands.getoutput(cmd)
    action_set({'result-map.message': res})


def create_subnet(args):
    sub_name = action_get('sub-name')
    net_name = action_get('net-name')
    cidr = action_get('cidr')
    pool_start = action_get('pool-start')
    pool_end = action_get('pool-end')

    cmd = "su - ubuntu -c 'source nova.rc && neutron subnet-create --name {} \
{} {} --no-gateway --allocation-pool start={},end={}'"\
          .format(sub_name, net_name, cidr, pool_start, pool_end)
    res = commands.getoutput(cmd)
    action_set({'result-map.message': res})


def add_ogr_vm(args):
    name = action_get('name')
    image_path = download_ogr_image()

    cmd = "su - ubuntu -c 'source nova.rc && glance image-create --name {} \
--visibility public --container-format bare --disk-format qcow2 < {}'"\
          .format(name, image_path)
    res = commands.getoutput(cmd)
    action_set({'result-map.message': res})

# A dictionary of all the defined actions to callables (which take
# parsed arguments).
ACTIONS = {"neutron-agent-list": neutron_agent_list,
           "neutron-agent-show": neutron_agent_show,
           "create-ogr-zone": create_ogr_zone,
           "delete-ogr-zone": delete_ogr_zone,
           "ogr-zone-detail": ogr_zone_detail,
           "create-network": create_network,
           "create-subnet": create_subnet,
           "add-ogr-vm": add_ogr_vm, }


def main(args):
    action_name = os.path.basename(args[0])
    try:
        action = ACTIONS[action_name]
    except KeyError:
        return "Action %s undefined" % action_name
    else:
        try:
            action(args)
        except Exception as e:
            action_fail(str(e))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
