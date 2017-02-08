#!/usr/bin/python
from netifaces import AF_INET
import netifaces as ni
import subprocess
from cplane_interface import UbuntuIntfMgmt

from charmhelpers.core.hookenv import (
    status_set,
)


class InterfaceConfigurationException(Exception):
    pass


def create_br_ext(interface):
    data = get_int_config(interface)
    netmask = data[0]['netmask']
    addr = data[0]['addr']
    gateway = ni.gateways()
    gw = gateway['default'][ni.AF_INET][0]

    cmd = ['ovs-vsctl', 'add-br', 'br-ext']
    subprocess.check_call(cmd)
    cmd = ['ovs-vsctl', 'add-port', 'br-ext', interface]
    subprocess.check_call(cmd)
    cmd = ['ifconfig', interface, '0.0.0.0']
    subprocess.check_call(cmd)
    cmd = ['ifconfig', 'br-ext', addr, 'netmask', netmask, 'up']
    subprocess.check_call(cmd)
    cmd = ['route', 'add', 'default', 'gw', gw]
    subprocess.check_call(cmd)


def delete_br_ext(interface):
    data = get_int_config('br-ext')
    netmask = data[0]['netmask']
    addr = data[0]['addr']
    gateway = ni.gateways()
    gw = gateway['default'][ni.AF_INET][0]

    cmd = ['ovs-vsctl', 'del-port', 'br-ext', interface]
    subprocess.check_call(cmd)

    cmd = ['ovs-vsctl', 'del-br', 'br-ext']
    subprocess.check_call(cmd)

    cmd = ['ifconfig', interface, addr, 'netmask', netmask, 'up']
    subprocess.check_call(cmd)
    cmd = ['route', 'add', 'default', 'gw', gw]
    subprocess.check_call(cmd)


def add_bridge(name, interface, gw=None):
    network_configuration = UbuntuIntfMgmt()

    if check_interface(name):
        return
    data = get_int_config(interface)
    netmask = data[0]['netmask']
    addr = data[0]['addr']
    if not gw:
        gateway = ni.gateways()
        gw = gateway['default'][ni.AF_INET][0]

    extra_params = network_configuration.extract_net_config(interface,
                                                            backup=True,
                                                            read_only=False)
    extra_params['inet_type'] = 'manual'
    extra_params['bridge_name'] = name
    extra_params = dict([(k, "".join(list(v))) for k, v in extra_params
                         .iteritems()])


    network_configuration._write_net_config_bridged_iface_br(interface,
                                                             **extra_params)

    extra_params = {'source_intf': interface, 'inet_type': 'static', }
    network_configuration._write_net_config_bridge(name, addr, netmask, gw,
                                                   **extra_params)

    restart_network_service(name, interface)


def restart_network_service(name, interface):
    cmd = ['ifdown', interface, ]
    subprocess.check_call(cmd)
    cmd = ['ip', 'addr', 'flush', 'dev', interface]
    subprocess.check_call(cmd)
    cmd = ['ifup', name, ]
    subprocess.check_call(cmd)


def check_interface(interface):
    interface_list = ni.interfaces()
    if interface in interface_list:
        return True
    else:
        return False


def get_int_config(interface, af=AF_INET):
    interface_list = ni.interfaces()
    if interface in interface_list:
        data = ni.ifaddresses(interface).get(AF_INET)
        if data:
            return data
        else:
            msg = ("Interface {} does not have an address in the address "
                   "family {}".format(interface, af))
            status_set("blocked", msg)
            raise InterfaceConfigurationException(msg)
    else:
        msg = "Interface {} does not exist.".format(interface)
        status_set("blocked", msg)
        raise InterfaceConfigurationException(msg)
