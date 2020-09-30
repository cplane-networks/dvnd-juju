import netifaces as ni
import subprocess
from cplane_interface import UbuntuIntfMgmt


class InterfaceConfigurationException(Exception):
    pass


def check_interface(interface):
    interface_list = ni.interfaces()
    if interface in interface_list:
        return True
    else:
        return False


def change_iface_config(interface, field, value):
    network_configuration = UbuntuIntfMgmt()
    if check_interface(interface):
        network_configuration.change_iface_config(interface, field, value)
        cmd = ['ifdown', interface, ]
        subprocess.check_call(cmd)
        cmd = ['ifup', interface, ]
        subprocess.check_call(cmd)
