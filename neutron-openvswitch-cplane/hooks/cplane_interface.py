import logging

from datetime import datetime
import re
import shutil
from collections import OrderedDict
import os

logger = logging.getLogger(__name__)


class UbuntuIntfMgmt(object):
    def __init__(self):
        self.iface_params = {}
        self.config_params = OrderedDict()

    def _extract_iface_param(self, line):
        """ given the input line extrace the iface params """
        options = line.lstrip().split()
        k = options[0]
        vals = options[1:]
        self.iface_params[k] = vals
        if k == 'post-up':
            k = options[4]
            self.config_params[k] = vals
        else:
            self.config_params[k] = vals

    def _validate_iface_params(self):
        keys_mandatory = ["address"]
        for key in keys_mandatory:
            if key not in self.iface_params:
                return False
        return True

    def extract_net_config(self, ifname, backup=True,
                           intf_save_file=None, read_only=True):
        """ extract the configuration for a specific interface
        """
        src_file = "/etc/network/interfaces.d/50-cloud-init.cfg"
        if check_default_interface_file():
            src_file = "/etc/network/interfaces"
        back_file = "/tmp/cp_interfaces_file.{dt}".format(
            dt=datetime.now().strftime("%m%d%Y%H%M%S"))
        if backup:
            intf_backup_file = "/tmp/cp_interfaces_{name}.{dt}".format(
                name=ifname,
                dt=datetime.now().strftime("%m%d%Y%H%M%S"))

        # setup regex for checking of interface names.
        is_iface_stanza = 0
        re_comment = re.compile(r"^#")
        re_empty = re.compile(r"^\s*$")
        re_iface_stz = re.compile(r"^iface.*{name}(?!\.)".format(name=ifname))
        re_new_stz = re.compile(r"^iface|^mapping|^auto|^allow|^source")
        re_ifname = re.compile(r".*(?<!vlan-raw-device\s){name}(?!\.).*"
                               .format(name=ifname))

        fp_read = open(src_file, "r")
        fp_bak = open(back_file, "w")
        if backup:
            fp_bak_intf = open(intf_backup_file, "w")

        for line in fp_read:
            # check for comment or empty line.
            if re_comment.match(line) or re_empty.match(line):
                fp_bak.write(line)
                continue
            if is_iface_stanza == 0:
                if re_iface_stz.match(line):
                    is_iface_stanza = 1
                    if backup:
                        fp_bak_intf.write(line)
                    continue
            elif is_iface_stanza == 1:
                if re_new_stz.match(line):
                    is_iface_stanza = 2
                else:
                    self._extract_iface_param(line)
                    if backup:
                        fp_bak_intf.write(line)
                    continue
            # don't save any lines with ifname in it.
            if re_ifname.match(line):
                continue
            else:
                fp_bak.write(line)

        fp_read.close()
        fp_bak.close()
        if backup:
            fp_bak_intf.close()
        if self._validate_iface_params() is False:
            raise ValueError("{name}: Could not parse needed iface params".
                             format(name=ifname))

        if not read_only:
            shutil.move(back_file, src_file)
        # Now save the files and move them to their specified locations.
        if backup:
            if intf_save_file is None:
                intf_save_file = "/etc/network/cp_interface_{name}".format(
                    name=ifname)
            shutil.move(intf_backup_file, intf_save_file)
        return self.iface_params

    def _write_net_config_bridge(self, ifname, addr, mask, gw,
                                 **kwargs):
        """ write the configuration bridge
                kwargs {"defroute" : T|F",
                        "source_intf: "bridge-src",
                       }
        """
        if "defroute" in kwargs:
            defroute = kwargs["defroute"]
        else:
            defroute = False

        if "source_intf" not in kwargs:
            raise ValueError("{name} bridge needs source_intf".
                             format(name=ifname))

        if "intf_file" in kwargs:
            op_file = kwargs['intf_file']
        else:
            op_file = "/etc/network/interfaces.d/50-cloud-init.cfg"
            if check_default_interface_file():
                op_file = "/etc/network/interfaces"
        with open(op_file, "a+") as fp_o:
            fp_o.write("\n")
            fp_o.write("# Bridge {name}\n".format(name=ifname))
            fp_o.write("auto {name}\n".format(name=ifname))
            fp_o.write("allow-ovs {name}\n".format(name=ifname))
            fp_o.write("iface {name} inet static\n".format(name=ifname))
            fp_o.write("    address {addr}\n".format(addr=addr))
            fp_o.write("    netmask {mask}\n".format(mask=mask))
            if defroute is True:
                fp_o.write("    gateway {gw}\n".format(gw=gw))
            fp_o.write("    cp_gateway {gw}\n".format(gw=gw))
            fp_o.write("    ovs_type OVSBridge\n")
            fp_o.write("    ovs_ports {ports}\n"
                       .format(ports=kwargs['source_intf']))
            for key, value in list(kwargs.items()):
                if key != 'intf_file' and key != 'source_intf' and \
                   key != 'defroute' and key != 'inet_type':
                    if key == 'gateway' and not defroute:
                        continue
                    if type(value) is list:
                        fp_o.write("    {key} {value}\n"
                                   .format(key=key, value=" ".join(value)))
                    elif type(value) is str:
                        fp_o.write("    {key} {value}\n".format(key=key,
                                                                value=value))

    def _write_net_config_bridged_iface_br(self, ifname, **kwargs):
        """ write the configuration bridged interface for native juju
        Linux bridge
        kwargs {"defroute" : T|F",
                "bridge_name: "bridge name",
               }
        """
        if "bridge_name" not in kwargs:
            raise ValueError("{name} interface needs bridge_name".
                             format(name=ifname))
        op_file = "/etc/network/interfaces.d/50-cloud-init.cfg"
        if check_default_interface_file():
            op_file = "/etc/network/interfaces"

        with open(op_file, "a+") as fp_o:
            fp_o.write("\n")
            fp_o.write("# Interface {name}\n".format(name=ifname))
            fp_o.write("allow-{bridge_name} {name} \n"
                       .format(bridge_name=kwargs['bridge_name'], name=ifname))
            fp_o.write("iface {name} inet manual\n".format(name=ifname))
            fp_o.write("    ovs_type OVSPort\n")
            fp_o.write("    ovs_bridge {bridge}\n"
                       .format(bridge=kwargs['bridge_name']))
            for key, value in list(kwargs.items()):
                if key != 'inet_type' and key != 'address':
                    if type(value) is list:
                        fp_o.write("    {key} {value}\n"
                                   .format(key=key, value=" ".join(value)))
                    elif type(value) is str:
                        fp_o.write("    {key} {value}\n"
                                   .format(key=key, value=value))

    def write_net_config(self, iftype, ifname, addr, mask, gw, **kwargs):
        if iftype == "bridge":
            self._write_net_config_bridge(ifname, addr, mask, gw, **kwargs)
        elif iftype == "iface":
            self._write_net_config_iface(ifname, addr, mask, gw, **kwargs)
        elif iftype == "bridged_iface":
            self._write_net_config_bridged_iface(ifname, addr, mask, gw,
                                                 **kwargs)

    def del_net_config(self, ifname):
        """ Delete the configuration for the specified intf. """
        self.extract_net_config(ifname, backup=False)

    def _write_net_config_bridged_iface(self, ifname, addr, mask, gw,
                                        **kwargs):
        """ write the configuration bridged interface
        kwargs {"defroute" : T|F",
                "bridge_name: "bridge name",
               }
        """
        if "defroute" in kwargs:
            defroute = kwargs["defroute"]
        else:
            defroute = False

        if "bridge_name" not in kwargs:
            raise ValueError("{name} interface needs bridge_name".
                             format(name=ifname))

        if "intf_file" in kwargs:
            op_file = kwargs['intf_file']
        else:
            op_file = "/etc/network/interfaces.d/50-cloud-init.cfg"
            if check_default_interface_file():
                op_file = "/etc/network/interfaces"
        with open(op_file, "a+") as fp_o:
            fp_o.write("\n")
            fp_o.write("# Interface {name}\n".format(name=ifname))
            fp_o.write("allow-{bridge_name} {name} \n"
                       .format(bridge_name=kwargs['bridge_name'], name=ifname))
            fp_o.write("iface {name} inet manual\n".format(name=ifname))
            fp_o.write("    ovs_type OVSPort\n")
            fp_o.write("    ovs_bridge {bridge}\n"
                       .format(bridge=kwargs['bridge_name']))
            for key, value in list(kwargs.items()):
                if key != 'intf_file' and key != 'source_intf' and \
                   key != 'defroute' and key != 'inet_type':
                    if key == 'gateway' and not defroute:
                        continue
                    if type(value) is list:
                        fp_o.write("    {key} {value}\n"
                                   .format(key=key, value=" ".join(value)))
                    elif type(value) is str:
                        fp_o.write("    {key} {value}\n"
                                   .format(key=key, value=value))

    def _write_net_config_iface(self, ifname, addr, mask, gw, **kwargs):
        """ write the configuration bridged interface
        kwargs {"defroute" : T|F",
                "inet_type: "dhcp or static",
               }
        """
        if "defroute" in kwargs:
            defroute = kwargs["defroute"]
        else:
            defroute = False

        if "inet_type" not in kwargs:
            raise ValueError("{name} interface needs inet_type".
                             format(name=ifname))

        if "intf_file" in kwargs:
            op_file = kwargs['intf_file']
        else:
            op_file = "/etc/network/interfaces.d/50-cloud-init.cfg"
            if check_default_interface_file():
                op_file = "/etc/network/interfaces"
        with open(op_file, "a+") as fp_o:
            fp_o.write("\n")
            fp_o.write("# Interface {name}\n".format(name=ifname))
            fp_o.write("auto {name} \n".format(name=ifname))
            fp_o.write("iface {name} inet {inet_type}\n"
                       .format(name=ifname, inet_type=kwargs['inet_type']))
            fp_o.write("    cp_gateway {gw}\n".format(gw=gw))
            if kwargs['inet_type'] == 'static':
                fp_o.write("    address {addr}\n".format(addr=addr))
                fp_o.write("    netmask {mask}\n".format(mask=mask))
                if defroute is True:
                    fp_o.write("    gateway {gw}\n".format(gw=gw))
                for key, value in list(kwargs.items()):
                    if key != 'intf_file' and key != 'source_intf' and \
                       key != 'defroute' and key != 'inet_type':
                        if key == 'gateway' and not defroute:
                            continue
                        if type(value) is list:
                            fp_o.write("    {key} {value}\n"
                                       .format(key=key, value=" ".join(value)))
                        elif type(value) is str:
                            fp_o.write("    {key} {value}\n"
                                       .format(key=key, value=value))

    def change_iface_config(self, ifname, field, value):
        """ Change the MTU of the interface
        """
        src_file = "/etc/network/interfaces.d/50-cloud-init.cfg"
        if check_default_interface_file():
            src_file = "/etc/network/interfaces"
        back_file = "/tmp/cp_interfaces_file.{dt}".format(
            dt=datetime.now().strftime("%m%d%Y%H%M%S"))

        save_file = "/etc/network/interfaces.cplane.old"
        if not os.path.exists(save_file):
            shutil.copy(src_file, save_file)
        # setup regex for checking of interface names.
        is_iface_stanza = 0
        re_comment = re.compile(r"^#")
        re_empty = re.compile(r"^\s*$")
        re_iface_stz = re.compile(r"^iface.*{name}(?!\.)".format(name=ifname))
        re_new_stz = re.compile(r"^iface|^mapping|^auto|^allow|^source")

        fp_read = open(src_file, "r")
        fp_bak = open(back_file, "w")

        for line in fp_read:
            # check for comment or empty line.
            if re_comment.match(line) or re_empty.match(line):
                fp_bak.write(line)
                continue

            if is_iface_stanza == 0:
                fp_bak.write(line)
                if re_iface_stz.match(line):
                    is_iface_stanza = 1
            elif is_iface_stanza == 1:
                self._extract_iface_param(line)
                for in_line in fp_read:
                    if re_new_stz.match(in_line) or re_comment.match(in_line) \
                       or re_empty.match(in_line):
                        break
                    else:
                        self._extract_iface_param(in_line)
                        continue
                if field == 'mtu':
                    self.config_params['mtu'] = int(value)
                elif field == 'tso':
                    if 'tso' in self.config_params:
                        self.config_params['tso'][4] = str(value)
                    else:
                        self.config_params['tso'] = ['/sbin/ethtool',
                                                     '-K', '{}'.format(ifname),
                                                     'tso',
                                                     '{}'.format(value)]

                elif field == 'gso':
                    if 'gso' in self.config_params:
                        self.config_params['gso'][4] = value
                    else:
                        self.config_params['gso'] = ['/sbin/ethtool',
                                                     '-K', '{}'.format(ifname),
                                                     'gso',
                                                     '{}'.format(value)]

                elif field == 'rx':
                    if 'rx' in self.config_params:
                        self.config_params['rx'][4] = value
                    else:
                        self.config_params['rx'] = ['/sbin/ethtool',
                                                    '-K', '{}'.format(ifname),
                                                    'rx',
                                                    '{}'.format(value)]

                elif field == 'tx':
                    if 'tx' in self.config_params:
                        self.config_params['tx'][4] = value
                    else:
                        self.config_params['tx'] = ['/sbin/ethtool',
                                                    '-K', '{}'.format(ifname),
                                                    'tx',
                                                    '{}'.format(value)]

                elif field == 'sg':
                    if 'sg' in self.config_params:
                        self.config_params['sg'][4] = value
                    else:
                        self.config_params['sg'] = ['/sbin/ethtool',
                                                    '-K', '{}'.format(ifname),
                                                    'sg',
                                                    '{}'.format(value)]

                elif field == 'ufo':
                    if 'ufo' in self.config_params:
                        self.config_params['ufo'][4] = value
                    else:
                        self.config_params['ufo'] = ['/sbin/ethtool',
                                                     '-K', '{}'.format(ifname),
                                                     'ufo',
                                                     '{}'.format(value)]

                elif field == 'gro':
                    if 'gro' in self.config_params:
                        self.config_params['gro'][4] = value
                    else:
                        self.config_params['gro'] = ['/sbin/ethtool',
                                                     '-K', '{}'.format(ifname),
                                                     'gro',
                                                     '{}'.format(value)]

                elif field == 'lro':
                    if 'lro' in self.config_params:
                        self.config_params['lro'][4] = value
                    else:
                        self.config_params['lro'] = ['/sbin/ethtool',
                                                     '-K', '{}'.format(ifname),
                                                     'lro',
                                                     '{}'.format(value)]

                for key, value in list(self.config_params.items()):
                    if type(value) is list:
                        if key == 'tso' or key == 'gso' or key == 'rx' or \
                           key == 'tx' or key == 'sg' or key == 'ufo' or \
                           key == 'gro' or key == 'lro':
                            if value[-1] == 'on':
                                continue
                            else:
                                fp_bak.write("    {key} {value}\n"
                                             .format(key='post-up',
                                                     value=" ".
                                                     join(value)))
                        else:
                            fp_bak.write("    {key} {value}\n"
                                         .format(key=key,
                                                 value=" ".join(value)))
                    elif type(value) is str:
                        fp_bak.write("    {key} {value}\n".format(key=key,
                                     value=value))
                    elif type(value) is int:
                        fp_bak.write("    {key} {value}\n".format(key=key,
                                     value=value))
                if re_new_stz.match(in_line) or re_comment.match(in_line) or \
                   re_empty.match(in_line):
                    fp_bak.write(in_line)
                is_iface_stanza = 2
                continue
            else:
                fp_bak.write(line)
                continue

        fp_read.close()
        fp_bak.close()
        shutil.move(back_file, src_file)


def check_default_interface_file():
    with open('/etc/network/interfaces', 'r') as file:
        if "source /etc/network/interfaces.d" in file.read():
            return False
        else:
            return True
