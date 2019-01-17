import os
import logging
from optparse import OptionParser
import urllib
import urllib2
import json
import hashlib
import urlparse

from charmhelpers.core.host import (
    mkdir,
)

from charmhelpers.core.hookenv import (
    status_set,
    config,
    log as juju_log,
)

CHARM_LIB_DIR = os.environ.get('CHARM_DIR', '') + "/lib/"


class ErrorException(Exception):
    pass


class CPlanePackageManager:
    def __init__(self, url):
        self._create_log()
        self.package_url = url
        if self.package_url.endswith(".json"):
            self.package_url += "?dl=1"
        self.package_data = {}
        self._get_pkg_json()

    def _create_log(self):
        log_file = os.path.join(os.path.abspath(os.path.dirname(__file__)),
                                "cp-package-manager.log")
        logging.basicConfig(filename=log_file,
                            format='%(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)
        logging.info("Writing to log file : %s" % log_file)

    def _validate_json(self, data):
        try:
            return json.loads(data)
        except ValueError as e:
            msg = "JSON Error: {}".format(e.message)
            status_set('blocked', msg)
            raise ErrorException(msg)

    def _get_pkg_json(self):
        url = self.package_url
        response = None
        proxies = {}
        if config('http-proxy'):
            proxies['http'] = config('http-proxy')
        if config('https-proxy'):
            proxies['https'] = config('https-proxy')
        try:
            if not proxies:
                response = urllib.urlopen(url)
            else:
                proxy = urllib2.ProxyHandler(proxies)
                opener = urllib2.build_opener(proxy)
                urllib2.install_opener(opener)
                response = urllib2.urlopen(url)
        except IOError:
            msg = "Invalid URL: URL metioned for Cplane binaries is not valid"
            status_set('blocked', msg)
            raise ErrorException(msg)

        logging.info("Package url:%s" % url)
        data = self._validate_json(response.read())
        if not data.get("{}".format(config("cplane-version"))):
            msg = "Invalid Cplane version: Invallid Cplane \
version {}".format(config("cplane-version"))
            status_set('blocked', msg)
            raise ErrorException(msg)

        if not data.get("{}".format(config("cplane-version")),
                        {}).get("ubuntu"):
            msg = "Invalid Linux flavour: Cplane binaries for Ubuntu not found"
            status_set('blocked', msg)
            raise ErrorException(msg)

        if not data.get("{}".format(config("cplane-version")),
                        {}).get("ubuntu",
                                {}).get(config("ubuntu-release-json")):
            msg = "Invalid OS versions: Cplane version for \
Ubuntu vesion {} not found".format(config("ubuntu-release-json"))
            status_set('blocked', msg)
            raise ErrorException(msg)

        if not data.get("{}".format(config("cplane-version")),
                        {}).get("ubuntu",
                                {}).get(config("ubuntu-release-json"),
                                        {}).get(config("openstack-version")):
            msg = "Invalid Openstack version: Cplane version for \
Openstack version {} not found".format(config("openstack-version"))
            status_set('blocked', msg)
            raise ErrorException(msg)
        self.package_data = data.get("{}".format(config("cplane-version")),
                                     {}).get("ubuntu",
                                             {}).get(config("ubuntu-release\
-json"),
                                                     {}).get(config("openstack\
-version"))

    def verify_file_checksum(self, file_name, file_md5sum):
        hash_md5 = hashlib.md5()
        with open(file_name, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)

        local_md5 = hash_md5.hexdigest()
        if local_md5 == file_md5sum:
            return True
        return False

    def download_package(self, package_name, version):
        version = int(version)
        if package_name not in self.package_data:
            msg = "Invalid Package: Package {} is not found in the \
Cplane repo".format(package_name)
            status_set('blocked', msg)
            raise ErrorException(msg)

        package_list = self.package_data.get(package_name)
        version_exist = False
        package_dwnld_link = ""
        file_checksum = ""
        if int(version) != -1:
            for package in package_list:
                if package.get("build_nr", 0) == int(version):
                    package_dwnld_link = package.get("dwd_link", "")
                    file_checksum = package.get("checksum", "")
                    version_exist = True
                    logging.info("Package download link %s" %
                                 package_dwnld_link)
                    break
        else:
            package_dwnld_link = package_list[-1].get("dwd_link", "")
            file_checksum = package_list[-1].get("checksum", "")
            version_exist = True
            logging.info("Package download link %s" % package_dwnld_link)

        if not version_exist:
            msg = "Invalid Version: Version {} doesn't exist for \
package {}".format(version, package_name)
            status_set('blocked', msg)
            raise ErrorException(msg)

        mkdir(CHARM_LIB_DIR)
        filename = urlparse.urlsplit(package_dwnld_link).path
        dwnld_package_name = os.path.join(CHARM_LIB_DIR,
                                          os.path.basename(filename))
        proxies = {}
        if config('http-proxy'):
            proxies['http'] = config('http-proxy')
        if config('https-proxy'):
            proxies['https'] = config('https-proxy')
        if not proxies:
            urllib.urlretrieve(package_dwnld_link, dwnld_package_name)
        else:
            proxy = urllib2.ProxyHandler(proxies)
            opener = urllib2.build_opener(proxy)
            urllib2.install_opener(opener)
            dwnldfile = urllib2.urlopen(package_dwnld_link)
            with open(dwnld_package_name, 'wb') as output:
                output.write(dwnldfile.read())

        if self.verify_file_checksum(dwnld_package_name, file_checksum):
            juju_log("Package %s downloaded successfully"
                     % dwnld_package_name)
        else:
            msg = "Invalid Checksum: Package {} checksum \
mismatch".format(dwnld_package_name)
            status_set('blocked', msg)
            raise ErrorException(msg)

        return dwnld_package_name


def get_opts_and_args(args):
    """
    Getting options and arguments passed to this script
    param args: in place system arguments sent to the script
    """
    parser = OptionParser()
    parser.add_option('-u', '--url',
                      action='store', dest='url',
                      help='JSON web page url')

    options, args = parser.parse_args()
    return options, args
