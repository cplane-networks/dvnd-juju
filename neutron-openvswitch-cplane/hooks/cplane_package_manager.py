import os, sys, datetime
import logging
from optparse import OptionParser
import urllib, json
import hashlib
import urlparse
from charmhelpers.core.hookenv import (
    Hooks,
)

CHARM_LIB_DIR = os.environ.get('CHARM_DIR', '') + "/lib/"

class CPlanePackageManager:
    def __init__(self, url):
        self._create_log()
        self.package_url = url
        if self.package_url.endswith(".json"):
            self.package_url = self.package_url + "?dl=1"
        self.package_data = {}
        self._get_pkg_json()

    def _create_log(self):
        log_file = os.path.join(os.path.abspath(os.path.dirname(__file__)), "cp-package-manager.log")
        logging.basicConfig(filename=log_file, format='%(asctime)s %(message)s',
                            datefmt='%m/%d/%Y %I:%M:%S %p', level=logging.INFO)
        logging.info("Writing to log file : %s" % log_file)

    def _get_pkg_json(self):
        url = self.package_url
        response = urllib.urlopen(url)
        logging.info("Package url:%s" % url)
        data = json.loads(response.read())
        self.package_data = data.get("1.3.5", {}).get("ubuntu", {}).get("14.04", {}).get("liberty")

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
            logging.error("Package name %s doesn't exist" % package_name)
            return

        package_list = self.package_data.get(package_name)
        version_exist = False
        package_dwnld_link = ""
        file_checksum = ""
        for package in package_list:
            if package.get("build_nr", 0) == int(version):
                package_dwnld_link = package.get("dwd_link", "")
                file_checksum = package.get("checksum", "")
                version_exist = True
                logging.info("Package download link %s" % package_dwnld_link)
                break

        if not version_exist:
            logging.error("Version %d doesn't exist for package %s" % (version, package_name))
            return

        filename = urlparse.urlsplit(package_dwnld_link).path
        dwnld_package_name = os.path.join(CHARM_LIB_DIR, os.path.basename(filename))
        urllib.urlretrieve(package_dwnld_link, dwnld_package_name)

        if self.verify_file_checksum(dwnld_package_name, file_checksum):
            logging.info("Package %s downloaded successfully" % dwnld_package_name)
        else:
            logging.info("Package %s downloaded, but checksum mismatch" % dwnld_package_name)

        return dwnld_package_name 

def get_opts_and_args(args):
    """
    Getting options and arguments passed to this script
    param args: in place system arguments sent to the script
    """
    parser = OptionParser()
    parser.add_option('-u', '--url',
                      action='store', dest='url',
                      help='JSON web page url'
                      )

    options, args = parser.parse_args()
    return options, args

