#!/bin/bash

set -e

KEYSTONE_IP=`juju status keystone/0 --format=yaml | grep public-address | awk '{ print $2 }'`
KEYSTONE_ADMIN_TOKEN=`juju ssh keystone/0 sudo cat /etc/keystone/keystone.conf | grep admin_token | sed -e '/^M/d' -e 's/.$//' | awk '{ print $3 }'`

echo "Keystone IP: [${KEYSTONE_IP}]"
echo "Keystone Admin Token: [${KEYSTONE_ADMIN_TOKEN}]"

cat << EOF > ./nova.rc
#export SERVICE_ENDPOINT=http://${KEYSTONE_IP}:35357/v3/
#export SERVICE_TOKEN=${KEYSTONE_ADMIN_TOKEN}
export OS_AUTH_URL=http://${KEYSTONE_IP}:35357/v3/
export OS_IDENTITY_API_VERSION=3
export OS_USERNAME=admin
export OS_PASSWORD=openstack
#export OS_TENANT_NAME=admin
export OS_PROJECT_DOMAIN_NAME=default 
export OS_USER_DOMAIN_NAME=default
export OS_PROJECT_NAME=admin


EOF

juju scp ./nova.rc neutron-api/0:
juju scp ./nova.rc nova-compute/0:
juju scp ./nova.rc nova-cloud-controller/0:
juju scp ./nova.rc cplane-compute/0:
juju scp ./nova.rc ogr-compute-cplane/0: