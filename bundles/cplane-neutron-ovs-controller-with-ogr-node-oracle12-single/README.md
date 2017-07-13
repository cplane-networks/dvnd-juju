This bundle installs a CPLANE Multi-Site OPENSTACK Environment
Multi-Site OpenStack consists of the following environment.
- CPLANE Controller and DB (Oracle12c-single) on different hosts
- Run OpenStack Management and Data on separate vlan networks.
- OpenStack Controller with CPLANE Neutron Plugin
- OpenStack Compute Node with CPLANE OVS Compute node
- This bundle can only be deployed after signing a cplane license agreement with embedded oracle
- Oracle12c runs on a centos7 host
- Special OGR Compute Node on which OGR VMs can be deployed. Can be used with CPLANE Multi-Site Manger Product
- NOTE: OGR Nodes requires 4 physical NIC cards.
