This bundle installs a CPLANE Multi-Site OPENSTACK Environment
Multi-Site OpenStack consists of the following environment.
- CPLANE Controller and DB (12c RAC) running in 2-HA Cluster nodes 
- This bundle can only be deployed after signing a cplane license agreement with embedded oracle
- Oracle12c and RAC runs on a centos7 host
- Oracle RAC requires 3 shared volumes > 30G each (voting disks).  Host VM main volume requires 50G.   
- Run OpenStack Management and Data on separate vlan networks.
- OpenStack Controller with CPLANE Neutron Plugin
- OpenStack Compute Node with CPLANE OVS Compute node
- This bundle can only be deployed after signing a cplane license agreement with embedded oracle
- Oracle12c runs on a centos7 host
- Special OGR Compute Node on which OGR VMs can be deployed. Can be used with CPLANE Multi-Site Manger Product
- NOTE: OGR Nodes requires 4 physical NIC cards.