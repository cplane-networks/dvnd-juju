This bundle installs a basic CPLANE OPENSTACK Environment
Simple OpenStack Stand-alone environment.
- CPLANE Controller and DB DB (12c RAC) running in 2-HA Cluster nodes 
- This bundle can only be deployed after signing a cplane license agreement with embedded oracle
- Oracle12c and RAC runs on a centos7 host
- Oracle RAC requires 3 shared volumes > 30G each (voting disks).  Host VM main volume requires 50G.   
- OpenStack Controller with CPLANE Neutron Plugin
- OpenStack Compute Node with CPLANE OVS Compute node
- No OGR Compute Node
