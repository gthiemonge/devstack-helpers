#!/usr/bin/env python

from __future__ import print_function
import openstack
import os
import time
import yaml
import sys

def config_from_env():
    config = {}
    for k in ('auth_url', 'project_name', 'username',
              'password', 'region_name'):
        v = os.environ.get('OS_%s' % (k.upper()))
        config[k] = v
    return config

def neutron_print_status(conn):
    status = {
        'networks': {},
        'routers': {}
    }

    for n in conn.network.networks():
        n_status = {
            'id': n.id,
            'mtu': n.mtu,
            'name': n.name,
            'provider_network_type': n.provider_network_type,
            'provider_physical_network': n.provider_physical_network,
            'provider_segmentation_id': n.provider_segmentation_id,
            'subnets': {},
            'ports': [],
        }
        for s_id in n.subnet_ids:
            s = conn.network.get_subnet(s_id)
            d = {
                'id': s.id,
                'name': s.name,
                'cidr': s.cidr,
                'gateway_ip': s.gateway_ip,
                'prefix_length': s.prefix_length,
                'segment_id': s.segment_id,
                'host_routes': s.host_routes,
                'dns_nameservers': s.dns_nameservers,
            }
            if s.ip_version == 6:
                d['ipv6_address_mode'] = s.ipv6_address_mode
                d['ipv6_ra_mode'] = s.ipv6_ra_mode
            else:
                d['dhcp_enabled'] = s.is_dhcp_enabled

            n_status['subnets'][s.name] = d
        for p in conn.network.ports(network_id=n.id):
            ip_addresses = [a['ip_address'] for a in p.fixed_ips]
            p_status = {
                'id': p.id,
                'name': p.name,
                'ip_addresses': ip_addresses,
                'mac_address': p.mac_address,
            }
            n_status['ports'].append(p_status)

        status['networks'][n.name] = n_status

    for r in conn.network.routers():
        r_status = {
            'id': r.id,
            'external_gateway_info': r.external_gateway_info,
            'name': r.name,
            'routes': r.routes,
            'status': r.status,
            'interfaces': [],
        }

        for p in conn.network.ports(device_id=r.id):
            p_status = {
                'id': p.id,
                'name': p.name,
                'fixed_ips': p.fixed_ips,
                'mac_address': p.mac_address,
            }
            r_status['interfaces'].append(p_status)

        status['routers'][r.name] = r_status

    print(yaml.safe_dump(status, default_flow_style=False))

def wait_for_lb(lb):
    print("Waiting for %s (%s) to be active" % (lb.name, lb.id), end='')
    sys.stdout.flush()
    while range(0, 120):
        lb = conn.load_balancer.get_load_balancer(lb)
        print(".", end='')
        sys.stdout.flush()
        if lb.provisioning_status == 'ACTIVE':
            print("")
            break
        time.sleep(1)
    else:
        print(lb)
        raise Exception("")

openstack.enable_logging()

conn = openstack.connect(**config_from_env())

neutron_print_status(conn)
sys.exit(0)
