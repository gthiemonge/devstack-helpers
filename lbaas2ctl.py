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

def lbaasv2_print_status(conn):
    status = {}

    try:
        for a in conn.load_balancer.amphorae():
            a_status = {
                'vrrp_ip': a.vrrp_ip,
                'ha_ip': a.ha_ip,
                'lb_network_ip': a.lb_network_ip,
                'role': a.role,
                'status': a.status,
            }
            if a.name:
                a_status['name'] = a.name
            if 'amphorae' not in status:
                status['amphorae'] = {}
            status['amphorae'][a.name if a.name else a.id] = a_status
    except openstack.exceptions.HttpException as e:
        pass

    for lb in conn.load_balancer.load_balancers():
        lb_status = {
            'operating_status': lb.operating_status,
            'provisioning_status': lb.provisioning_status,
            'vip_address': lb.vip_address,
            'vip_port_id': lb.vip_port_id,
            'vip_subnet_id': lb.vip_subnet_id,
            'pools': {},
            'listeners': {}
        }
        for l in lb.listeners:
            listener = conn.load_balancer.get_listener(l['id'])
            d = {
                'operating_status': listener.operating_status,
                'provisioning_status': listener.provisioning_status,
                'protocol_port': listener.protocol_port,
                'protocol': listener.protocol,
            }
            lb_status['listeners'][listener.name] = d

        for p in lb.pools:
            pool = conn.load_balancer.get_pool(p['id'])
            d = {
                'operating_status': pool.operating_status,
                'provisioning_status': pool.provisioning_status,
                'protocol': pool.protocol,
                'lb_algorithm': pool.lb_algorithm,
                'session_persistence': pool.session_persistence,
                'members': {},
                'health_monitor': None
            }

            if pool.health_monitor_id is not None:
                hm = conn.load_balancer.get_health_monitor(pool.health_monitor_id)
                dh = {
                    'operating_status': hm.operating_status,
                    'provisioning_status': hm.provisioning_status,
                    'name': hm.name,
                    'type': hm.type
                }
                d['health_monitor'] = dh

            for m in pool.members:
                member = conn.load_balancer.get_member(m['id'], pool)
                dm = {
                    'operating_status': member.operating_status,
                    'provisioning_status': member.provisioning_status,
                    'address': member.address,
                    'protocol_port': member.protocol_port,
                    'monitor_address': member.monitor_address,
                    'subnet': member.subnet_id,
                }
                k = member.name if member.name != '' else member.id
                d['members'][k] = dm

            lb_status['pools'][pool.name] = d

        for ip in conn.network.ips(port_id=lb['vip_port_id']):
            lb_status['floating_ip'] = ip.floating_ip_address

        if 'loadbalancer' not in status:
            status['loadbalancer'] = {}
        status['loadbalancer'][lb.name] = lb_status

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

try:
    action = sys.argv[1]
except ValueError:
    action = None

if action == 'status':
    lbaasv2_print_status(conn)
    sys.exit(0)

if action == 'unstack':
    deleted_lbs = []

    for lb in conn.load_balancer.load_balancers():
        print("Deleting lb %s (%s) and its children." % (lb.name, lb.id))
        conn.load_balancer.delete_load_balancer(lb, cascade=True)
        deleted_lbs.append(lb.name)

    for name in deleted_lbs:
        while range(0, 120):
            lb = conn.load_balancer.find_load_balancer(name)
            if lb is None:
                break
            time.sleep(1)
        else:
            print(lb)
            raise Exception("")

    sys.exit(0)

if action != 'stack':
    sys.exit(1)

vip_ip_version = 6
members_ip_version = 4

subnet = conn.network.find_subnet('ipv%d-vip-subnet' % (vip_ip_version))

lb = conn.load_balancer.find_load_balancer('lb1')
if lb is None:
    print("Creating loadbalancer lb1.")
    lb = conn.load_balancer.create_load_balancer(
        name='lb1',
        vip_subnet_id=subnet.id,
    )
    wait_for_lb(lb)

else:
    print("Using existing loadbalancer lb1 (%s)" % (lb.id))

listener = conn.load_balancer.find_listener('listener1')
if listener is None:
    secret = None
    # find_secret doesn't seem to work
    #for s in conn.key_manager.secrets():
    #    if s.name == 'tls_secret1':
    #        secret = s
    #        break

    if secret == None:
        protocol = 'HTTP'
        port = 80
        default_tls_container_ref = None
    else:
        protocol = 'TERMINATED_HTTPS'
        port = 443
        default_tls_container_ref=secret.secret_ref

    print("Creating listener listener1.")
    listener = conn.load_balancer.create_listener(
        protocol=protocol,
        protocol_port=port,
        name='listener1',
        load_balancer_id=lb.id,
        default_tls_container_ref=default_tls_container_ref)

    wait_for_lb(lb)

pool = conn.load_balancer.find_pool('pool1')
if pool is None:
    print("Creating pool pool1.")
    pool = conn.load_balancer.create_pool(
        lb_algorithm='ROUND_ROBIN',
        listener_id=listener.id,
        protocol='HTTP',
        name='pool1')
    wait_for_lb(lb)

hm = conn.load_balancer.find_health_monitor('hm1')
if hm is None:
    print("Creating health monitor hm1.")
    hm = conn.load_balancer.create_health_monitor(
        name='hm1',
        delay=5,
        timeout=2,
        max_retries=1,
        type='HTTP',
        pool_id=pool.id)
    wait_for_lb(lb)


#for server in sorted(conn.compute.servers(), key=lambda s:s.name):
for server in conn.compute.servers():
    private_addr = [a for a in server.addresses.values()[0] if a['version'] == members_ip_version][0]

    network = server.addresses.keys()[0]
    subnet = conn.network.find_subnet('ipv%d-%s-subnet' % (members_ip_version,
                                                           network))

    member = None
    for m in conn.load_balancer.members(pool):
        if m.address == private_addr['addr']:
            print(m)
            member = m
            break

    if member is None:
        print("Creating member for %s." % (server.name))
        member = conn.load_balancer.create_member(
            pool,
            subnet_id=subnet.id,
            address=private_addr['addr'],
            protocol_port=80)

        wait_for_lb(lb)

if vip_ip_version == 4:
    net = conn.network.find_network('public')

    floating_ip_exists = False
    for _ in conn.network.ips(port_id=lb.vip_port_id):
        floating_ip_exists = True

    if not floating_ip_exists:
        ip = None
        for i in conn.network.ips():
            if i.port_id is None:
                ip = i
                ip = conn.network.update_ip(ip,
                                            port_id=lb.vip_port_id)
                break
        else:
            ip = conn.network.create_ip(
                floating_network_id=net.id,
                port_id=lb.vip_port_id
            )

lbaasv2_print_status(conn)
