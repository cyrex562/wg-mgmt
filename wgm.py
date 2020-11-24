from argparse import Namespace
import os
import argparse
import ipaddress
import subprocess
from subprocess import CompletedProcess
import sys
from enum import Enum
import configparser
from typing import List, Dict, Set
import logging

DFLT_MTU = 1500
DFLT_KEEPALIVE = 25
DFLT_DNS = "1.1.1.1"
DLFT_ALLOWED_IPS = "0.0.0.0/0,::/0"
DFLT_WG_BINARY = "wg"
DFLT_QRENCODE = "qrencode"
DFLT_PORT = 51820

LOG = logging.getLogger()
stdout_handler = logging.StreamHandler(sys.stdout)
stdout_handler.setLevel(logging.DEBUG)
formatter = logging.Formatter("%(asctime)s: %(levelname)s: %(message)s", "%Y%b%d:%H%M:%S")
stdout_handler.setFormatter(formatter)
LOG.addHandler(stdout_handler)
LOG.setLevel(logging.INFO)

class Command(Enum):
    ADD = "add peer"
    CREATE = "create interface"
    SAVE = "save interface"
    REM_PEER = "remove peer"
    REM_IFC = "remove interface"
    QR = "generate qr code"


def get_server_addresses(ifc: str) -> List[ipaddress.IPv4Address]:
    LOG.debug("getting server addresses")
    config = configparser.ConfigParser()   
    ifc_config_path = f"/etc/wireguard/{ifc}.conf"
    config.read(ifc_config_path)
    addresses_field = config["Interface"]["Address"]
    addresses = []
    for v in addresses_field.split(","):
        host_addr = v.split("/")[0].strip()
        addresses.append(ipaddress.IPv4Address(host_addr))
    LOG.debug("addresses=%s", addresses)
    return addresses


def get_server_networks(ifc: str) -> Set[ipaddress.IPv4Network]:
    LOG.debug("getting server networks")
    config = configparser.ConfigParser()   
    ifc_config_path = f"/etc/wireguard/{ifc}.conf"
    config.read(ifc_config_path)
    addresses = config["Interface"]["Address"]
    addresses = [x.strip() for x in addresses.split(",")]
    nets = set()
    for a in addresses:
        net = ipaddress.IPv4Network(a, strict=False)
        nets.add(net)
    LOG.debug("server networks=%s", nets)
    return nets


def get_assigned_addresses(opts: Namespace, ) -> Dict[ipaddress.IPv4Network, List[ipaddress.IPv4Address]]:
    LOG.debug("getting current peer addresses")
    raw_cmd = subprocess.check_output(
        [opts.wg_path, "show", opts.interface_name, "allowed-ips"]
    )
    if len(raw_cmd) > 0:
        raw_lines = [x.strip for x in raw_cmd.decode("utf-8").split("\n")]
    else:
        raw_lines = []

    server_addrs = get_server_addresses(opts.interface_name)
    server_nets = get_server_networks(opts.interface_name)

    address_map = {}

    for net in server_nets:
        address_map[net] = []

    for net in address_map.keys():
        for srv_addr in server_addrs:
            if srv_addr in net:
                address_map[net].append(srv_addr)

    if len(raw_lines) > 0:
        addrs = []
        for rl in raw_lines:
            addrs = rl.split()[1:].strip()

        for addr in addrs:
            a = ipaddress.IPv4Address(addr.split("/")[0].strip())
            for net in address_map.keys():
                if a in net:
                    address_map[net].append(a)
    
    LOG.debug("peer addresses=%s", address_map)
    return address_map

def get_available_ips(opts: Namespace) -> List[ipaddress.IPv4Address]:
    LOG.debug("getting available addresses")
    addr_map = get_assigned_addresses(opts)

    available_addrs = []
    for net in addr_map.keys():
        addr_list = addr_map[net]
        for host in net.hosts():
            if host not in addr_list:
                available_addrs.append(host)
                break

    LOG.debug("available addresses=%s", available_addrs)
    return available_addrs
    
        

# def first_available_ip_from_subnet(args: object):
#     result = []
#     host_list = {}
#     taken_host_list = {}

#     subnets = list(map(lambda x: x.strip(), args.subnet.split(',')))
#     for subnet in subnets:
#         network = ipaddress.ip_network(subnet, strict=True)
#         if network.version == 4 or network.version == 6:
#             host_list[network.version] = network

#     raw_command = subprocess.check_output(
#         [args.wg_binary, 'show', args.wg_interface, 'allowed-ips'], stderr=sys.stdout)

#     raw_lines = raw_command.decode('utf-8').split('\n')
#     raw_lines = [x.split('\t')[1].split(' ') for x in raw_lines if x]
#     for line in raw_lines:
#         for ip in line:
#             parsed_ip = ipaddress.ip_network(ip, strict=True)[0]
#             if not parsed_ip.version in taken_host_list:
#                 taken_host_list[parsed_ip.version] = []

#             taken_host_list[parsed_ip.version].append(parsed_ip)

#     if 4 in host_list:
#         # Grab the first free ivp4 address
#         for ip in host_list[4].hosts():
#             if ip != host_list[4][0] and ip != host_list[4][1]:
#                 if 4 not in taken_host_list or ip not in taken_host_list[4]:
#                     result.append(str(ipaddress.ip_network(ip, strict=True)))
#                     break

#     if 6 in host_list:
#         # Grab the first free ivp6 address
#         for ip in host_list[6].hosts():
#             if ip != host_list[6][0] and ip != host_list[6][1]:
#                 if 6 not in taken_host_list or ip not in taken_host_list[6]:
#                     result.append(str(ipaddress.ip_network(ip, strict=True)))
#                     break

#     return ", ".join(result)

def get_public_key(opts: Namespace, private_key: str) -> str:
    LOG.debug("getting public key")
    pipe = subprocess.Popen(["echo", private_key], stdout=subprocess.PIPE)
    public_key_raw = subprocess.check_output(
        [opts.wg_path, "pubkey"], stdin=pipe.stdout)
    public_key = public_key_raw.decode("utf-8").strip()
    LOG.debug("public key=%s", public_key)
    return public_key

def get_listen_port(opts: Namespace) -> int:
    LOG.debug("getting listen port")
    result: CompletedProcess = subprocess.call([opts.wg_path, "show" f"{opts.interface_name}", "listen-port"])
    listen_port_raw = result.stdout.decode("utf-8").strip()
    listen_port = int(listen_port_raw)
    LOG.debug("listen port=%d", listen_port)
    return listen_port

def get_server_public_key(opts: Namespace) -> str:
    """

    """
    LOG.debug("getting server public key")
    public_key_raw = subprocess.check_output(
        [opts.wg_path, "show", opts.interface_name, 'public-key'])
    public_key = public_key_raw.decode("utf-8").strip()
    LOG.debug("server public key=%s", public_key)
    return public_key


def gen_private_key(opts: Namespace) -> str:
    """

    """
    LOG.debug("generating private key")
    if opts.private_key != "":
        return opts.private_key
    private_key_raw = subprocess.check_output([opts.wg_path, "genkey"])
    private_key = private_key_raw.decode("utf-8").strip()
    LOG.debug("private key=%s...", private_key[1:5])
    return private_key


def parse_args() -> Namespace:
    """
    """
    p = argparse.ArgumentParser()

    p.add_argument("--wg-path", help="specify the path of the wg binary. If not specified, than a default will be used", default=DFLT_WG_BINARY, dest="wg_path")
    
    p.add_argument("--qrencode-path", help="specify the path of the qrencode binary. If not specified, then a default will be used.", default=DFLT_QRENCODE)

    p.add_argument("-n", "--ifc-name", help="name of the wireguard interface", metavar="IFC_NAME", required=True, dest="interface_name")

    p.add_argument("-q", "--quiet", help="turn log level down to warnings and errors only", action="store_true")
    p.add_argument("-v", "--verbose", help="turn log level up to include debug messages", action="store_true")

    sp = p.add_subparsers(title="command", dest="command")

    # CREATE
    # arguments: interface name (r), private key (o), listen port (o), interface address/mask (r),  
    cp = sp.add_parser(name="create-ifc")

    cp.add_argument("-k", "--private-key", help="private key to use for the interface. If not specified, one will be generated", default="", dest="private_key")

    cp.add_argument("-p", "--listen-port", help="port for the interface to listen on. if not specified, default will be used", default=DFLT_PORT, dest="listen_port")

    cp.add_argument("-a", "--addresses", help="address for the interface in CIDR form", metavar="A.B.C.D/EF", required=True, nargs="*", default=[], dest="addresses")
    
    # DEL IFC
    # arguments: interface name (r)
    dip = sp.add_parser(name="del-ifc")

    # ADD PEER
    # arguments: interface name (r), peer private key (o), peer listen port (o), peer endpoint (o), allowed-ips (o), peer address/mask (o), keepalive interval (o)
    ap = sp.add_parser(name="add-peer")

    ap.add_argument("--private-key", help="private key for the peer. If not specified, one will be generated", default="")

    ap.add_argument("--listen-port", help="port for peer to listen on", default=DFLT_PORT, type=int)

    ap.add_argument("--peer-endpoint", help="endpoint address for the peer. If not specified, will not be added", default="", dest="peer_endpoint")

    ap.add_argument("--server-endpoint", help="endpoint address for the server", default="", dest="server_endpoint", required=True)

    ap.add_argument("-w", "--allowed-ips", nargs="*", help="list of allowed ips/networks. If not specified, default will be used", default=["0.0.0.0/0"])

    ap.add_argument("-a", "--addresses", help="address/netmask to use for peer. If not specified, one will be chosen based on the server's configuration", default=[], nargs="*")

    ap.add_argument("-t", "--keepalive", help="peer keepalive interval", default=DFLT_KEEPALIVE, type=int, metavar="SECS", dest="keepalive")

    # DEL PEER
    # arguments: interface name (r), peer public key (o)
    dp = sp.add_parser(name="del-peer")

    dp.add_argument("-k", "--public-key", required=True, help="the public key of the peer to remove", dest="public_key")

    # SAVE IFC
    # arguments: interface name (r)
    si = sp.add_parser(name="save-ifc")

    args = p.parse_args()
    return args

def generate_qrcode(opts: Namespace, config: str):
    """

    """
    pipe = subprocess.Popen(["echo", config], stdout=subprocess.PIPE)
    qrcode = subprocess.check_output(
        [opts.qrencode_path, "-t", "ANSIUTF8"], stdin=pipe.stdout)
    print(qrcode.decode("utf-8").strip())


def enable_wg_quick(ifc: str):
    subprocess.check_call(["systemctl", "enable", f"wg-quick@{ifc}"])


def start_wg_quick(ifc: str):
    subprocess.check_call(["systemctl", "start", f"wg-quick@{ifc}"])

def stop_wg_quick(ifc: str):
    subprocess.check_call(["systemctl", "stop", f"wg-quick@{ifc}"])

def disable_wg_quick(ifc: str):
    subprocess.check_call(["systemctl", "disable", f"wg-quick@{ifc}"])

def delete_link(ifc: str):
    subprocess.check_call(["ip", "link", "delete", ifc])

def delete_config_file(ifc: str):
    ifc_config_path = f"/etc/wireguard/{ifc}.conf"
    os.remove(ifc_config_path)

def delete_private_key_file(ifc: str):
    ifc_key_path = f"/etc/wireguard/{ifc}.key"
    os.remove(ifc_key_path)

def create_interface(opts: Namespace):
    """

    """
    ifc_config_path = f"/etc/wireguard/{opts.interface_name}.conf"
    if os.path.exists(ifc_config_path):
        raise ValueError(f"config file at path {ifc_config_path} already exists")
    
    ifc_key_path = f"/etc/wireguard/{opts.interface_name}.key"

    private_key = gen_private_key(opts)

    addresses = f"{opts.addresses[0]}"
    for ad in opts.addresses[1:]:
        addresses += f", {ad}"

    template = f"""
[Interface]
PrivateKey = {private_key}
ListenPort = {opts.listen_port}
Address = {addresses}
    """

    with open(ifc_config_path, "w") as fd:
        fd.write(template)
    
    with open(ifc_key_path, "w") as fd:
        fd.write(private_key)
        
    enable_wg_quick(opts.interface_name)

    start_wg_quick(opts.interface_name)


def delete_interface(opts: Namespace):
    # stop the service
    stop_wg_quick(opts.interface_name)

    # disable the service
    disable_wg_quick(opts.interface_name)

    # delete the link
    # delete_link(opts.interface_name)

    # delete the config file
    delete_config_file(opts.interface_name)

    # delete the key
    delete_private_key_file(opts.interface_name)


def gen_peer_addresses(opts: Namespace) -> str:
    out: str = ""

    avail_addrs = get_available_ips(opts)

    addr = avail_addrs[0]
    out = f"{addr.exploded}"
    if isinstance(addr, ipaddress.IPv4Address): 
        out += "/32"
    else:
        out += "/128"
    for addr in avail_addrs[1:]:
        out += f", {addr.exploded}"

        if isinstance(addr, ipaddress.IPv4Address): 
            out += "/32"
        else:
            out += "/128"

    return out



def add_peer(opts: Namespace):
    """

    """
    # get interface data
    server_public_key = get_server_public_key(opts)

    # get peer data
    peer_private_key = gen_private_key(opts)
    peer_public_key = get_public_key(opts, peer_private_key)

    # get address assignments for peer
    if len(opts.addresses) > 0:
        peer_addresses = f"{opts.adresses[0]}"
        for ad in opts.addresses[1:]:
            peer_addresses += f", {ad}"
    else:
        peer_addresses = gen_peer_addresses(opts)

    peer_allowed_ips = peer_addresses
    if len(opts.allowed_ips) > 1:
        for ap in opts.allowed_ips[1:]:
            peer_allowed_ips += f", {ap}"

    # generate peer config
    peer_config_template = f"""
[Interface]
PrivateKey = {peer_private_key}
ListenPort = {opts.listen_port}
Address = {peer_addresses}

[Peer]
PublicKey = {server_public_key}
Endpoint = {opts.server_endpoint}
PersistentKeepalive = {opts.keepalive}
AllowedIps = {peer_allowed_ips}
    """

    # add peer to interface
    subprocess.check_call(["wg", "set", opts.interface_name, "peer", peer_public_key, "persistent-keepalive", f"{opts.keepalive}", "allowed-ips", peer_allowed_ips])

    # print peer config
    print(peer_config_template)

def delete_peer(opts: Namespace):
    # get peer public key
    subprocess.check_call(["wg", "set", opts.interface_name, "peer", opts.public_key, "remove"])

def wg_quick_save_ifc(opts: Namespace):
    subprocess.check_call(["wg-quick", "save", opts.interface_name])

def main() -> int:
    opts: Namespace = parse_args()
    if opts.verbose is True:
        LOG.setLevel(logging.DEBUG)
    if opts.quiet is True:
        LOG.setLevel(logging.WARN)

    LOG.debug("command=%s", opts.command)

    if opts.command == "create-ifc":
        create_interface(opts)
    elif opts.command == "del-ifc":
        delete_interface(opts)
    elif opts.command == "add-peer":
        add_peer(opts)
    elif opts.command == "del-peer":
        delete_peer(opts)
    elif opts.command == "save-ifc":
        wg_quick_save_ifc(opts)
    else:
        pass
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
