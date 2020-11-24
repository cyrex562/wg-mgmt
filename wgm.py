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
import yaml
from dataclasses import dataclass

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
    ADD_PEER = "add-peer"
    CREATE_INTERFACE = "create-interface"
    SAVE_INTERFACE = "save-interface"
    DELETE_PEER = "delete-peer"
    DELETE_INTERFACE = "delete-interface"
    GENERATE_QR_CODE = "generate-qr-code"
    INVALID = "invalid"

    def __repr__(self) -> str:
        return str(self.value)
    
    def __str__(self) -> str:
        return str(self.value)

@dataclass
class AppContext:
    interface_name: str
    wg_path: str
    config_file_path: str
    qrencode_path: str
    quiet: bool
    verbose: bool
    command: str
    server_private_key: str
    server_listen_port: int
    server_addresses: List[str]
    server_networks: List[str]
    server_endpoint: str
    server_allowed_ips: List[str]
    server_keepalive: int
    server_description: str
    peer_endpoint: str
    peer_allowed_ips: List[str]
    peer_keepalive: int
    peer_public_key: str
    peer_listen_port: int
    peer_private_key: str
    peer_networks: List[str]
    peer_description: str

class Peer:
    def __init__(
            public_key: str = "",
            private_key: str = "",
            peer_addresses: List[str] = None,
            peer_networks: List[str] = None,
            server_keepalive: int = 0,
            peer_keepalive: int = 0,
            server_allowed_ips: List[str] = None,
            peer_allowed_ips: List[str] = None,
            peer_description: str = "",
            server_endpoint: str = "",
            peer_endpoint: str = "",
            peer_listen_port: int = 0
    ):
        self.public_key = public_key
        self.private_key = private_key
        if peer_addresses is None:
            self.peer_addresses = []
        else:
            self.peer_addresses = peer_addresses
        if peer_networks is None:
            self.peer_networks = []
        else:
            self.peer_networks = peer_networks
        self.server_keepalive = server_keepalive
        self.peer_keepalive = peer_keepalive
        if server_allowed_ips is None:
            self.server_allowed_ips = []
        else:
            self.server_allowed_ips = server_allowed_ips
        if peer_allowed_ips is None:
            self.peer_allowed_ips = []
        else:
            self.peer_allowed_ips = peer_allowed_ips
        self.peer_description = peer_description
        self.server_endpoint = server_endpoint
        self.peer_endpoint = peer_endpoint
        self.peer_listen_port = peer_listen_port


class Interface:
    def __init__(
            self, name: str = "", 
            description: str = "", 
            addresses: List[str] = None, 
            networks: List[str] = None, 
            private_key: str = "", 
            listen_port: int = 0, 
            peers: List[Peer] = None):
        self.name = name
        self.description = description
        if addresses is None:
            self.addresses = []
        else:
            self.addresses = addresses
        if networks is None:
            self.networks = []
        else:
            self.networks = networks
        self.private_key = private_key
        self.listen_port = listen_port
        if peers is None:
            self.peers = []
        else:
            self.peers = peers



class Config:
    def __init__(self, 
            interfaces: List[Interface] = None):
        if interfaces is not None:
            self.interfaces = interfaces
        else:
            self.interfaces = []

def config_from_dict(in_config: Dict) -> Config:
    out_config = Config()
    for interface in in_config["interfaces"]:
        out_interface = Interface(
            name = interface["name"],
            description = interface["description"],
            addresses = interface["addresses"],
            private_key = interface["private_key"],
            listen_port = interface["listen_port"]
        )
        for peer in interface["peers"]:
            out_peer = Peer(
                public_key =  peer["public_key"],
                private_key = peer["private_key"],
                peer_addresses = peer["peer_addresses"],
                peer_networks = peer["peer_networks"],
                server_keepalive = peer["server_keepalive"],
                peer_keepalive = peer["peer_keepalive"],
                server_allowed_ips = peer["server_allowed_ips"],
                peer_allowed_ips = peer["peer_allowed_ips"],
                peer_description = peer["peer_description"],
                server_endpoint = peer["server_endpoint"],
                peer_endpoint = peer["peer_endpoint"],
                peer_listen_port = peer["peer_listen_port"]
            )
            out_interface.peers.append(out_peer)
        out_config.interfaces.append(out_interface)
    return out_config

def dict_from_config(in_config: Config) -> Dict:
    out_config = {"interfaces": []}
    for interface in in_config.interfaces:
        out_interface = {
            "name": interface.name,
            "description": interface.description,
            "addresses": interface.addresses,
            "private_key": interface.private_key,
            "listen_port": interface.listen_port,
            "peers": []}
        for peer in interface.peers:
            out_peer = {
                "public_key": peer.public_key,
                "private_key": peer.private_key,
                "peer_addresses": peer.peer_addresses,
                "peer_networks": peer.peer_networks,
                "server_keepalive": peer.server_keepalive,
                "peer_keepalive": peer.peer_keepalive,
                "server_allowed_ips": peer.server_keepalive,
                "peer_allowed_ips": peer.peer_allowed_ips,
                "peer_description": peer.peer_description,
                "peer_endpoint": peer.peer_endpoint,
                "server_endpoint": peer.server_endpoint,
                "peer_listen_port": peer.peer_listen_port
            }
            out_interface["peers"].append(out_peer)
        out_config["interfaces"].append(out_interface)
    return out_config


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

def get_available_ips(opts: Namespace) -> Dict[ipaddress.IPv4Network, ipaddress.IPv4Address]:
    LOG.debug("getting available addresses")
    addr_map = get_assigned_addresses(opts)

    available_addrs = {}
    for net in addr_map.keys():
        addr_list = addr_map[net]
        for host in net.hosts():
            if host not in addr_list:
                available_addrs[net] = host
                break

    LOG.debug("available addresses=%s", available_addrs)
    return available_addrs

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


def gen_private_key(ctx: AppContext) -> str:
    """

    """
    LOG.debug("generating private key")
    if ctx.server_private_key != "":
        return ctx.server_private_key
    private_key_raw = subprocess.check_output([ctx.wg_path, "genkey"])
    private_key = private_key_raw.decode("utf-8").strip()
    LOG.debug("private key=%s...", private_key[1:5])
    return private_key


def parse_args() -> AppContext:
    """
    """
    p = argparse.ArgumentParser()
    p.add_argument("command", metavar="COMMAND", type=Command, choices=list(Command))
    p.add_argument(
        "--config-file", 
        required=True, 
        help="(required) config file path.",
        dest="config_file")
    p.add_argument(
        "--wg-path", 
        help=f"(optional) wg binary path; default: {DFLT_WG_BINARY}", 
        default=DFLT_WG_BINARY, 
        dest="wg_path",
        metavar="/PATH/TO/WG")
    p.add_argument(
        "--qrencode-path", 
        help=f"(optional) qrencode path; default={DFLT_QRENCODE}", default=DFLT_QRENCODE)
    p.add_argument(
        "--interface", 
        help="name of the wireguard interface", 
        metavar="IFC_NAME", 
        required=True, 
        dest="interface_name")
    p.add_argument(
        "--quiet", 
        help="output only warning and error messages", 
        action="store_true")
    p.add_argument(
        "--verbose", 
        help="output debug-level messages", 
        action="store_true")
    p.add_argument(
        "--server-listen-port", 
        help=f"(optional) server listen port; default: {DFLT_PORT}", 
        default=DFLT_PORT, 
        dest="server_listen_port")
    p.add_argument(
        "--server-addresses", 
        dest="server_addresses", 
        nargs="*", 
        metavar="X.X.X.X",
        help="(required) comma-separated list of IPv4 addresses",
        default=[])
    p.add_argument(
        "--server-allowed-ips", 
        dest="server_allowed_ips", 
        nargs="*", 
        metavar="X.X.X.X/Y",
        help="(required) comma-separated list of allowed IPs/Networks",
        default=[])
    p.add_argument(
        "--server-networks", 
        dest="server_networks", 
        nargs="*", 
        metavar="X.X.X.Y/Z",
        help="(required) comma-separated list of server networks",
        default=[])
    p.add_argument(
        "--server-description", 
        dest="server_description",
        help="(optional) server description",
        default="")
    p.add_argument(
        "--server-private-key",
        dest="server_private_key",
        help="(optional) server's private key",
        default="")
    p.add_argument(
        "--server-keepalive", 
        dest="server_keepalive",
        help=f"(optional) servers' keepalive interval; default={DFLT_KEEPALIVE}",
        metavar="SECS",
        type=int,
        default=DFLT_KEEPALIVE)
    p.add_argument(
        "--peer-listen-port", 
        dest="peer_listen_port",
        default=DFLT_PORT,
        type=int,
        help=f"(optional) peer listen port; default={DFLT_PORT}")
    p.add_argument(
        "--peer-adresses", 
        dest="peer_addresses", 
        nargs="*",
        metavar="X.X.X.X",
        help="(optional) comma-separated list of peer IP addresses",
        default=[])
    p.add_argument(
        "--peer-networks", 
        dest="peer_networks", 
        nargs="*",
        metavar="X.X.X.Y/Z",
        help="(optional) comma-separated list of peer networks",
        default=[])
    p.add_argument(
        "--peer-allowed_ips", 
        dest="peer_allowed_ips", 
        nargs="*",
        default=[],
        metavar="X.X.X.X/Y",
        help="(optional) comma-separated list of peer allowed_ips")
    p.add_argument(
        "--peer-keepalive", 
        dest="peer_keepalive",
        metavar="SECS",
        default=DFLT_KEEPALIVE,
        type=int,
        help=f"(optional) peer keep-alive interval; default={DFLT_KEEPALIVE}")
    p.add_argument(
        "--peer-public-key", 
        dest="peer_public_key",
        help="(required) peer public key",
        default=[])
    p.add_argument(
        "--peer-private-key",
        dest="peer_private_key",
        metavar="PRVIATE_KEY",
        default="",
        help="(optional) peer private key"
    )
    p.add_argument(
        "--peer-description", 
        dest="peer_description",
        help="(optional) peer description",
        default="")
    p.add_argument(
        "--server-endpoint",
        dest="server_endpoint",
        help="(required) server endpoint",
        metavar="X.X.X.X:Y",
        default = ""
    )
    p.add_argument(
        "--peer-endpoint",
        dest="peer_endpoint",
        help="(optional) peer endpoint",
        metavar="X.X.X.X:Y",
        default = ""
    )

    args = p.parse_args()
    ctx = AppContext(
        interface_name=args.interface_name,
        wg_path=args.wg_path,
        config_file_path=args.config_file,
        qrencode_path=args.qrencode_path,
        quiet=args.quiet,
        verbose=args.verbose,
        command=args.command,
        server_private_key=args.server_private_key,
        server_listen_port=args.server_listen_port,
        server_addresses=args.server_addresses,
        server_networks=args.server_networks,
        server_keepalive=args.server_keepalive,
        server_description=args.server_description,
        server_allowed_ips=args.server_allowed_ips,
        server_endpoint=args.server_endpoint,
        peer_endpoint=args.peer_endpoint,
        peer_allowed_ips=args.peer_allowed_ips,
        peer_keepalive=args.peer_keepalive,
        peer_public_key=args.peer_public_key,
        peer_listen_port=args.peer_listen_port,
        peer_private_key=args.peer_private_key,
        peer_networks=args.peer_networks,
        peer_description=args.peer_description)
    return ctx

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

def create_interface(ctx: AppContext, config: Config) -> Config:
    """

    """
    ifc_config_path = f"/etc/wireguard/{ctx.interface_name}.conf"
    if os.path.exists(ifc_config_path):
        raise ValueError(f"config file at path {ifc_config_path} already exists")
    
    curr_interfaces = config.interfaces
    for interface in curr_interfaces:
        if interface.name == ctx.interface_name:
            raise ValueError(f"interface \"{ctx.interface_name}\" already exists in config file")

    new_ifc = Interface(name = ctx.interface_name,
            private_key=gen_private_key(ctx))

    # private key
    ifc_key_path = f"/etc/wireguard/{new_ifc.name}.key"

    # addresses
    if len(ctx.server_addresses) == 0:
        raise ValueError("no server addresses specified")
    addresses_config_field = ""
    count = 0
    for addr in ctx.server_addresses:
        if count > 0:
            addresses_config_field += ", "
        addresses_config_field += addr
        new_ifc.addresses.append(addr)
        count += 1

    # listen port
    new_ifc.listen_port = ctx.server_listen_port

    # template
    template = f"""
[Interface]
PrivateKey = {new_ifc.private_key}
ListenPort = {new_ifc.listen_port}
Address = {addresses_config_field}
    """

    with open(ifc_config_path, "w") as fd:
        fd.write(template)
    
    with open(ifc_key_path, "w") as fd:
        fd.write(new_ifc.private_key)
        
    enable_wg_quick(new_ifc.name)

    start_wg_quick(new_ifc.name)

    config.interfaces.append(new_ifc)

    return config


def delete_interface(ctx: AppContext, config: Config) -> Config:
    # stop the service
    stop_wg_quick(ctx.interface_name)

    # disable the service
    disable_wg_quick(ctx.interface_name)

    # delete the link
    # delete_link(opts.interface_name)

    # delete the config file
    delete_config_file(ctx.interface_name)

    # delete the key
    delete_private_key_file(ctx.interface_name)

    # remove the element from the config object
    for i in range(0, len(config.interfaces)):
        if config.interfaces[i].name == ctx.interface_name:
            config.interfaces.pop(i)
            break

    return config


def gen_peer_addresses(opts: Namespace) -> str:
    out: str = ""
    if len(opts.addresses) > 0:
        count = 0
        for addr in opts.addresses:
            if count > 0:
                out += ", "
            out += f"{addr}"
            count += 1

        peer_addresses = f"{opts.adresses[0]}"
        for ad in opts.addresses[1:]:
            peer_addresses += f", {ad}"
    else:
        avail_addrs = get_available_ips(opts)

        count = 0
        for net, addr in avail_addrs.items():
            if count > 0:
                out += ", "
            out += f"{addr.exploded}/{net.prefixlen}"
            count += 1

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


def load_config_file(ctx: AppContext) -> Dict:
    """
    """
    LOG.debug("loading config file")
    if os.path.exists(ctx.config_file_path):
        stream = open(ctx.config_file_path, "r")
        doc = yaml.load(stream)
        stream.close()
    else:
        doc = {"interfaces": []}
    return doc

def save_config_file(ctx: AppContext, config: Config):
    """
    """
    LOG.debug("saving config file")
    with open(ctx.config_file_path, 'w') as fd:
        data = dict_from_config(config)
        out = yaml.dump(data)
        fd.write(out)


def main() -> int:
    """
    """
    ctx: AppContext = parse_args()
    if ctx.verbose is True:
        LOG.setLevel(logging.DEBUG)
    if ctx.quiet is True:
        LOG.setLevel(logging.WARN)
 
    LOG.debug("command=%s", ctx.command)

    config_doc = load_config_file(ctx)
    config: Config = config_from_dict(config_doc)

    if ctx.command == Command.CREATE_INTERFACE:
        config =create_interface(ctx, config)
    elif ctx.command == Command.DELETE_INTERFACE:
        config = delete_interface(ctx, config)
    elif ctx.command == Command.ADD_PEER:
        config = add_peer(ctx, config)
    elif ctx.command == Command.DELETE_PEER:
        config = delete_peer(ctx, config)
    elif ctx.command == Command.SAVE_INTERFACE:
        config = wg_quick_save_ifc(ctx, config)
    else:
        pass
    
    save_config_file(ctx, config)


    return 0


if __name__ == "__main__":
    sys.exit(main())
