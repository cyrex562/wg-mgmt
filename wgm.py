import os
import io
import argparse
import configparser
import ipaddress
import subprocess
from subprocess import CompletedProcess
import sys
from dataclasses import dataclass
from enum import Enum
from typing import List

DFLT_MTU = 1500
DFLT_KEEPALIVE = 25
DFLT_DNS = "1.1.1.1"
DLFT_ALLOWED_IPS = "0.0.0.0/0,::/0"
DFLT_WG_BINARY = "wg"
DFLT_QRENCODE = "qrencode"
DFLT_PORT = 51820


class Command(Enum):
    ADD = "add peer"
    CREATE = "create interface"
    SAVE = "save interface"
    REM_PEER = "remove peer"
    REM_IFC = "remove interface"
    QR = "generate qr code"


@dataclass
class AppContext:
    private_key: str
    wg_binary: str
    endpoint: str
    address: str
    subnet: str
    dns: str
    keep_alive: int
    mtu: int
    allowed_ips: List[str]
    qrencode_binary: str
    wg_interface: str
    command: Command
    listen_port: int


def first_available_ip_from_subnet(args: object):
    result = []
    host_list = {}
    taken_host_list = {}

    subnets = list(map(lambda x: x.strip(), args.subnet.split(',')))
    for subnet in subnets:
        network = ipaddress.ip_network(subnet, strict=True)
        if network.version == 4 or network.version == 6:
            host_list[network.version] = network

    raw_command = subprocess.check_output(
        [args.wg_binary, 'show', args.wg_interface, 'allowed-ips'], stderr=sys.stdout)

    raw_lines = raw_command.decode('utf-8').split('\n')
    raw_lines = [x.split('\t')[1].split(' ') for x in raw_lines if x]
    for line in raw_lines:
        for ip in line:
            parsed_ip = ipaddress.ip_network(ip, strict=True)[0]
            if not parsed_ip.version in taken_host_list:
                taken_host_list[parsed_ip.version] = []

            taken_host_list[parsed_ip.version].append(parsed_ip)

    if 4 in host_list:
        # Grab the first free ivp4 address
        for ip in host_list[4].hosts():
            if ip != host_list[4][0] and ip != host_list[4][1]:
                if 4 not in taken_host_list or ip not in taken_host_list[4]:
                    result.append(str(ipaddress.ip_network(ip, strict=True)))
                    break

    if 6 in host_list:
        # Grab the first free ivp6 address
        for ip in host_list[6].hosts():
            if ip != host_list[6][0] and ip != host_list[6][1]:
                if 6 not in taken_host_list or ip not in taken_host_list[6]:
                    result.append(str(ipaddress.ip_network(ip, strict=True)))
                    break

    return ", ".join(result)


def get_public_key(ctx: AppContext, private_key: str) -> str:
    pipe = subprocess.Popen(["echo", private_key], stdout=subprocess.PIPE)
    pubkey = subprocess.check_output(
        [ctx.wg_binary, "pubkey"], stdin=pipe.stdout)
    pubkey_cleaned = pubkey.decode("utf-8").strip()
    return pubkey_cleaned

def get_listen_port(ctx: AppContext) -> str:
    result: CompletedProcess = subprocess.call(["wg", "show" f"{ctx.wg_interface}", "listen-port"])

    return result.stdout.decode("utf-8").strip()


def get_server_public_key(ctx: AppContext) -> str:
    """

    """
    pubkey = subprocess.check_output(
        [ctx.wg_binary, "show", ctx.wg_interface, 'public-key'])
    pubkey_cleaned = pubkey.decode("utf-8").strip()
    return pubkey_cleaned


def get_private_key(ctx: AppContext) -> str:
    """

    """
    if ctx.private_key != "":
        return ctx.private_key

    privkey = subprocess.check_output([ctx.wg_binary, "genkey"])
    privkey_cleaned = privkey.decode("utf-8").strip()
    return privkey_cleaned


def parse_args() -> AppContext:
    """
    """
    p = argparse.ArgumentParser()

    p.add_argument("--wg-path", help="specify the path of the wg binary. If not specified, than a default will be used", default=DFLT_WG_BINARY)
    
    p.add_argument("--qrencode-path", help="specify the path of the qrencode binary. If not specified, then a default will be used.", default=DFLT_QRENCODE)
    
    p.add_argument("--interface", help="specify the name of the interface to configure", required=True)
    
    p.add_argument("--command", help="action to perform", choices=Command, required=True)

    p.add_argument("--private", help="specify the private key for the interface. If not specified then a value will be generated", default="")
    
    p.add_argument("--address", help="specify the peer's address. If not specified, then one will be generated", default="")
    
    p.add_argument("--subnet", help="the bits of the subnet mask", metavar="NETWORK_ADDR", default="")
    
    p.add_argument("--endpoint", help="the peer's endpoint. If not specified, then none will be generated", default="")
    
    p.add_argument("--allowed-ips", help="specify one or more subnets to allow", nargs="*", default=DLFT_ALLOWED_IPS, metavar="IP ADDRESS")
    
    p.add_argument("--dns", help="specify a DNS address for the peer. if not specified, then none will be provided.", default="")
    
    p.add_argument("--keep-alive", help="specify the keepalive period. if not specified, then the default value will be used", default=DFLT_KEEPALIVE, type=int)
    
    p.add_argument("--mtu", help="specify the peer's MTU. If none is specified, then the field will not be generated", default=0, store_as=int)
    
    p.add_argument("--port", help="the port to listen on. If not specified then the defualt will be used.", default=DFLT_PORT)
    
    p.add_argument("--public", help="the peer's public key", default="")

    args = parse_args()

    app_ctx = AppContext(
        private_key=args.private, 
        wg_binary=args.wg_path,
        endpoint=args.endpoint,
        address=args.address,
        subnet=args.subnet,
        dns=args.dns,
        keep_alive=args.keep_alive,
        mtu=args.mtu,
        allowed_ips=args.allowed_ips,
        qrencode_binary=args.qrencode_path,
        wg_interface=args.interface,
        command=args.command,
        listen_port=args.port)

    return app_ctx


def generate_configuration(
    ctx: AppContext, 
    privkey: str, 
    interface_address: str, 
    server_pubkey: str) -> str:
    config = configparser.ConfigParser()
    config.optionxform = str

    config.add_section('Interface')
    config.set('Interface', 'PrivateKey', privkey)
    config.set('Interface', 'Address', interface_address)
    
    # if ctx.dns != "":
    #     config.set('Interface', 'DNS', ctx.dns)

    # if int(ctx.mtu) > 0:
    #     config.set('Interface', 'MTU', ctx.mtu)

    config.add_section('Peer')
    config.set('Peer', 'PublicKey', server_pubkey)
    config.set('Peer', 'Endpoint', ctx.endpoint)

    allowed_ips = f"{ctx.allowed_ips[0]}"
    for ap in allowed_ips[1:]:
        allowed_ips += f", {ap}"

    config.set('Peer', 'AllowedIPs', allowed_ips)

    if int(ctx.keep_alive) > 0:
        config.set('Peer', 'PersistentKeepalive', ctx.keep_alive)

    output = io.StringIO()
    config.write(output)
    content = output.getvalue()
    output.close()

    return content.strip() + "\n"


def generate_qrcode(ctx, config):
    """

    """
    pipe = subprocess.Popen(["echo", config], stdout=subprocess.PIPE)
    qrcode = subprocess.check_output(
        [ctx.qrencode_binary, "-t", "ANSIUTF8"], stdin=pipe.stdout)
    print(qrcode.decode("utf-8").strip())


def enable_wg_quick(ctx: AppContext):
    subprocess.check_call(["systemctl", "enable", f"wg-quick@{ctx.wg_interface}"])


def start_wg_quick(ctx: AppContext):
    subprocess.check_call(["systemctl", "start", f"wg-quick@{ctx.wg_interface}"])


def create_interface(ctx: AppContext):
    ifc_config_path = f"/etc/wireguard/{ctx.wg_interface}.conf"

        private_config_path = f"/etc/wireguard/{ctx.wg_interface}.private.key"

        if os.path.exists(ifc_config_path):
            raise ValueError(f"config file at path {ifc_config_path} already exists")

        private_key = get_private_key(ctx)

        template = f"""
[Interface]
PrivateKey = {private_key}
ListenPort = {ctx.listen_port}
        """

        with open(ifc_config_path, "w") as fd:
            fd.write(template)
        
        with open(private_config_path, "w") as fd:
            fd.write(private_key)
        
        enable_wg_quick(ctx)

        start_wg_quick(ctx)

def main() -> int:
    ctx: AppContext = parse_args()
    
    if ctx.command == Command.ADD:
        private_key = get_private_key(ctx)
        public_key = get_public_key(ctx, private_key)
        server_public_key = get_server_public_key(ctx)

        # create peer interface config
        template = f"""
[Interface]
PrivateKey = {private_key}
ListenPort = {ctx.listen_port}

[Peer]
PublicKey = {server_public_key}

        """

        # add peer to this interface config
    if ctx.command == Command.CREATE:
        
    if ctx.command == Command.SAVE:
        pass
    if ctx.command == Command.REM_IFC:
        pass
    if ctx.command == Command.REM_PEER:
        pass

    
    
    
    
    privkey = get_private_key(ctx)
    pubkey = get_public_key(ctx, privkey)
    interface_address = ctx.address
    server_pubkey = get_server_public_key(ctx)

    if ctx.subnet is not None:
        interface_address = first_available_ip_from_subnet(args)

    interface_address = interface_address.replace(' ', '')

    if args.auto_add is False:
        print("# Run the following command to add this newly created peer")
        print(
            f"# {args.wg_binary} set {args.wg_interface} peer '{pubkey}' allowed-ips '{interface_address}'\n\n")

    config = generate_configuration(
        args,
        privkey=privkey,
        interface_address=interface_address,
        server_pubkey=server_pubkey
    )

    if args.qr:
        generate_qrcode(args, config)
    else:
        print(config)

    if args.auto_add is True:
        subprocess.Popen([
            args.wg_binary, "set", args.wg_interface, "peer",
            pubkey, "allowed-ips", interface_address
        ])
        subprocess.Popen([
            args.wg_binary, "show", args.wg_interface])
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
