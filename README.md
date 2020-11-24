# wg-mgmt

WireGuard® VPN peer creator.

## Dependencies:
`Python3`, `wg`

Optionnaly, you'll need `qrencode` (if `--qr` argument is specified)

## Install:

Using wget
```sh
$ wget https://raw.githubusercontent.com/j0n17/wg-mgmt/master/wg_mgmt.py
```

Using curl
```sh
$ curl -o wg_mgmt.py https://raw.githubusercontent.com/j0n17/wg-mgmt/master/wg_mgmt.py
```



## Usage command:

```sh
# Display what to do in order to create add a new peer
$ python3 wg_mgmt.py --subnet 10.10.0.0/24,fd86:ea04:1111::/64 --endpoint example.org:51280
# Run the following command to add this newly created peer
# wg set wg0 peer 'mgNpWHZe1a4irAyp/x2Fz1Psz19Rf+e0T5GZPLgKFho=' allowed-ips '10.10.0.4/32,fd86:ea04:1111::4/128'


[Interface]
PrivateKey = IPa804Rvd8I/uE+kjGun2f9PhBKdxrEVxZmnIFQfcHQ=
Address = 10.10.0.4/32,fd86:ea04:1111::4/128
DNS = 1.1.1.1

[Peer]
PublicKey = mgNpWHZe1a4irAyp/x2Fz1Psz19Rf+e0T5GZPLgKFho=
Endpoint = example.org:51280
AllowedIPs = 0.0.0.0/0,::/0




# If you need to manually specify the IP addresses used
$ python3 wg_mgmt.py --address 10.10.0.4/32,fd86:ea04:1111::3/128 --endpoint example.org:51280
# Run the following command to add this newly created peer
# wg set wg0 peer 'JTOE9DRu4jfCjpBzUl5rXZZJBHdtd2ZRx/m+uiCxPV8=' allowed-ips '10.10.0.4/32,fd86:ea04:1111::3/128'


[Interface]
PrivateKey = 6P6jliBjYHrzeb9C3xRpvbNjuKQNEin7juSfgWMCR3g=
Address = 10.10.0.4/32,fd86:ea04:1111::3/128
DNS = 1.1.1.1

[Peer]
PublicKey = JTOE9DRu4jfCjpBzUl5rXZZJBHdtd2ZRx/m+uiCxPV8=
Endpoint = example.org:51280
AllowedIPs = 0.0.0.0/0,::/0
```


```sh
usage: wgm.py [-h] --config-file CONFIG_FILE [--wg-path /PATH/TO/WG] [--qrencode-path QRENCODE_PATH] --interface IFC_NAME [--quiet] [--verbose] [--server-listen-port SERVER_LISTEN_PORT] [--server-addresses [X.X.X.X [X.X.X.X ...]]] [--server-allowed-ips [X.X.X.X/Y [X.X.X.X/Y ...]]]
              [--server-networks [X.X.X.Y/Z [X.X.X.Y/Z ...]]] [--server-description SERVER_DESCRIPTION] [--server-private-key SERVER_PRIVATE_KEY] [--server-keepalive SECS] [--peer-listen-port PEER_LISTEN_PORT] [--peer-adresses [X.X.X.X [X.X.X.X ...]]] [--peer-networks [X.X.X.Y/Z [X.X.X.Y/Z ...]]]
              [--peer-allowed_ips [X.X.X.X/Y [X.X.X.X/Y ...]]] [--peer-keepalive SECS] [--peer-public-key PEER_PUBLIC_KEY] [--peer-description PEER_DESCRITPION]
              COMMAND

positional arguments:
  COMMAND

optional arguments:
  -h, --help            show this help message and exit
  --config-file CONFIG_FILE
                        (required) config file path.
  --wg-path /PATH/TO/WG
                        (optional) wg binary path; default: wg
  --qrencode-path QRENCODE_PATH
                        (optional) qrencode path; default=qrencode
  --interface IFC_NAME  name of the wireguard interface
  --quiet               output only warning and error messages
  --verbose             output debug-level messages
  --server-listen-port SERVER_LISTEN_PORT
                        (optional) server listen port; default: 51820
  --server-addresses [X.X.X.X [X.X.X.X ...]]
                        (required) comma-separated list of IPv4 addresses
  --server-allowed-ips [X.X.X.X/Y [X.X.X.X/Y ...]]
                        (required) comma-separated list of allowed IPs/Networks
  --server-networks [X.X.X.Y/Z [X.X.X.Y/Z ...]]
                        (required) comma-separated list of server networks
  --server-description SERVER_DESCRIPTION
                        (optional) server description
  --server-private-key SERVER_PRIVATE_KEY
                        (optional) server's private key
  --server-keepalive SECS
                        (optional) servers' keepalive interval; default=25
  --peer-listen-port PEER_LISTEN_PORT
                        (optional) peer listen port; default=51820
  --peer-adresses [X.X.X.X [X.X.X.X ...]]
                        (optional) comma-separated list of peer IP addresses
  --peer-networks [X.X.X.Y/Z [X.X.X.Y/Z ...]]
                        (optional) comma-separated list of peer networks
  --peer-allowed_ips [X.X.X.X/Y [X.X.X.X/Y ...]]
                        (optional) comma-separated list of peer allowed_ips
  --peer-keepalive SECS
                        (optional) peer keep-alive interval; default=25
  --peer-public-key PEER_PUBLIC_KEY
                        (required) peer public key
  --peer-description PEER_DESCRITPION
                        (optional) peer description
```

## TODO List

- [ ] support adding ufw/iptables rules for listen port on server
- [ ] support ipv6 addresses and endpoints
- [ ] support FQDN endpoints



create an interface
```
python3 wgm.py create-interface --config-file wg_config.yaml --interface test0 --verbose --server-addresses 192.168.255.1 --server-allowed-ips 192.168.255.0/24 --server-networks 192.168.255.0/24`
```

delete an interface
```
python3 wgm.py delete-interface --config-file wg_config.yaml --interface test0
```