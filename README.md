# Cloak

**Cloak 2 is a WIP and not ready for release. Cloak 2 will not be compatible with Cloak 1 protocols or configurarion files**

Cloak is a universal pluggable transport that obfuscates proxy traffic as legitimate HTTPS traffic, disguises the proxy server as a normal webserver, multiplexes traffic through multiple TCP connections and provide multi-user usage control. 

Cloak eliminates any "fingerprints" exposed by traditional proxy protocol designs which can be identified by adversaries through deep packet inspection. If a non-Cloak program or an unauthorised Cloak user (such as an adversary's prober) attemps to connect to Cloak server, it will serve as a transparent proxy between said machine and an ordinary website, so that to any unauthorised third party, a host running Cloak server is indistinguishable from an innocent web server.

Since Cloak is transparent, it can be used in conjunction with any proxy softwares that tunnels traffic through TCP, such as Shadowsocks, OpenVPN and Tor. Multiple proxy servers can be running on the same server host machine and Cloak will act as a dispatcher, bridging clients with their desired proxy end.

Cloak multiplexes traffic through multiple underlying TCP connections which reduces head-of-line blocking and eliminates TCP handshake overhead.

Cloak provides multi-user support, allowing multiple clients to connect to the proxy server on the same port (443 by default). It also provides QoS controls for individual users such as data limit and bandwidth control.

This project is based on [GoQuiet](https://github.com/cbeuw/GoQuiet). Through multiplexing, Cloak provides a siginifcant reduction in webpage loading time compared to GoQuiet (from 10% to 50%+, depending on the amount of content on the webpage, see [benchmarks](https://github.com/cbeuw/Cloak/wiki/Web-page-loading-benchmarks)).

## Build
Simply `make client` and `make server`. Output binary will be in `build` folder.
Do `make server_pprof` if you want to access the live profiling data.

## Configuration

### Server
`RedirAddr` is the redirection address and port when the incoming traffic is not from a Cloak client. It should correspond to the IP record of the `ServerName` field set in `ckclient.json`.

`ProxyMethod` is a nested JSON section which defines the address of different proxy server ends. For instance, if OpenVPN server is listening on 127.0.0.1:1194, the pair should be `"openvpn":"127.0.0.1:1194"`. There can be multiple pairs.

`PrivateKey` is the static curve25519 Diffie-Hellman private key encoded in base64.

`AdminUID` is the UID of the admin user in base64.

`DatabasePath` is the path to userinfo.db. If userinfo.db doesn't exist in this directory, Cloak will create one automatically. **If Cloak is started as a Shadowsocks plugin and Shadowsocks is started with its working directory as / (e.g. starting ss-server with systemctl), you need to set this field as an absolute path to a desired folder. If you leave it as default then Cloak will attempt to create userinfo.db under /, which it doesn't have the permission to do so and will raise an error. See Issue #13.**

`BackupDirPath` is the path to save the backups of userinfo.db whenever you delete a user. If left blank, Cloak will attempt to create a folder called db-backup under its working directory. This may not be desired. See notes above.

### Client
`UID` is your UID in base64.

`PublicKey` is the static curve25519 public key, given by the server admin.

`ProxyMethod` is the name of the proxy method you are using.

`EncryptionMethod` is the name of the encryption algorithm you want Cloak to use. Note: Cloak isn't intended to provide data security or authentication. The point of encryption is to hide fingerprints of proxy protocols. If the proxy protocol already doesn't have any fingerprint, such as Shadowsocks, this field can be left as `plain`. Options are `plain`, `aes-gcm` and `chacha20-poly1305`.

`ServerName` is the domain you want to make your ISP or firewall think you are visiting.

`TicketTimeHint` is the time needed for a session ticket to expire and a new one to be generated. Leave it as the default.

`NumConn` is the amount of underlying TCP connections you want to use.

`BrowserSig` is the browser you want to **make the GFW _think_ you are using, it has NOTHING to do with the web browser or any web application you are using on your machine**. Currently, `chrome` and `firefox` are supported.

## Setup
### For the administrator of the server
**Run this script: https://github.com/HirbodBehnam/Shadowsocks-Cloak-Installer/blob/master/Shadowsocks-Cloak-Installer.sh (thanks to [@HirbodBehnam](https://github.com/HirbodBehnam))** or do it manually:

0. [Install and configure shadowsocks-libev on your server](https://github.com/shadowsocks/shadowsocks-libev#installation)
1. Download [the latest release](https://github.com/cbeuw/Cloak/releases) or clone and build this repo. If you wish to build it, make sure you fetch the dependencies using `go get github.com/boltdb/bolt`, `go get github.com/juju/ratelimit` and `go get golang.org/x/crypto/curve25519`
2. Run ck-server -k. The base64 string before the comma is the **public** key to be given to users, the one after the comma is the **private** key to be kept secret
3. Run `ck-server -u`. This will be used as the AdminUID
4. Put the private key and the AdminUID you obtained previously into config/ckserver.json
5. Edit the configuration file of shadowsocks-libev (default location is /etc/shadowsocks-libev/config.json). Let `server_port` be `443`, `plugin` be the full path to the ck-server binary and `plugin_opts` be the full path to ckserver.json. If the fields `plugin` and `plugin_opts` were not present originally, add these fields to the config file.
6. Run ss-server as root (because we are binding to TCP port 443)

#### If you want to add more users
1. Run ck-server -u to generate a new UID
2. On your client, run `ck-client -a -c <path-to-ckclient.json>` to enter admin mode
3. Input as prompted, that is your ip:port of the server and your AdminUID. Enter 4 to create a new user.
4. Enter the the newly generated UID, enter SessionsCap (maximum amount of concurrent sessions a user can have), UpRate and DownRate (in bytes/s), UpCredit and DownCredit (in bytes) and ExpiryTime (as a unix epoch)
5. Give your **public** key and the newly generated UID to the new user

Note: the user database is persistent as it's in-disk. You don't need to add the users again each time you start ck-server.

### Instructions for clients
**Android client is available here: https://github.com/cbeuw/Cloak-android**

0. Install and configure a version of shadowsocks client that supports plugins (such as shadowsocks-libev and shadowsocks-windows)
1. Download [the latest release](https://github.com/cbeuw/Cloak/releases) or clone and build this repo. If you wish to build it, make sure you fetch the dependencies using `go get github.com/boltdb/bolt`, `go get github.com/juju/ratelimit` and `go get golang.org/x/crypto/curve25519`
2. Obtain the public key and your UID (or the AdminUID, if you are the server admin) from the administrator of your server
3. Put the public key and the UID you obtained into config/ckclient.json
4. Configure your shadowsocks client with your server information. The field `plugin` should be the path to ck-server binary and `plugin_opts` should be the path to ckclient.json

## Support me
If you find this project useful, donations are greatly appreciated!

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=SAUYKGSREP8GL&source=url)

BTC: `bc1q59yvpnh0356qq9vf0j2y7hx36t9ysap30spx9h`

ETH: `0x8effF29a8F9bD38A367580527AC303972c92b60c`
