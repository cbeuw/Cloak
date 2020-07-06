![image](https://user-images.githubusercontent.com/7034308/65361318-0a719180-dbfb-11e9-96de-56d1023856f0.png)

![Cloak](https://user-images.githubusercontent.com/7034308/65385852-7eab5280-dd2b-11e9-8887-db449b250e2a.png)

Cloak is a universal pluggable transport that cryptographically obfuscates proxy traffic as legitimate HTTPS traffic, disguises the proxy server as a normal web server, multiplexes traffic through a fixed amount of TCP connections and provides multi-user usage control. 

Cloak works fundamentally by masquerading proxy traffic as normal web browsing traffic. This increases the collateral damage to censorship actions and therefore make it very difficult, if not impossible, for censors to selectively block censorship evasion tools and proxy servers without affecting services that the state may also heavily rely on. 

Cloak eliminates any "fingerprints" exposed by traditional proxy protocol designs which can be identified by adversaries through deep packet inspection. If a non-Cloak program or an unauthorised Cloak user (such as an adversary's prober) attempts to connect to Cloak server, it will serve as a transparent proxy between said machine and an ordinary website, so that to any unauthorised third party, a host running Cloak server is indistinguishable from an innocent web server. This is achieved through the use a series of [cryptographic stegnatography techniques](https://github.com/cbeuw/Cloak/wiki/Steganography-and-encryption).

Since Cloak is transparent, it can be used in conjunction with any proxy software that tunnels traffic through TCP, such as Shadowsocks, OpenVPN and Tor. Multiple proxy servers can be running on the same server host machine and Cloak server will act as a reverse proxy, bridging clients with their desired proxy end.

Cloak multiplexes traffic through multiple underlying TCP connections which reduces head-of-line blocking and eliminates TCP handshake overhead. This also makes the traffic pattern more similar to real websites.

Cloak provides multi-user support, allowing multiple clients to connect to the proxy server on the same port (443 by default). It also provides traffic management features such as usage credit and bandwidth control. This allows a proxy server to serve multiple users even if the underlying proxy software wasn't designed for multiple users

Cloak has two modes of [_Transport_](https://github.com/cbeuw/Cloak/wiki/CDN-mode): `direct` and `CDN`. Clients can either connect to the host running Cloak server directly, or it can instead connect to a CDN edge server, which may be used by many legitimate websites as well, thus further increases the collateral damage to censorship. 

**Cloak 2.x is not compatible with legacy Cloak 1.x's protocol, configuration file or database file. Cloak 1.x protocol has critical cryptographic flaws regarding encrypting stream headers. Using Cloak 1.x is strongly discouraged**

This project was evolved from [GoQuiet](https://github.com/cbeuw/GoQuiet). Through multiplexing, Cloak provides a significant reduction in webpage loading time compared to GoQuiet (from 10% to 50%+, depending on the amount of content on the webpage, see [benchmarks](https://github.com/cbeuw/Cloak/wiki/Web-page-loading-benchmarks)).

## Quick Start
To quickly deploy Cloak with Shadowsocks on a server, you can run this [script](https://github.com/HirbodBehnam/Shadowsocks-Cloak-Installer/blob/master/Cloak2-Installer.sh) written by @HirbodBehnam 

## Build
If you are not using the experimental go mod support, make sure you `go get` the following dependencies:
```
go.etcd.io/bbolt
github.com/cbeuw/connutil
github.com/juju/ratelimit
github.com/gorilla/mux
github.com/gorilla/websocket
github.com/sirupsen/logrus
golang.org/x/crypto
github.com/refraction-networking/utls
```
Then run `make client` or `make server`. Output binary will be in `build` folder.

## Configuration

### Server
`RedirAddr` is the redirection address when the incoming traffic is not from a Cloak client. It should be the IP and port of a webserver that responds to HTTPS (eg: `localhost:10443`), preferably with a real SSL certificate.

`BindAddr` is a list of addresses Cloak will bind and listen to (e.g. `[":443",":80"]` to listen to port 443 and 80 on all interfaces)

`ProxyBook` is an object whose key is the name of the ProxyMethod used on the client-side (case-sensitive). Its value is an array whose first element is the protocol and the second element is an `IP:PORT` string of the upstream proxy server that Cloak will forward the traffic to.

Example:
```json
{
    "ProxyBook": {
        "shadowsocks": [ "tcp", "localhost:51443" ],
        "openvpn": [ "tcp", "localhost:12345" ]
    }
}
```

`PrivateKey` is the static curve25519 Diffie-Hellman private key encoded in base64.

`AdminUID` is the UID of the admin user in base64.

`BypassUID` is a list of UIDs that are authorised without any bandwidth or credit limit restrictions

`DatabasePath` is the path to userinfo.db. If userinfo.db doesn't exist in this directory, Cloak will create one automatically. **If Cloak is started as a Shadowsocks plugin and Shadowsocks is started with its working directory as / (e.g. starting ss-server with systemctl), you need to set this field as an absolute path to a desired folder. If you leave it as default then Cloak will attempt to create userinfo.db under /, which it doesn't have the permission to do so and will raise an error. See Issue #13.**

`KeepAlive` is the number of seconds to tell the OS to wait after no activity before sending TCP KeepAlive probes to the upstream proxy server. Zero or negative value disables it. Default is 0 (disabled).

`StreamTimeout` is the number of seconds of no sent data after which the incoming Cloak client connection will be terminated. Default is 300 seconds.

### Client
`UID` is your UID in base64.

`Transport` can be either `direct` or `CDN`. If the server host wishes you to connect to it directly, use `direct`. If instead a CDN is used, use `CDN`.

`PublicKey` is the static curve25519 public key, given by the server admin.

`ProxyMethod` is the name of the proxy method you are using.

`EncryptionMethod` is the name of the encryption algorithm you want Cloak to use. Note: Cloak isn't intended to provide transport security. The point of encryption is to hide fingerprints of proxy protocols and render the payload statistically random-like. If the proxy protocol is already fingerprint-less, which is the case for Shadowsocks, this field can be left as `plain`. Options are `plain`, `aes-gcm` and `chacha20-poly1305`.

`ServerName` is the domain you want to make your ISP or firewall think you are visiting.

`NumConn` is the amount of underlying TCP connections you want to use. The default of 4 should be appropriate for most people. Setting it too high will hinder the performance. Setting it to 0 will disable connection multiplexing and each TCP connection will spawn a separate short lived session that will be closed after it is terminated. This makes it behave like GoQuiet. This maybe useful for people with unstable connections.

`BrowserSig` is the browser you want to **appear** to be using. It's not relevant to the browser you are actually using. Currently, `chrome` and `firefox` are supported.

`KeepAlive` is the number of seconds to tell the OS to wait after no activity before sending TCP KeepAlive probes to the Cloak server. Zero or negative value disables it. Default is 0 (disabled). Warning: Enabling it might make your server more detectable as a proxy, but it will make the Cloak client detect internet interruption more quickly.

`StreamTimeout` is the number of seconds of no sent data after which the incoming proxy connection will be terminated. Default is 300 seconds.

## Setup
### For the administrator of the server

0. Set up the underlying proxy server.
1. Download [the latest release](https://github.com/cbeuw/Cloak/releases) or clone and build this repo.
2. Run ck-server -k. The base64 string before the comma is the **public** key to be given to users, the one after the comma is the **private** key to be kept secret
3. Run `ck-server -u`. This will be used as the AdminUID
4. Copy example_config/ckserver.json into a desired location. Change `PrivateKey` to the private key you just obtained; change `AdminUID` to the UID you just obtained.
5. Configure your underlying proxy server so that they all listen on localhost. Edit `ProxyBook` in the configuration file accordingly
6. [Configure the proxy program.](https://github.com/cbeuw/Cloak/wiki/Underlying-proxy-configuration-guides) Run `sudo ck-server -c <path to ckserver.json>`. ck-server needs root privilege because it binds to a low numbered port (443). Alternatively you can follow https://superuser.com/a/892391 to avoid granting ck-server root privilege unnecessarily.

#### To add users
##### Unrestricted users
Run `ck-server -u` and add the UID into the `BypassUID` field in `ckserver.json`

##### Users subject to bandwidth and credit controls
1. On your client, run `ck-client -s <IP of the server> -l <A local port> -a <AdminUID> -c <path-to-ckclient.json>` to enter admin mode
2. Visit https://cbeuw.github.io/Cloak-panel (Note: this is a static site, there is no backend and all data entered into this site are processed between your browser and the Cloak API endpoint you specified. Alternatively you can download the repo at https://github.com/cbeuw/Cloak-panel and host it on your own web server). 
3. Type in 127.0.0.1:<the port you entered in step 1> as the API Base, and click `List`.
4. You can add in more users by clicking the `+` panel

Note: the user database is persistent as it's in-disk. You don't need to add the users again each time you start ck-server.

### Instructions for clients
**Android client is available here: https://github.com/cbeuw/Cloak-android**

0. Install and configure the proxy client based on the server
1. Download [the latest release](https://github.com/cbeuw/Cloak/releases) or clone and build this repo. 
2. Obtain the public key and your UID from the administrator of your server
3. Copy example_config/ckclient.json into a location of your choice. Enter the `UID` and `PublicKey` you have obtained. Set `ProxyMethod` to match exactly the corresponding entry in `ProxyBook` on the server end
4. [Configure the proxy program.](https://github.com/cbeuw/Cloak/wiki/Underlying-proxy-configuration-guides) Run `ck-client -c <path to ckclient.json> -s <ip of your server>`

## Support me
If you find this project useful, you can visit my [merch store](https://teespring.com/en-GB/stores/andys-scribble) which sells some of my designed t-shirts, phone cases, mugs and other bits and bobs; alternatively you can donate directly to me

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=SAUYKGSREP8GL&source=url)

BTC: `bc1q59yvpnh0356qq9vf0j2y7hx36t9ysap30spx9h`

ETH: `0x8effF29a8F9bD38A367580527AC303972c92b60c`
