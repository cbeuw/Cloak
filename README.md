[![Build Status](https://github.com/cbeuw/Cloak/workflows/Build%20and%20test/badge.svg)](https://github.com/cbeuw/Cloak/actions)
[![codecov](https://codecov.io/gh/cbeuw/Cloak/branch/master/graph/badge.svg)](https://codecov.io/gh/cbeuw/Cloak)
[![Go Report Card](https://goreportcard.com/badge/github.com/cbeuw/Cloak)](https://goreportcard.com/report/github.com/cbeuw/Cloak)
[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=SAUYKGSREP8GL&source=url)

<p align="center">
  <img src="https://user-images.githubusercontent.com/7034308/96387206-3e214100-1198-11eb-8917-689d7c56e0cd.png" />
  <img src="https://user-images.githubusercontent.com/7034308/155593583-f22bcfe2-ac22-4afb-9288-1a0e8a791a0d.svg" />
</p>

<p align="center">
  <img src="https://user-images.githubusercontent.com/7034308/155629720-54dd8758-ec98-4fed-b603-623f0ad83b6c.svg" />
</p>

Cloak is a [pluggable transport](https://www.ietf.org/proceedings/103/slides/slides-103-pearg-pt-slides-01) that enhances
traditional proxy tools like OpenVPN to evade [sophisticated censorship](https://en.wikipedia.org/wiki/Deep_packet_inspection) and [data discrimination](https://en.wikipedia.org/wiki/Net_bias).

Cloak is not a standalone proxy program. Rather, it works by masquerading proxied traffic as normal web browsing
activities. In contrast to traditional tools which have very prominent traffic fingerprints and can be blocked by simple filtering rules,
it's very difficult to precisely target Cloak with little false positives. This increases the collateral damage to censorship actions as
attempts to block Cloak could also damage services the censor state relies on.

To any third party observer, a host running Cloak server is indistinguishable from an innocent web server. Both while
passively observing traffic flow to and from the server, as well as while actively probing the behaviours of a Cloak
server. This is achieved through the use a series
of [cryptographic steganography techniques](https://github.com/cbeuw/Cloak/wiki/Steganography-and-encryption).

Cloak can be used in conjunction with any proxy program that tunnels traffic through TCP or
UDP, such as Shadowsocks, OpenVPN and Tor. Multiple proxy servers can be running on the same server host and
Cloak server will act as a reverse proxy, bridging clients with their desired proxy end.

Cloak multiplexes traffic through multiple underlying TCP connections which reduces head-of-line blocking and eliminates
TCP handshake overhead. This also makes the traffic pattern more similar to real websites.

Cloak provides multi-user support, allowing multiple clients to connect to the proxy server on the same port (443 by
default). It also provides traffic management features such as usage credit and bandwidth control. This allows a proxy
server to serve multiple users even if the underlying proxy software wasn't designed for multiple users

Cloak also supports tunneling through an intermediary CDN server such as Amazon Cloudfront. Such services are so widely used,
attempts to disrupt traffic to them can lead to very high collateral damage for the censor.

## Quick Start

To quickly deploy Cloak with Shadowsocks on a server, you can run
this [script](https://github.com/HirbodBehnam/Shadowsocks-Cloak-Installer/blob/master/Cloak2-Installer.sh) written by
@HirbodBehnam

Table of Contents
=================

* [Quick Start](#quick-start)
* [Build](#build)
* [Configuration](#configuration)
    * [Server](#server)
    * [Client](#client)
* [Setup](#setup)
    * [Server](#server-1)
        * [To add users](#to-add-users)
            * [Unrestricted users](#unrestricted-users)
            * [Users subject to bandwidth and credit controls](#users-subject-to-bandwidth-and-credit-controls)
    * [Client](#client-1)
* [Support me](#support-me)

## Build

```bash
git clone https://github.com/cbeuw/Cloak
cd Cloak
go get ./...
make
```

Built binaries will be in `build` folder.

## Configuration

Examples of configuration files can be found under `example_config` folder.

### Server

`RedirAddr` is the redirection address when the incoming traffic is not from a Cloak client. Ideally it should be set to
a major website allowed by the censor (e.g. `www.bing.com`)

`BindAddr` is a list of addresses Cloak will bind and listen to (e.g. `[":443",":80"]` to listen to port 443 and 80 on
all interfaces)

`ProxyBook` is an object whose key is the name of the ProxyMethod used on the client-side (case-sensitive). Its value is
an array whose first element is the protocol, and the second element is an `IP:PORT` string of the upstream proxy server
that Cloak will forward the traffic to.

Example:

```json
{
  "ProxyBook": {
    "shadowsocks": [
      "tcp",
      "localhost:51443"
    ],
    "openvpn": [
      "tcp",
      "localhost:12345"
    ]
  }
}
```

`PrivateKey` is the static curve25519 Diffie-Hellman private key encoded in base64.

`BypassUID` is a list of UIDs that are authorised without any bandwidth or credit limit restrictions

`AdminUID` is the UID of the admin user in base64. You can leave this empty if you only ever add users to `BypassUID`.

`DatabasePath` is the path to `userinfo.db`, which is used to store user usage information and restrictions. Cloak will
create the file automatically if it doesn't exist. You can leave this empty if you only ever add users to `BypassUID`.
This field also has no effect if `AdminUID` isn't a valid UID or is empty.

`KeepAlive` is the number of seconds to tell the OS to wait after no activity before sending TCP KeepAlive probes to the
upstream proxy server. Zero or negative value disables it. Default is 0 (disabled).

### Client

`UID` is your UID in base64.

`Transport` can be either `direct` or `CDN`. If the server host wishes you to connect to it directly, use `direct`. If
instead a CDN is used, use `CDN`.

`PublicKey` is the static curve25519 public key in base64, given by the server admin.

`ProxyMethod` is the name of the proxy method you are using. This must match one of the entries in the
server's `ProxyBook` exactly.

`EncryptionMethod` is the name of the encryption algorithm you want Cloak to use. Options are `plain`, `aes-256-gcm` (
synonymous to `aes-gcm`), `aes-128-gcm`, and `chacha20-poly1305`. Note: Cloak isn't intended to provide transport
security. The point of encryption is to hide fingerprints of proxy protocols and render the payload statistically
random-like. **You may only leave it as `plain` if you are certain that your underlying proxy tool already provides BOTH
encryption and authentication (via AEAD or similar techniques).**

`ServerName` is the domain you want to make your ISP or firewall _think_ you are visiting. Ideally it should
match `RedirAddr` in the server's configuration, a major site the censor allows, but it doesn't have to. Use `random` to randomize the server name for every connection made.

`AlternativeNames` is an array used alongside `ServerName` to shuffle between different ServerNames for every new
connection. **This may conflict with `CDN` Transport mode** if the CDN provider prohibits domain fronting and rejects
the alternative domains.

Example:

```json
{
  "ServerName": "bing.com",
  "AlternativeNames": ["cloudflare.com", "github.com"]
}
```

`CDNOriginHost` is the domain name of the _origin_ server (i.e. the server running Cloak) under `CDN` mode. This only
has effect when `Transport` is set to `CDN`. If unset, it will default to the remote hostname supplied via the
commandline argument (in standalone mode), or by Shadowsocks (in plugin mode). After a TLS session is established with
the CDN server, this domain name will be used in the `Host` header of the HTTP request to ask the CDN server to
establish a WebSocket connection with this host.

`CDNWsUrlPath` is the url path used to build websocket request sent under `CDN` mode, and also only has effect
when `Transport` is set to `CDN`. If unset, it will default to "/". This option is used to build the first line of the
HTTP request after a TLS session is extablished. It's mainly for a Cloak server behind a reverse proxy, while only
requests under specific url path are forwarded.

`NumConn` is the amount of underlying TCP connections you want to use. The default of 4 should be appropriate for most
people. Setting it too high will hinder the performance. Setting it to 0 will disable connection multiplexing and each
TCP connection will spawn a separate short-lived session that will be closed after it is terminated. This makes it
behave like GoQuiet. This maybe useful for people with unstable connections.

`BrowserSig` is the browser you want to **appear** to be using. It's not relevant to the browser you are actually using.
Currently, `chrome`, `firefox` and `safari` are supported.

`KeepAlive` is the number of seconds to tell the OS to wait after no activity before sending TCP KeepAlive probes to the
Cloak server. Zero or negative value disables it. Default is 0 (disabled). Warning: Enabling it might make your server
more detectable as a proxy, but it will make the Cloak client detect internet interruption more quickly.

`StreamTimeout` is the number of seconds of Cloak waits for an incoming connection from a proxy program to send any
data, after which the connection will be closed by Cloak. Cloak will not enforce any timeout on TCP connections after it
is established.

## Setup

### Server

0. Install at least one underlying proxy server (e.g. OpenVPN, Shadowsocks).
1. Download [the latest release](https://github.com/cbeuw/Cloak/releases) or clone and build this repo.
2. Run `ck-server -key`. The **public** should be given to users, the **private** key should be kept secret.
3. (Skip if you only want to add unrestricted users) Run `ck-server -uid`. The new UID will be used as `AdminUID`.
4. Copy example_config/ckserver.json into a desired location. Change `PrivateKey` to the private key you just obtained;
   change `AdminUID` to the UID you just obtained.
5. Configure your underlying proxy server so that they all listen on localhost. Edit `ProxyBook` in the configuration
   file accordingly
6. [Configure the proxy program.](https://github.com/cbeuw/Cloak/wiki/Underlying-proxy-configuration-guides)
   Run `sudo ck-server -c <path to ckserver.json>`. ck-server needs root privilege because it binds to a low numbered
   port (443). Alternatively you can follow https://superuser.com/a/892391 to avoid granting ck-server root privilege
   unnecessarily.

#### To add users

##### Unrestricted users

Run `ck-server -uid` and add the UID into the `BypassUID` field in `ckserver.json`

##### Users subject to bandwidth and credit controls

0. First make sure you have `AdminUID` generated and set in `ckserver.json`, along with a path to `userinfo.db`
   in `DatabasePath` (Cloak will create this file for you if it didn't already exist).
1. On your client, run `ck-client -s <IP of the server> -l <A local port> -a <AdminUID> -c <path-to-ckclient.json>` to
   enter admin mode
2. Visit https://cbeuw.github.io/Cloak-panel (Note: this is a pure-js static site, there is no backend and all data
   entered into this site are processed between your browser and the Cloak API endpoint you specified. Alternatively you
   can download the repo at https://github.com/cbeuw/Cloak-panel and open `index.html` in a browser. No web server is
   required).
3. Type in `127.0.0.1:<the port you entered in step 1>` as the API Base, and click `List`.
4. You can add in more users by clicking the `+` panel

Note: the user database is persistent as it's in-disk. You don't need to add the users again each time you start
ck-server.

### Client

**Android client is available here: https://github.com/cbeuw/Cloak-android**

0. Install the underlying proxy client corresponding to what the server has.
1. Download [the latest release](https://github.com/cbeuw/Cloak/releases) or clone and build this repo.
2. Obtain the public key and your UID from the administrator of your server
3. Copy `example_config/ckclient.json` into a location of your choice. Enter the `UID` and `PublicKey` you have
   obtained. Set `ProxyMethod` to match exactly the corresponding entry in `ProxyBook` on the server end
4. [Configure the proxy program.](https://github.com/cbeuw/Cloak/wiki/Underlying-proxy-configuration-guides)
   Run `ck-client -c <path to ckclient.json> -s <ip of your server>`

## Support me

If you find this project useful, you can visit my [merch store](https://www.redbubble.com/people/cbeuw/explore);
alternatively you can donate directly to me

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=SAUYKGSREP8GL&source=url)

BTC: `bc1q59yvpnh0356qq9vf0j2y7hx36t9ysap30spx9h`

ETH: `0x8effF29a8F9bD38A367580527AC303972c92b60c`
