# Cloak
A Shadowsocks plugin that obfuscates the traffic as normal HTTPS traffic and disguises the proxy server as a normal webserver.

**This is an active WIP. The program has shown to be stable but everything is subject to change.**

This project is based on my previous project [GoQuiet](https://github.com/cbeuw/GoQuiet). The aim is to make indiscriminate blocking of HTTPS servers (or even IP ranges) with high traffic the only effective way of stopping people from using Shadowsocks.

Numerous improvements have been made from GoQuiet. The most significant one is that, in GoQuiet, a new TCP connection is establieshed and a TLS handshake is done between the client and the proxy server each time a connection is made to Shadowsocks' client, whereas in Cloak all the traffic is multiplexed through a fixed amount of persistent TCP connections between the client and the proxy server. The major benefits are:

- Significantly quicker establishment of new connections as TLS handshake is only done on the startup of the client

- More realistic traffic pattern

Besides, Cloak allows multiple users to use one server **on a single port**. QoS restrictions such as bandwidth limitation and data cap can also be managed.

## Build
Simply `make client` and `make server`. Output binary will be in the build folder

## Setup
### For the administrator of the server
0. [Install and configure shadowsocks-libev on your server](https://github.com/shadowsocks/shadowsocks-libev#installation)
1. Clone this repo onto your server
2. Build and run ck-server -k. The base64 string before the comma is the **public** key to be given to users, the one after the comma is the **private** key to be kept secret
3. Run `ck-server -u`. This will be used as the AdminUID
4. Put the private key and the AdminUID you obtained previously into config/ckserver.json
5. Edit the configuration file of shadowsocks-libev (default location is /etc/shadowsocks-libev/config.json). Let `server_port` be `443`, `plugin` be the full path to the ck-server binary and `plugin_opts` be the full path to ckserver.json. If the fields `plugin` and `plugin_opts` were not present originally, add these fields to the config file.
6. Run ss-server as root (because we are binding to TCP port 443)

#### If you want to add more users
1. Run ck-server -u to generate a new UID
2. On your client, run `ck-client -a -c <path-to-ckclient.json>` to enter admin mode
3. Input as prompted, that is your ip:port of the server and your AdminUID. Enter 4 to create a new user.
4. Enter the UID in your ckclient.json as the prompted UID, enter SessionsCap (maximum amount of concurrent sessions a user can have), UpRate and DownRate (in bytes/s), UpCredit and DownCredit (in bytes) and ExpiryTime (as a unix epoch)
5. Give your **public** key and the newly generated UID to the new user

Note: the user database is persistent as it's in-disk. You don't need to add the users again each time you start ck-server.

### Instructions for clients
0. Install and configure a version of shadowsocks client that supports plugins (such as shadowsocks-libev and shadowsocks-windows)
1. Clone this repo and build ck-client
2. Obtain the public key and your UID (or the AdminUID, if you are the server admin) from the administrator of your server
3. Put the public key and the UID you obtained into config/ckclient.json
4. Configure your shadowsocks client with your server information. The field `plugin` should be the path to ck-server binary and `plugin_opts` should be the path to ckclient.json
