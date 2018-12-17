# Cloak
A shadowsocks plugin that obfuscates the traffic as normal HTTPS traffic and disguises the proxy server as a normal webserver.

**This is an active WIP. The functionality is incomplete, the code is messy and nothing has been properly tested (though the core multiplexing part seems to work fine). Everything is subject to change.**

This project is based on [GoQuiet](https://github.com/cbeuw/GoQuiet). The most significant difference is that, in GoQuiet, a new TCP connection is establieshed and a TLS handshake is done between the client and the proxy server each time a connection is made to ssclient, whereas in Cloak all the traffic is multiplexed through a fixed amount of consistant TCP connections between the client and the proxy server. The major benefits are:

- Significantly quicker establishment of new connections as TLS handshake is only done on the startup of the client

- More realistic traffic pattern

Besides, Cloak allows multiple users to use one server **on a single port**. QoS restrictions such as bandwidth limitation and data cap can also be managed.

## Setup Instructions for the administrator of the server
0. [Install and configure shadowsocks-libev on your server](https://github.com/shadowsocks/shadowsocks-libev#installation)
1. Clone this repo onto your server
2. Build and run cmd/keygen -k. The base64 string before the comma is the public key, the one after the comma is the private key
3. Run cmd/keygen -u. This will be used as the AdminUID
4. Put the private key and the AdminUID you obtained previously into config/ckserver.json
5. Edit the configuration file of shadowsocks-libev (default location is /etc/shadowsocks-libev/config.json). Let `server_port` be `443`, `plugin` be the full path to the ck-server binary and `plugin_opts` be the full path to ckserver.json. If the fields `plugin` and `plugin_opts` were not present originally, add these fields to the config file.
6. Run ss-server as root (because we are binding to TCP port 443)

### If you want to add more users
1. Run cmd/keygen -u to generate a new UID
2. On your client, run `ck-client -a -c <path-to-ckclient.json>` to enter admin mode
3. Input as prompted, that is your ip:port of the server and your AdminUID. Enter 4 to create a new user.
4. Enter the UID in your ckclient.json as the prompted UID, enter SessionsCap (maximum amount of concurrent sessions a user can have), UpRate and DownRate (in bytes/s), UpCredit and DownCredit (in bytes) and ExpiryTime (as a unix epoch)
5. Give your PUBLIC key and the newly generated UID to the new user

Note: the user database is persistent as it's in-disk. You don't need to add the users again each time you start ck-server.

## Instructions for clients
0. Install and configure a version of shadowsocks client that supports plugins (such as shadowsocks-libev and shadowsocks-windows)
1. Clone this repo and build cmd/ck-client
2. Obtain the PUBLIC key and your UID (or the AdminUID, if you are the server admin) from the administrator of your server
3. Put the public key and the UID you obtained into config/ckclient.json
4. Configure your shadowsocks client with your server information. The field `plugin` should be the path to ck-server binary and `plugin_opts` should be the path to ckclient.json
