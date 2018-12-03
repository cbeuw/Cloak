# Cloak
A shadowsocks plugin that obfuscates the traffic as normal HTTPS traffic and disguises the proxy server as a normal webserver.

**This is an active WIP. The functionality is incomplete, the code is messy and nothing has been properly tested (though the core multiplexing part seems to work fine). Everything is subject to change.**

This project is based on [GoQuiet](https://github.com/cbeuw/GoQuiet). The most significant difference is that, in GoQuiet, a new TCP connection is establieshed and a TLS handshake is done between the client and the proxy server each time a connection is made to ssclient, whereas in Cloak all the traffic is multiplexed through a fixed amount of consistant TCP connections between the client and the proxy server. The major benefits are:

- Significantly quicker establishment of new connections as TLS handshake is only done on the startup of the client

- More realistic traffic pattern

Besides, Cloak allows multiple users to use one server **on a single port**. QoS restrictions such as bandwidth limitation and data cap can also be managed.

## Setup Instructions
(unless specified, all UID are presented in base64 encoded form)
1. Clone the repo
2. Build and run cmd/keygen. You may want to keep the public and private keys somewhere
3. Substitute the fields in config/ckserver.json and config/ckclient.json with the output of keygen
4. Run keygen again and copy only the UID to AdminUID in ckserver.json. This is your AdminUID.
5. On your server, run `ss-server -c <path-to-ss-config> --plugin <path-to-ck-server-binary> --plugin-opts "<path-to-ckserver.json>"`
6. On your client, run `ck-client -a -c <path-to-ckclient.json>` to enter admin mode
7. Input as prompted, that is your ip:port of the server and your AdminUID. Enter 4 to create a new user.
8. Enter the UID in your ckclient.json as the prompted UID, enter SessionsCap (maximum amount of concurrent sessions a user can have), UpRate and DownRate (in bytes/s), UpCredit and DownCredit (in bytes) and ExpiryTime (as a unix epoch)
9. Ctrl-C to quit admin mode, start Shardowsocks with `ss-local -c <path-to-ss-config> --plugin <path-to-ck-client-binary> --plugin-opts "<path-to-ckclient.json>"`

If you want to add a new user, just run keygen again and put the UID into ckclient.json of the new user (don't touch the public and the private key), and do steps 6-8 again to add the new user into the server.

The user database is persistent as it's in-disk. You don't need to add the users again each time you start ck-server.
