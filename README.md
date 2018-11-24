# Cloak
A shadowsocks plugin that obfuscates the traffic as normal HTTPS traffic and disguises the proxy server as a normal webserver.

**This is an active WIP. The functionality is incomplete, the code is messy and nothing has been properly tested (though the core multiplexing part seems to work fine). Everything is subject to change.**

This project is based on [GoQuiet](https://github.com/cbeuw/GoQuiet). The most significant difference is that, in GoQuiet, a new TCP connection is establieshed and a TLS handshake is done between the client and the proxy server each time a connection is made to ssclient, whereas in Cloak all the traffic is multiplexed through a fixed amount of consistant TCP connections between the client and the proxy server. The major benefits are:

- Significantly quicker establishment of new connections as TLS handshake is only done on the startup of the client

- More realistic traffic pattern

Besides, Cloak allows multiple users to use one server **on a single port**. QoS restrictions such as bandwidth limitation and data cap can also be managed.
