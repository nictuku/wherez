Wherez
======
Wherez (Where Zee) is a p2p program and library that lets you register
and discover sibling servers in the network based on a shared 
passphrase. It uses the Mainline DHT network to advertise its own 
existence and to look for other nodes that are running with the same 
passphrase.

It authenticates sibling peers using an HMAC-based mechanism.

Example applications:

- find the location of your company's doozerd, Chubby or DNS servers.
- robust way for stolen notebooks to "phone home".
- register and locate servers in a corporate network based on
function, by using different passphrases for the DNS server, LDAP
server, etc.

This software is in early stages of development.

This repository contains a library and a command-line tool.

Example CLI usage:

    $ cd wherez ; go build
    $ ./wherez 8080 "wherezexample"
    14.15.87.13:3111
    77.66.77.22:3211
    16.97.12.12:3312

8080 is your application's port to be advertised to other wherez nodes.

The IP:port pairs that appear are those peers provided by Wherez nodes that have been contacted and authenticated.
