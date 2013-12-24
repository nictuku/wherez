Wherez
======
Wherez provides a robust way to find a list of peers using the DHT network to find
peers and a cryptographic challenge to authenticate them.

Wherez nodes find each other through shared secret passphrases.

Example usage:

$ cd wherez ; go build
$ ./wherez 8080 "dude wherez my car?"
14.15.87.13:3111
77.66.77.22:3211
16.97.12.12:3312

8080 is your application's port to be advertised to other wherez nodes.

The IP:port pairs listed are peers provided by Wherez nodes that have been contacted and authenticated.
