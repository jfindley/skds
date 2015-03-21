SKDS: Secure Key distribution system
======

A system for securely distributing secret keys across a large number of systems.

What is it for?
-----

TLS/SSL Keys.  Encrypted secrets for config management systems.  SSH keys.  Really, pretty much anything that needs to be distrubuted securely.

What can it do?
-----

Fully fledged administration system, built to be used by both large and small teams.  Scales easily to large numbers of admins and servers.

Fine-grained control over access - grant access to either individual or groups of admins and clients.

Currently, we support Linux and OSX.  It may well work on Windows, but that's not (yet) tested.

How do I use it?
-----

SKDS has a three-part architecture.

The server component holds the data in a database (sqlite and MySQL supported, Postgres could be added with little effort).

The client component is installed on the servers you're distributing the keys to.  This is designed to be very easy to mass-deploy, and requires little local configuration.

The admin component should be installed on the administrator(s) workstations.  Currently it has a CLI-only interface, although various GUI options are being considered.

Signed binaries are coming soon.  In the meantime, simply clone this repo and follow the instructions in the INSTALLING document.

How secure is it?
-----
Every effort has been made to make this software as secure as possible.
The server storing the keys never sees the secrets used to encrypt them, so a compromise of the server can never reveal the keys stored on it.

Furthermore, each secret is individually encrypted with a unique key, using the excellent NaCL cryptographic library (http://nacl.cr.yp.to/)

Additionally communication takes place over TLS connections, with certificate pinning to prevent impersonation.
