open-quantum-safe/openssh-portable OQS-master snapshot 2018-11
==============================================================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.  

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.  

**open-quantum-safe/openssh-portable** is an integration of liboqs into (a fork of) OpenSSH.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

This branch of our fork of OpenSSH can be used with the following versions of liboqs:

- **liboqs master branch** 0.1.0
- **liboqs nist-branch** 2018-11 snapshot

Release notes
=============

**This is a release candidate for the OQS fork of OpenSSH, not a final release.**. 
This snapshot of the OQS fork of OpenSSH was released on TODO.  Its release page on Github is TODO.

What's New
----------

This is the first snapshot release of the OQS fork of OpenSSH.

It is based on the upstream OpenSSH 7.7 portable 1 release.

It provides:

- post-quantum key exchange in SSH 2
- hybrid (post-quantum + elliptic curve) key exchange in SSH 2

It can build against either liboqs master branch or liboqs nist-branch.  

Future work
-----------

Snapshot releases of the OQS fork of OpenSSH will be made approximately bi-monthly.  These will include syncing the branch with upstream releases of OpenSSH, and changes required to sync with new releases of liboqs.
