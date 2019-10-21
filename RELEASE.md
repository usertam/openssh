OQS-openssh snapshot 2019-11-dev
============================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**open-quantum-safe/openssh-portable** is an integration of liboqs into (a fork of) OpenSSH.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

Release notes
=============

This snapshot of the OQS fork of OpenSSH was released on TODO.  Its release page on Github is https://github.com/open-quantum-safe/openssh-portable/releases/tag/OQS-OpenSSH-snapshot-2019-11.

What's New
----------

This is the third snapshot release of the OQS fork of OpenSSH.  It is based on the upstream OpenSSH 7.9 portable 1 release.

What's New
----------

Update to use NIST Round 2 submissions added to liboqs 0.2.1.

### Key encapsulation mechanisms

- Update BIKE to Round 2 submission; removes `BIKE2-*`, `BIKE3-*`, `BIKE1-L5`, renames `BIKE1-L1` and `BIKE1-L3` to `BIKE1-L1-CPA` and `BIKE1-L3-CPA`, and adds `BIKE1-L1-FO` and `BIKE-L3-FO`

### Digital signature schemes

- TBA

Future work
-----------

Snapshot releases of the OQS fork of OpenSSH will be made every 2 to 3 months.  These will include syncing the branch with upstream releases of OpenSSH, and changes required to sync with new releases of liboqs.
