OQS-OpenSSH snapshot 2020-06-rc1
================================

About
-----

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.  More information on OQS can be found on our website: https://openquantumsafe.org/ and on Github at https://github.com/open-quantum-safe/.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.

**OQS-OpenSSH** is an integration of liboqs into (a fork of) OpenSSH.  The goal of this integration is to provide easy prototyping of quantum-resistant cryptography.  The integration should not be considered "production quality".

Release notes
=============

This is release candidate 1 for the 2020-06 snapshot release of OQS-OpenSSH. This release candidate was released on June 23, 2020. Its release page on GitHub is https://github.com/open-quantum-safe/openssh/releases/tag/OQS-OpenSSH-snapshot-2020-06-rc1.

What's New
----------

This is the third snapshot release of the OQS fork of OpenSSH.  It is based on OpenSSH 7.9 portable 1.

What's New
----------

- Uses the updated NIST Round 2 submissions added to liboqs 0.3.0, as described in the [liboqs release notes](https://github.com/open-quantum-safe/liboqs/blob/master/RELEASE.md).
