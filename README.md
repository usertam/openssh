open-quantum-safe/openssh-portable
==================================

**This code is experimental -- do NOT use in production or to protect secrets!  See the Limitations section below.**

OpenSSH is an open-source implementation of the Secure Shell protocol https://openssh.org/.

This repository contains a fork of OpenSSH that adds quantum-safe key exchange algorithms using liboqs for prototyping purposes.

This README.md contains information about the modifications to OpenSSH by the Open Quantum Safe project.  For information about OpenSSH,
[see the original README file for OpenSSH](https://github.com/open-quantum-safe/openssh-portable/blob/master/README).

Overview
--------

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.

**liboqs** is an open source C library for quantum-safe cryptographic algorithms.  See more about liboqs at [https://github.com/open-quantum-safe/liboqs/](https://github.com/open-quantum-safe/liboqs/), including a list of supported algorithms.

**open-quantum-safe/openssh-portable** contains a fork of OpenSSH that adds quantum-safe key exchange algorithms using liboqs for prototyping purposes, specifically adding key exchange methods that use hybrid (post-quantum + traditional elliptic curve) or post-quantum-only algorithms.  The integration should not be considered "production quality".

More information on OQS can be found on our website: https://openquantumsafe.org/.

Limitations and security
------------------------

liboqs is designed for prototyping and evaluating quantum-resistant cryptography.  Security of proposed quantum-resistant algorithms may rapidly change as research advances, and may ultimately be completely insecure against either classical or quantum computers.  

We believe that the NIST Post-Quantum Cryptography standardization project is currently the best avenue to identifying potentially quantum-resistant algorithms.  liboqs does not intend to "pick winners", and we strongly recommend that applications and protocols rely on the outcomes of the NIST standardization project when deploying post-quantum cryptography.  

We acknowledge that some parties may want to begin deploying post-quantum cryptography prior to the conclusion of the NIST standardization project.  We strongly recommend that any attempts to do make use of so-called **hybrid cryptography**, in which post-quantum public-key algorithms are used alongside traditional public key algorithms (like RSA or elliptic curves) so that the solution is at least no less secure than existing traditional cryptography.

liboqs is provided "as is", without warranty of any kind.  See [LICENSE.txt](https://github.com/open-quantum-safe/liboqs/blob/ds-nist-branch/LICENSE.txt) for the full disclaimer.

The integration of liboqs into our fork of OpenSSH is currently at an experimental stage.  This fork of OpenSSH has not received the same level of auditing and analysis that OpenSSH has received.  At this stage, we do not recommend relying on it in any production environment or to protect any sensitive data.

The OQS fork of OpenSSH is not endorsed by with the OpenSSH project.

This fork is developed for the purposes of prototyping and evaluating the use of post-quantum cryptography in SSH, and is not intended for use in production environments to protect the transmission of sensitive information.  

At the time of writing, there are no vulnerabilities or weaknesses known in any of the post-quantum key exchange algorithms used in this fork.  However, it is advisable to wait on deploying post-quantum algorithms until further guidance is provided by the standards community, especially from the NIST Post-Quantum Cryptography project.

This fork does not yet contain support for post-quantum authentication.

The message format used in this fork is not standardized, and is subject to unilateral change at any time without regards to backwards compatibility with previous versions of this fork.

Contents
--------

### Key exchange mechanisms

open-quantum-safe/openssh currently implements hybrid key exchange methods and PQ-only key exchange methods using the the following post-quantum key exchange mechanisms from liboqs:

- `kex_rlwe_newhope`
- `kex_lwe_frodo`
- `kex_sidh`
- `kex_sike`
- `kex_bike`
- `kex_ntru`

See https://github.com/open-quantum-safe/liboqs/blob/master/README.md for more information about each of the above PQ KEX mechanisms.

Building on Linux and macOS
---------------------------

Builds have been tested on macOS Sierra 10.12.6, macOS High Sierra 10.13.4, and Amazon Linux AMI 2018.03 (AWS EC2).

### Step 0: Install dependencies

**On macOS**: You need to install several tools using `brew`:

	brew install autoconf automake libtool openssl

You might have to install xcode for zlib dependency:

    xcode-select --install

**On Ubuntu**: You need to install several tools using `apt`:

	sudo apt install autoconf automake git libtool openssl zlib1g-dev libssl-dev


### Step 1: Build and install liboqs

First, you must download and build liboqs.  You must use the "master" branch version of liboqs that uses the old key exchange API, located at https://github.com/open-quantum-safe/liboqs/tree/master.

Follow the instructions there to download and build that branch of liboqs.  You will need to specify a path to install liboqs in during configure time; we recommend that you install in a special-purpose directory, rather than the global `/usr` or `/usr/local` directories.  As a summary:

	git clone -b master --single-branch https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	autoreconf -i
	./configure --prefix=/path/to/install/liboqs/install --with-pic=yes
	make
	make install

### Step 2: Build fork of OpenSSH

Next, you can build and install our fork of OpenSSH:

	git clone https://github.com/open-quantum-safe/openssh-portable.git
	cd openssh-portable
	autoreconf
	./configure --enable-pq-kex --enable-hybrid-kex --with-ssl-dir=/path/to/openssl/include --with-ldflags=-L/path/to/openssl/lib --prefix=/path/to/openssh/install/dir --sysconfdir=/path/to/config/files/dir --with-liboqs-dir=/path/to/install/liboqs/install
	make
	make install

(On some platforms such as Ubuntu, you may not need to specify the `--with-ssl-dir` and `--with-ldflags` options as OpenSSH-configure automatically detect your OpenSSL installation.)

`--enable-pq-kex` enables PQ-only key exchange methods. `--enable-hybrid-kex` enables hybrid key exchange methods.

The configuration script will automatically disable the NTRU based hybrid/PQ-only key exchange method if sandbox mode is not disabled.

Running
-------

### Client/server demo

In one terminal, run a server:

	/path/to/install/openssh/in/sbin/sshd -p 2222 -d

The server automatically supports all available hybrid and PQ-only key exchange methods.

In another terminal, run a client:

	/path/to/install/openssh/in/bin/ssh -l <username> -o 'KexAlgorithms=LIBOQSALGORITHM' -p 2222 localhost

where `LIBOQSALGORITHM` is one of the following:

_Hybrid key exchange methods:_

    ecdh-nistp384-frodo-recommended-sha384@openquantumsafe.org
    ecdh-nistp384-newhope-sha384@openquantumsafe.org
    ecdh-nistp384-ntru-sha384@openquantumsafe.org
    ecdh-nistp384-sidh-msr503-sha384@openquantumsafe.org
    ecdh-nistp384-sidh-msr751-sha384@openquantumsafe.org
    ecdh-nistp384-sike-503-sha384@openquantumsafe.org
    ecdh-nistp384-sike-751-sha384@openquantumsafe.org
    ecdh-nistp384-bike1-L1-sha384@openquantumsafe.org
    ecdh-nistp384-bike1-L3-sha384@openquantumsafe.org
    ecdh-nistp384-bike1-L5-sha384@openquantumsafe.org

_PQ-only key exchange methods:_

    frodo-recommended-sha384@openquantumsafe.org
    newhope-sha384@openquantumsafe.org
    ntru-sha384@openquantumsafe.org
    sidh-msr503-sha384@openquantumsafe.org
    sidh-msr751-sha384@openquantumsafe.org
    sike-503-sha384@openquantumsafe.org
    sike-751-sha384@openquantumsafe.org
    bike1-L1-sha384@openquantumsafe.org
    bike1-L3-sha384@openquantumsafe.org
    bike1-L5-sha384@openquantumsafe.org

BIKE based hybrid/PQ-only key exchange methods are only available if the libOQS library has been patched with an appropriate BIKE patch.

### Automated tests

To test the build, run:

    make tests

License
-------

This fork is released under the same license(s) as Portable OpenSSH. More information about licensing can be found in the LICENSE file.

(Pre-draft) IETF Draft
----------------------

This repository contains an experimental (pre-draft) IETF draft for hybrid key exchange methods ECDH-SIKE and ECDH-BIKE. This documents has **not** been submitted to IETF.  See https://github.com/open-quantum-safe/openssh-portable/blob/OQS-master/ietf_pre_draft_sike_bike_hybrid_kex.txt.

Team
----

The Open Quantum Safe project is lead by [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) (University of Waterloo) and [Douglas Stebila](https://www.douglas.stebila.ca/research/) (McMaster University).

### Contributors

Contributors to this fork of OpenSSH include:

- Torben Hansen (Amazon AND Royal Holloway, University of London)
