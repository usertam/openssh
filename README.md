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

open-quantum-safe/openssh-portable periodically updated to track the original OpenSSH code (openssh/openssh-portable).  The OQS-master branch of open-quantum-safe/openssh-portable is currently based on **OpenSSH version 7.7** (Git tag V_7_7_P1).

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

open-quantum-safe/openssh currently implements hybrid key exchange methods and PQ-only key exchange methods using the the following post-quantum key encapsulation mechanisms from liboqs:

- BIKE (only available if liboqs is built with BIKE enabled)
- FrodoKEM
- SIKE
- NewHope
- oqsdefault (see the "oqsdefault KEM" section below)

See https://github.com/open-quantum-safe/liboqs/blob/master/README.md for more information about each of the above PQ key encapsulation mechanisms.

Building on Linux and macOS
---------------------------

Builds have been tested on macOS Sierra 10.12.6, macOS High Sierra 10.13.4, and Amazon Linux AMI 2018.03 (AWS EC2).

### Step 0: Install dependencies

**On macOS**: You need to install several tools using `brew`:

	brew install autoconf automake libtool openssl

You might have to install xcode for zlib dependency:

    xcode-select --install

**On Ubuntu**: You need to install several tools using `apt`:

	sudo apt install make autoconf automake git libtool openssl zlib1g-dev libssl-dev


### Step 1: Build and install liboqs

First, you must download and build liboqs.  You will need to specify a path to install liboqs in during configure time; we recommend that you install in a special-purpose directory, rather than the global `/usr` or `/usr/local` directories.  As a summary:

	git clone -b master --single-branch https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	autoreconf -i
	./configure --prefix=<path-to-install-liboqs> --with-pic=yes --enable-shared=no
	make -j
	make install
	rm -f <path-to-install-liboqs>/lib/liboqs.so*

Alternatively, you can compile OpenSSH against liboqs nist-branch using the following instructions:

	git clone -b nist-branch --single-branch https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	make
	make install PREFIX=<path-to-install-liboqs>
	rm -f <path-to-install-liboqs>/lib/liboqs.so*

### Step 2: Build fork of OpenSSH

Next, you can build and install our fork of OpenSSH:

	export LIBOQS_INSTALL= TODO: your-install-location
	export OPENSSH_INSTALL= TODO: another-install-location
	git clone https://github.com/open-quantum-safe/openssh-portable.git
	cd openssh-portable
	autoreconf

For Ubuntu 16.04 and MacOS, try the following:

	./configure --enable-pq-kex --enable-hybrid-kex      \
				--with-ssl-dir=<path-to-openssl>/include \
				--with-ldflags=-L<path-to-openssl>/lib   \
				--prefix=$OPENSSH_INSTALL                \
				--sysconfdir=$OPENSSH_INSTALL            \
				--with-liboqs-dir=$LIBOQS_INSTALL
	make -j
	make install

On Ubuntu 18.04, some modifications are required due to the openssl version:

	apt install openssl1.0 libssl1.0-dev  # WARNING: removes existing libssl dev pkg!
	./configure --enable-pq-kex --enable-hybrid-kex \
				--with-ldflags=-L/usr/lib/ssl1.0    \
				--prefix=$OPENSSH_INSTALL           \
				--sysconfdir=$OPENSSH_INSTALL       \
				--with-liboqs-dir=$LIBOQS_INSTALL
	make -j
	make install

On Linux:

- You may need to create the privilege separation directory:

		sudo mkdir -p -m 0755 /var/empty

- You may need to create the privilege separation user:

		sudo groupadd sshd
		sudo useradd -g sshd -c 'sshd privsep' -d /var/empty -s /bin/false sshd

Notes about building OpenSSH:

- `--enable-pq-kex` enables PQ-only key exchange methods.
- `--enable-hybrid-kex` enables hybrid key exchange methods.
- On some platforms such as Ubuntu, you may not need to specify the `--with-ssl-dir` and `--with-ldflags` options as OpenSSH-configure automatically detect your OpenSSL installation.
- If you do not use `--enable-shared=no` when building liboqs master, you may encounter problems with shared libraries when building/installing/running OpenSSH.  These can be resolved by judiciously setting `LD_LIBRARY_PATH`, but it is easier to simply build liboqs master with *only* static libraries for OpenSSH to link against.
- We recommend that you install this fork of OpenSSH in a non-system directory (i.e., not `/usr` or `/usr/local`)
- With OpenSSL installed via brew on macOS, your command might be:

		./configure --enable-pq-kex --enable-hybrid-kex --with-ssl-dir=/usr/local/opt/openssl/include --with-ldflags=-L/usr/local/opt/openssl/lib --prefix=<path-to-install-openssh> --sysconfdir=<path-to-install-openssh> --with-liboqs-dir=<path-to-liboqs>

Running
-------

### Client/server demo

In one terminal, run a server:

	sudo <path-to-openssh>/sbin/sshd -p 2222 -d

The server automatically supports all available hybrid and PQ-only key exchange methods.  `sudo` is required on Linux so that sshd can read the shadow password file.

In another terminal, run a client:

	<path-to-openssh>/bin/ssh -l <username> -o 'KexAlgorithms=LIBOQSALGORITHM' -p 2222 localhost

where `LIBOQSALGORITHM` is one of the following:

_Hybrid key exchange methods:_

	ecdh-nistp384-bike1-L1-sha384@openquantumsafe.org
	ecdh-nistp384-bike1-L3-sha384@openquantumsafe.org
	ecdh-nistp384-bike1-L5-sha384@openquantumsafe.org
	ecdh-nistp384-frodo-640-aes-sha384@openquantumsafe.org
	ecdh-nistp384-frodo-976-aes-sha384@openquantumsafe.org
	ecdh-nistp384-sike-503-sha384@openquantumsafe.org
	ecdh-nistp384-sike-751-sha384@openquantumsafe.org
	ecdh-nistp384-newhope-512-sha384@openquantumsafe.org
	ecdh-nistp384-newhope-1024-sha384@openquantumsafe.org
	ecdh-nistp384-oqsdefault-sha384@openquantumsafe.org

_PQ-only key exchange methods:_

	bike1-L1-sha384@openquantumsafe.org
	bike1-L3-sha384@openquantumsafe.org
	bike1-L5-sha384@openquantumsafe.org
	frodo-640-aes-sha384@openquantumsafe.org
	frodo-976-aes-sha384@openquantumsafe.org
	sike-503-sha384@openquantumsafe.org
	sike-751-sha384@openquantumsafe.org
	newhope-512-sha384@openquantumsafe.org
	newhope-1024-sha384@openquantumsafe.org
	oqsdefault-sha384@openquantumsafe.org

### Automated tests

To test the build, run:

	make tests

oqsdefault KEM
--------------

liboqs can be configured at compile-time to use any of its algorithms as its "default" algorithm.  If OpenSSH is told to use `oqsdefault`, then it will use whichever KEM algorithm was set as the default in liboqs at compile time.

The purpose of this option is as follows.  liboqs master branch and liboqs nist-branch contain different subsets of algorithms.  We will make most algorithms from liboqs master branch available as a named key exchange method in OpenSSH.  However, there are significantly more algorithms supported in liboqs nist-branch than liboqs master branch, and we will not be explicitly making each nist-branch algorithm available as a named key exchange method in OpenSSH.  It is still possible to prototype KEMs from liboqs master branch or liboqs nist-branch that were not made available as named key exchange methods in OpenSSH using the `oqsdefault` key exchange method in OpenSSH by changing the default mapping in liboqs and then recompiling.

1. Recompile liboqs with your preferred default algorithm:
	- For liboqs master branch:
		- `cd liboqs`
		- Edit `src/kem/kem.h` and change `#define OQS_KEM_DEFAULT` to map to your preferred algorithm
		- `make clean`
		- `make -j8`
		- `make install`
	- For liboqs nist-branch:
		- `cd liboqs`
		- `make clean`
		- `make -j8 KEM_DEFAULT=newhope_1024_cca_kem` (or whichever algorithm you prefer)
		- `make install PREFIX=<path-to-install-liboqs>`
		- `rm <path-to-install-liboqs>/lib/liboqs.so`
2. Recompile OpenSSH against the newly build liboqs:
	- `cd openssh-portable`
	- `make clean`
	- `make -j8`
	- `make install`
3. Run `ssh` with `ecdh-nistp384-oqsdefault-sha384@openquantumsafe.org ` or `oqsdefault-sha384@openquantumsafe.org` for the `KexAlgorithms` option


License
-------

This fork is released under the same license(s) as Portable OpenSSH. More information about licensing can be found in the LICENSE file.

(Pre-draft) IETF Draft
----------------------

This repository contains an experimental (pre-draft) IETF draft for hybrid key exchange methods ECDH-SIKE and ECDH-BIKE. This documents has **not** been submitted to IETF.  See https://github.com/open-quantum-safe/openssh-portable/blob/OQS-master/ietf_pre_draft_sike_bike_hybrid_kex.txt.

Team
----

The Open Quantum Safe project is led by [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) (University of Waterloo) and [Douglas Stebila](https://www.douglas.stebila.ca/research/) (University of Waterloo).

### Contributors

Contributors to this fork of OpenSSH include:

- Eric Crockett (Amazon Web Services)
- Torben Hansen (Amazon Web Services and Royal Holloway, University of London)
- Douglas Stebila (University of Waterloo)
- Ben Davies (University of Waterloo)

Contributors to an earlier OQS fork of OpenSSH included:

- Mira Belenkiy (Microsoft Research)
- Karl Knopf (McMaster University)
- Christian Paquin (Microsoft Research)
