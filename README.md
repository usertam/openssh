open-quantum-safe/openssh-portable
==================================

**OpenSSH** is an open-source implementation of the Secure Shell protocol https://openssh.org/.  ([View the original README file for OpenSSH](https://github.com/open-quantum-safe/openssh-portable/blob/OQS-master/README).)

This repository contains a fork of OpenSSH that adds quantum-resistant key exchange algorithms using liboqs for prototyping purposes.

Overview
--------

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms.  See more about liboqs at [https://github.com/open-quantum-safe/liboqs/](https://github.com/open-quantum-safe/liboqs/), including a list of supported algorithms. OpenSSL can use either the [master](https://github.com/open-quantum-safe/liboqs/tree/master) or the [nist](https://github.com/open-quantum-safe/liboqs/tree/nist-branch) branch of liboqs; the former is recommended for normal uses of OpenSSH as included mechanisms follow a stricter set of requirements, the latter contains more algorithms and is better suited for experimentation.

**open-quantum-safe/openssh-portable** contains a fork of OpenSSH that adds quantum-safe key exchange algorithms using liboqs for prototyping purposes, specifically adding key exchange methods that use hybrid (post-quantum + traditional elliptic curve) or post-quantum-only algorithms.  The integration should not be considered "production quality".  The OQS-master branch of open-quantum-safe/openssh-portable is currently based on **OpenSSH version 7.7** (Git tag V_7_7_P1).

More information on OQS can be found on our website: [https://openquantumsafe.org/](https://openquantumsafe.org/).

Contents
--------

This branch ([OQS-master](https://github.com/open-quantum-safe/openssh-portable/tree/OQS-master)) integrates post-quantum key exchange from liboqs in SSH 2 in OpenSSH v7.7 portable 1.  

### Key exchange mechanisms

The following key exchange / key encapsulation methods from liboqs are supported (assuming they have been enabled in liboqs):

- `bike1-L1`, `bike1-L3`, `bike1-L5`
- `frodo-640-aes`, `frodo-976-aes`
- `newhope-512`, `newhope-1024`
- `sike-503`, `sike-751`
- `oqsdefault`

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

Lifecycle for open-quantum-safe/openssh-portable OQS-master branch
------------------------------------------------------------------

**Release cycle:** We aim to make releases of our fork of OpenSSH stable on a bi-monthly basis, either when there has been a new release of OpenSSH or when we have made changes to our fork.

See the README.md files of [liboqs master branch](https://github.com/open-quantum-safe/liboqs/blob/master/README.md) and [liboqs nist-branch](https://github.com/open-quantum-safe/liboqs/blob/nist-branch/README.md) for information about the algorithm lifecycle within the corresponding libraries.

**SSH compatibility:** The message format used in this fork is not standardized, and is subject to unilateral change at any time without regards to backwards compatibility with previous versions of this fork.

Building on Linux and macOS
---------------------------

Builds have been tested manually on macOS 10.14 (clang 10.0.0), Ubuntu 14.04 (gcc-5), Ubuntu 16.04 (gcc-5), and Ubuntu 18.04.1 (gcc-7).

### Step 0: Install dependencies

For **Ubuntu**, you need to install the following packages:

	sudo apt install autoconf automake gcc libtool libssl-dev make unzip xsltproc

For **Ubuntu 18.04**, you need to downgrade the version of OpenSSL.  (Ubuntu 18.04 bundles OpenSSL 1.1.0 by default,  but OpenSSH only supports building against OpenSSL 1.0.2 at present.)

	sudo apt install openssl1.0 libssl1.0-dev
	
Warning: this removes the existing libssl 1.1 development package.

On **Linux**, you also may need to do the following:

- You may need to create the privilege separation directory:

		sudo mkdir -p -m 0755 /var/empty

- You may need to create the privilege separation user:

		sudo groupadd sshd
		sudo useradd -g sshd -c 'sshd privsep' -d /var/empty -s /bin/false sshd

For **macOS**, you need to install the following packages using brew (or a package manager of your choice):

	brew install autoconf automake libtool openssl wget
	
### Step 1: Build and install liboqs

You can use the either the [master](https://github.com/open-quantum-safe/liboqs/tree/master) or the [nist](https://github.com/open-quantum-safe/liboqs/tree/nist-branch) branch of liboqs with the OQS-master branch of OpenSSH. Each branch support a different set of KEX/KEM mechanisms (see above).

You will need to specify a path to install liboqs in during configure time; we recommend that you install in a special-purpose directory, rather than the global `/usr` or `/usr/local` directories.

For the **master branch** of liboqs:

	git clone -b master --single-branch https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	autoreconf -i
    ./configure --prefix=<path-to-openssl-dir>/oqs --with-pic=yes --enable-shared=no --enable-openssl --with-openssl-dir=<path-to-system-openssl-dir>
	make -j
	make install
	rm -f <path-to-install-liboqs>/lib/liboqs.so*

On **Ubuntu**, `<path-to-system-openssl-dir>` is probably `/usr`.  On **macOS** with brew, `<path-to-system-openssl-dir>` is probably `/usr/local/opt/openssl`.

For the **nist branch** of liboqs:

	git clone -b nist-branch --single-branch https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	make -j
	make install-noshared PREFIX=<path-to-install-liboqs>

### Step 2: Build fork of OpenSSH

Next, you can build and install our fork of OpenSSH:

	export LIBOQS_INSTALL=<path-to-liboqs>
	export OPENSSH_INSTALL=<path-to-install-openssh>
	git clone https://github.com/open-quantum-safe/openssh-portable.git
	cd openssh-portable
	autoreconf

For Ubuntu 16.04 and macOS, try the following:

	./configure --enable-pq-kex --enable-hybrid-kex      \
	            --with-ssl-dir=<path-to-openssl>/include \
	            --with-ldflags=-L<path-to-openssl>/lib   \
	            --prefix=$OPENSSH_INSTALL                \
	            --sysconfdir=$OPENSSH_INSTALL            \
	            --with-liboqs-dir=$LIBOQS_INSTALL
	make -j
	make install

On Ubuntu 18.04, some modifications are required due to the default openssl version:

	./configure --enable-pq-kex --enable-hybrid-kex \
	            --with-ldflags=-L/usr/lib/ssl1.0    \
	            --prefix=$OPENSSH_INSTALL           \
	            --sysconfdir=$OPENSSH_INSTALL       \
	            --with-liboqs-dir=$LIBOQS_INSTALL
	make -j
	make install

Notes about building OpenSSH:

- `--enable-pq-kex` enables PQ-only key exchange methods.
- `--enable-hybrid-kex` enables hybrid key exchange methods.

Running
-------

### Client/server demo

In one terminal, run a server:

	sudo <path-to-openssh>/sbin/sshd -p 2222 -d

The server automatically supports all available hybrid and PQ-only key exchange methods.  `sudo` is required on Linux so that sshd can read the shadow password file.

In another terminal, run a client:

	<path-to-openssh>/bin/ssh -l <username> -o 'KexAlgorithms=LIBOQSALGORITHM' -p 2222 localhost

where `LIBOQSALGORITHM` is either:

- `X-sha384@openquantumsafe.org` (for post-quantum-only key exchange)
- `ecdh-nistp384-X-sha384@openquantumsafe.org` (for hybrid post-quantum and elliptic curve key exchange)

where `X` is one of the algorithms listed in the Contents section above.

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
		- `make -j`
		- `make install`
	- For liboqs nist-branch:
		- `cd liboqs`
		- `make clean`
		- `make -j KEM_DEFAULT=newhope_1024_cca_kem` (or whichever algorithm you prefer)
		- `make install-noshared PREFIX=<path-to-install-liboqs>`
2. Recompile OpenSSH against the newly build liboqs:
	- `cd openssh-portable`
	- `make clean`
	- `make -j`
	- `make install`
3. Run `ssh` with `ecdh-nistp384-oqsdefault-sha384@openquantumsafe.org ` or `oqsdefault-sha384@openquantumsafe.org` for the `KexAlgorithms` option.

License
-------

This fork is released under the same license(s) as Portable OpenSSH. More information about licensing can be found in the LICENSE file.

(Pre-draft) IETF Draft
----------------------

This repository contains an experimental (pre-draft) IETF draft for hybrid key exchange methods ECDH-SIKE and ECDH-BIKE. This documents has **not** been submitted to IETF.  See https://github.com/open-quantum-safe/openssh-portable/blob/OQS-master/ietf_pre_draft_sike_bike_hybrid_kex.txt.

Team
----

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

### Contributors

Contributors to this fork of OpenSSH include:

- Eric Crockett (Amazon Web Services)
- Ben Davies (University of Waterloo)
- Torben Hansen (Amazon Web Services and Royal Holloway, University of London)
- Christian Paquin (Microsoft Research)
- Douglas Stebila (University of Waterloo)

Contributors to an earlier OQS fork of OpenSSH included:

- Mira Belenkiy (Microsoft Research)
- Karl Knopf (McMaster University)

### Support

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Tutte Institute for Mathematics and Computing.  

We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, evolutionQ, and Microsoft Research.  

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see the source papers for funding acknowledgments.
