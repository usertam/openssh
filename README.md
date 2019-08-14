[![Build status image](https://circleci.com/gh/open-quantum-safe/openssh-portable/tree/OQS-master.svg?style=svg)](https://circleci.com/gh/open-quantum-safe/openssh-portable)

OQS-OpenSSH
==================================

[OpenSSH](https://openssh.org/) is an open-source implementation of the Secure Shell protocol.  ([View the original README](https://github.com/open-quantum-safe/openssh-portable/blob/OQS-master/README).)

OQS-OpenSSH is a fork of OpenSSH that adds quantum-safe key exchange and signature algorithms using [liboqs](https://github.com/open-quantum-safe/liboqs) for prototyping and evaluation purposes. This fork is not endorsed by the OpenSSH project.

- [Overview](#overview)
- [Status](#status)
  * [Limitations and Security](#limitations-and-security)
  * [Supported Algorithms](#supported-algorithms)
- [Quickstart](#quickstart)
  * [Building OQS-OpenSSH](#building-oqs-openssh)
  * [Running OQS-OpenSSH](#running-oqs-openssh)
- [License](#license)
- [Team](#team)
- [Acknowledgements](#acknowledgements)

## Overview

**liboqs** is an open source C library for quantum-resistant cryptographic algorithms. See [here](https://github.com/open-quantum-safe/liboqs/) for more information.

**OQS-OpenSSH** is a fork of OpenSSH that adds quantum-safe key exchange and signature algorithms using liboqs for prototyping purposes.

Both liboqs and this fork are part of the **Open Quantum Safe (OQS) project**, which aims to develop and prototype quantum-safe cryptography. More information about the project can be found [here](https://openquantumsafe.org/).

## Status

This fork is currently based on OpenSSH version **7.9** (Git tag V_7_9_P1), and is maintained for the purposes of prototyping and evaluating the use of quantum-safe cryptography in SSH. **It is at an experimental stage**, and has not received the same level of auditing and analysis that OpenSSH has received. See the [Limitations and Security](#limitations-and-security) section below for more information.

**We do not recommend relying on this fork in a production environment or to protect any sensitive data.**

liboqs is provided "as is", without warranty of any kind.  See [LICENSE.txt](https://github.com/open-quantum-safe/liboqs/blob/master/LICENSE.txt) for the full disclaimer.

This fork also contains an experimental (pre-draft) [IETF draft](https://github.com/open-quantum-safe/openssh-portable/blob/OQS-master/ietf_pre_draft_sike_bike_hybrid_kex.txt) for hybrid key exchange algorithms ECDH-SIKE and ECDH-BIKE. This document has **not** been submitted to IETF.

### Limitations and security
As research advances, the supported algorithms may see rapid changes in their security, and may even prove insecure against both classical and quantum computers.

We believe that the NIST Post-Quantum Cryptography standardization project is currently the best avenue to identifying potentially quantum-resistant algorithms, and strongly recommend that applications and protocols rely on the outcomes of the NIST standardization project when deploying post-quantum cryptography.

While at the time of this writing there are no vulnerabilities known in any of the quantum-safe algorithms used in this fork, it is advisable to wait on deploying quantum-safe algorithms until further guidance is provided by the standards community, especially from the NIST standardization project.

We realize some parties may want to deploy quantum-safe cryptography prior to the conclusion of the standardization project.  We strongly recommend such attempts make use of so-called **hybrid cryptography**, in which quantum-safe public-key algorithms are combined with traditional public key algorithms (like RSA or elliptic curves) such that the solution is at least no less secure than existing traditional cryptography. This fork provides the ability to use hybrid cryptography.

### Supported Algorithms

If an algorithm is provided by liboqs but is not listed below, it can still be used in the fork through [either one of two ways](https://github.com/open-quantum-safe/openssh-portable/wiki/Using-liboqs-supported-algorithms-in-the-fork).

#### Key Exchange

The following quantum-safe algorithms from liboqs are supported (assuming they have been enabled in liboqs):

- `oqsdefault` (see [here](https://github.com/open-quantum-safe/openssh-portable/wiki/Using-liboqs-supported-algorithms-in-the-fork) for what this denotes)
- `bike1-L1`, `bike1-L3`, `bike1-L5`
- `bike2-L1`, `bike2-L3`, `bike2-L3`
- `frodo-640-aes`, `frodo-976-aes`
- `kyber-512`, `kyber-768`, `kyber-1024`
- `newhope-512`, `newhope-1024`
- `ntru-hps-2048-509`, `ntru-hps-2048-677`
- `saber-lightsaber`, `saber-saber`, `saber-firesaber`
- `sidh-503`, `sidh-751`
- `sike-503`, `sike-751`

The following hybrid algorithms are supported; they combine a quantum-safe algorithm listed above with ECDH that uses NIST's P384 curve:

- `ecdh-nistp384-<KEX>`, where ``<KEX>`` is any one of the algorithms listed above.

#### Digital Signature

The following digital signature algorithms from liboqs are supported (assuming they have been enabled in liboqs):

- `oqsdefault` (see [here](https://github.com/open-quantum-safe/openssh-portable/wiki/Using-liboqs-supported-algorithms-in-the-fork) for what this denotes)
- `dilithium2`, `dilithium4`
- `mqdss3148`
- `picnicl1fs`, `picnicl1ur`, `picnicl3fs`,`picnicl3ur`, `picnicl5fs`, `picnicl5ur`
- `picnic2l1fs`, `picnic2l3fs`
- `qteslai`, `qteslaiiispeed`, `qteslaiiisize`
- `sphincsharaka128frobust`

The following hybrid algorithms are supported; they combine a quantum-safe algorithm listed above with a traditional digital signature algorithm (`<SIG>` is any one of the algorithm listed above):

- if `<SIG>` has L1 security, then the fork provides the methods `rsa3072-<SIG>` and `p256-<SIG>`, which combine `<SIG>` with RSA3072 and with ECDSA using NIST's P256 curve respectively.
- if `<SIG>` has L3 security, the fork provides the method `p384-<SIG>`, which combines `<SIG>` with ECDSA using NIST's P384 curve.
- if `<SIG>` has L5 security, the fork provides the method `p521-<SIG>`, which combines `<SIG>` with ECDSA using NIST's P521 curve.


## Quickstart

The steps below have been confirmed to work on macOS 10.14 (clang 10.0.0), Ubuntu 14.04 (gcc-5), Ubuntu 16.04 (gcc-5), and Ubuntu 18.04.1 (gcc-7).

### Building OQS-OpenSSH

### Step 0: Install dependencies

For **Ubuntu**, you need to install the following packages:

	sudo apt install autoconf automake gcc libtool libssl-dev make unzip xsltproc zlib1g-dev

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

You will need to specify a path to install liboqs in during configure time; we recommend that you install in a special-purpose directory, rather than the global `/usr` or `/usr/local` directories.

	git clone -b master --single-branch https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	autoreconf -i
	./configure --prefix=<path-to-openssh-dir>/oqs --with-pic=yes --enable-shared=no
	make -j
	make install
	rm -f <path-to-install-liboqs>/lib/liboqs.so*

Building liboqs requires your system to have OpenSSL already installed.  configure will detect it if it is located in a standard location, such as `/usr` or `/usr/local/opt/openssl` (for brew on macOS).  Otherwise, you may need to specify it with `--with-openssl=<path-to-system-openssl-dir>`.

### Step 2: Build the fork

Next, build and install our fork of OpenSSH:

	export LIBOQS_INSTALL=<path-to-liboqs>
	export OPENSSH_INSTALL=<path-to-install-openssh>
	git clone https://github.com/open-quantum-safe/openssh-portable.git
	cd openssh-portable
	autoreconf

For Ubuntu 16.04 and macOS, try the following:

	./configure --with-ssl-dir=<path-to-openssl>/include \
	            --with-ldflags=-L<path-to-openssl>/lib   \
	            --prefix=$OPENSSH_INSTALL                \
	            --sysconfdir=$OPENSSH_INSTALL            \
	            --with-liboqs-dir=$LIBOQS_INSTALL
	make -j
	make install

On Ubuntu 18.04, some modifications are required due to the default OpenSSL version:

	./configure --with-ldflags=-L/usr/lib/ssl1.0      \
	            --prefix=$OPENSSH_INSTALL             \
	            --sysconfdir=$OPENSSH_INSTALL         \
	            --with-liboqs-dir=$LIBOQS_INSTALL
	make -j
	make install

To test the build, run:

	make tests

### Running OQS-OpenSSH

The following instructions explain how to establish an SSH connection that uses quantum-safe key exchange and authentication.

#### Generating post-quantum authentication keys

To setup post-quantum authentication, the server (and optionally, the client) need to generate post-quantum keys. In what follows, `<SIG>` is one of the quantum-safe digital signature algorithms listed in [Supported Algorithms](#supported-algorithms) section above.

The server generates its key files with the right permissions, and then generates its key pair:

	mkdir ~/ssh_server/
	chmod 700 ~/ssh_server/
	touch ~/ssh_server/authorized_keys
	chmod 600 ~/ssh_server/authorized_keys
	<path-to-openssh>/bin/ssh-keygen -t ssh-<SIG> -f ~/ssh_server/id_<SIG>

To enable client-side public-key authentication, the client generates its key pair:

	mkdir ~/ssh_client/
	<path-to-openssh>/bin/ssh-keygen -t ssh-<SIG> -f ~/ssh_client/id_<SIG>

The server then adds the client's public key to its authorized keys

	cat ~/ssh_client/id_<SIG>.pub >> ~/ssh_server/authorized_keys

#### Establishing a quantum-safe SSH connection

In one terminal, run a server (the arguments between `[...]` can be omitted if only classical authentication is required):

	sudo <path-to-openssh>/sbin/sshd -p 2222 -d             \
	    -o KexAlgorithms=<OPENSSH_KEX_ALGORITHM>             \
	    [-o AuthorizedKeysFile=<absolute-path-to>/ssh_server/authorized_keys \
	     -o HostKeyAlgorithms=<OPENSSH_SIG_ALGORITHM>        \
	     -o PubkeyAcceptedKeyTypes=<OPENSSH_SIG_ALGORITHM>   \
	     -h <absolute-path-to>/ssh_server/id_<SIG>]

where `<OPENSSH_SIG_ALGORITHM>` is `ssh-<SIG>` (all in lowercase) and `<OPENSSH_KEX_ALGORITM>` can be one of:

- `<KEX>-sha384@openquantumsafe.org` (for post-quantum-only key exchange)
- `ecdh-nistp384-<KEX>-sha384@openquantumsafe.org` (for hybrid post-quantum and elliptic curve key exchange)

`<KEX>` and `<SIG>` are respectively one of the key exchange and signature (PQ-only or hybrid) algorithms listed in the [Supported Algorithms](#supported-algorithms) section above.

The `-o` options can also be added to the server/client configuration file instead of being specified on the command line.

The server automatically supports all available hybrid and PQ-only key exchange algorithms.  `sudo` is required on Linux so that sshd can read the shadow password file.

In another terminal, run a client(the arguments between `[...]` can be omitted if only classical authentication is required):

	<path-to-openssh>/bin/ssh -l                         \
	    -p 2222 localhost                                \
	    -o KexAlgorithms=<OPENSSH_KEX_ALGORITHM>          \
	   [-o HostKeyAlgorithms=<OPENSSH_SIG_ALGORITHM>      \
	    -o PubkeyAcceptedKeyTypes=<OPENSSH_SIG_ALGORITHM> \
	    -o StrictHostKeyChecking=no                      \
	    -i ~/ssh_client/id_<SIG>]

The `StrictHostKeyChecking` option is used to allow trusting the newly generated server key; alternatively, the key could be added manually to the client's trusted keys.

## License

This fork is released under the same license(s) as Portable OpenSSH. More information can be found in the [LICENSE](LICENSE) file.

## Team

The Open Quantum Safe project is led by [Douglas Stebila](https://www.douglas.stebila.ca/research/) and [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) at the University of Waterloo.

Contributors to this fork of OpenSSH include:

- Eric Crockett (Amazon Web Services)
- Ben Davies (University of Waterloo)
- Torben Hansen (Amazon Web Services and Royal Holloway, University of London)
- Christian Paquin (Microsoft Research)
- Douglas Stebila (University of Waterloo)
- Goutam Tamvada (University of Waterloo)

Contributors to an earlier OQS fork of OpenSSH included:

- Mira Belenkiy (Microsoft Research)
- Karl Knopf (McMaster University)

## Acknowledgments

Financial support for the development of Open Quantum Safe has been provided by Amazon Web Services and the Tutte Institute for Mathematics and Computing.

We'd like to make a special acknowledgement to the companies who have dedicated programmer time to contribute source code to OQS, including Amazon Web Services, evolutionQ, and Microsoft Research.

Research projects which developed specific components of OQS have been supported by various research grants, including funding from the Natural Sciences and Engineering Research Council of Canada (NSERC); see the source papers for funding acknowledgments.
