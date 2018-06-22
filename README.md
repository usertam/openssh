open-quantum-safe/openssh-portable
==================================

This code is experimental - do NOT use in production or to protect secrets!

This repository contains a fork of OpenSSH that adds quantum-safe key exchange algorithms using liboqs for prototyping purposes.

This README.md contains information about the modifications to OpenSSH by the Open Quantum Safe project.  For information about OpenSSH,
([see the original README file for OpenSSH](https://github.com/open-quantum-safe/openssh-portable/blob/master/README).)

Overview
--------

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.

**liboqs** is an open source C library for quantum-safe cryptographic algorithms.  See more about liboqs at [https://github.com/open-quantum-safe/liboqs/](https://github.com/open-quantum-safe/liboqs/), including a list of supported algorithms.

OpenSSH is an open-source implementation of the Secure Shell protocol [https://openssh.org/](https://openssh.org/).

This repository contains a fork of OpenSSH that adds quantum-safe key exchange algorithms using liboqs for prototyping purposes. Specifically, SSH hybrid and PQ-only key exchange methods.

See the Limitations section below.


Contents
--------

### Key exchange mechanisms

**NEED UPDATE**

open-quantum-safe/openssh currently implements hybrid key exchange methods and PQ-only key exchange methods using the the following post-quantuym key exchange mechanisms:

- `kex_rlwe_newhope`: "NewHope": key exchange from the ring learning with errors problem (Alkim, Ducas, Pöppelmann, Schwabe, *USENIX Security 2016*, [https://eprint.iacr.org/2015/1092](https://eprint.iacr.org/2015/1092)) (using the reference C implementation of NewHope from [https://github.com/tpoeppelmann/newhope](https://github.com/tpoeppelmann/newhope))
- `kex_lwe_frodo`: "Frodo": key exchange from the learning with errors problem (Bos, Costello, Ducas, Mironov, Naehrig, Nikolaenko, Raghunathan, Stebila, *ACM Conference on Computer and Communications Security 2016*, [https://eprint.iacr.org/2016/659](https://eprint.iacr.org/2016/659))
- `kex_sidh?`: key exchange from the supersingular isogeny Diffie-Hellman problem (Costello, Naehrig, Longa, *CRYPTO 2016*, [https://eprint.iacr.org/2016/413](https://eprint.iacr.org/2016/413)), using the implementation of Microsoft Research [https://www.microsoft.com/en-us/research/project/sidh-library/](https://www.microsoft.com/en-us/research/project/sidh-library/)
- `kex_sike?`:
- `kex_bike?`:
- `kex_ntru?`:


Building and Running
--------------------

Builds have been tested on macOS Sierra 10.12.6 and Amazon Linux AMI 2018.03 (AWS EC2)

### Install dependencies for macOS

You need to install several tools using `brew`:

	brew install autoconf automake libtool openssl 

You might have to install xcode for zlib dependency:

    xcode-select --install

### Install dependencies for Ubuntu

You need to install several tools using `apt`:

	sudo apt install autoconf automake git libtool openssl zlib1g-dev libssl-dev

### Building

First, you will need to download and build `liboqs` (master branch):

    git clone -b master --single-branch https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	autoreconf -i
	./configure --prefix=/path/to/install/liboqs/install
	make
	make install

Next, you can build and install OpenSSH:

	git clone https://github.com/open-quantum-safe/openssh-portable.git
	cd openssh-portable
	autoreconf
	./configure --enable-pq-kex --enable-hybrid-kex --with-ssl-dir=/path/to/openssl/include --with-ldflags=/path/to/openssl/lib --prefix=/path/to/openssh/install/dir --sysconfdir=/path/to/config/files/dir --with-liboqs-dir=/path/to/install/liboqs/install
	make
	make install

(On some platforms such as Ubuntu, you may not need to specify the `--with-ssl-dir` and `--with-ldflags` options as OpenSSH-configure automatically detect your OpenSSL installation.)

`--enable-pq-kex` enables PQ-only key exchange methods. `--enable-hybrid-kex` enables hybrid key exchange methods.

The configuration script will automatically disable the NTRU based hybrid/PQ-only key exchange method if sandbox mode is not disabled.

### Running

In one terminal, run a server:

	/path/to/install/openssh/in/sbin/sshd -p 2222 -d

The server automatically supports all available hybrid and PQ-only key exchange methods.

In another terminal, run a client:

	/path/to/install/openssh/in/bin/ssh -l <username> -o 'KexAlgorithms=LIBOQSALGORITHM' -p 2222 localhost

where `LIBOQSALGORITHM` is one of the following:

Hybrid key exchange methods:

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

PQ-only key exchange methods:

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

### Test

To test the build, run:

    make tests 

Limitations
-----------

This fork is developed for the purposes of prototyping and evaluating the use of post-quantum cryptography in SSH, and is not intended for use in production environments to protect the transmission of sensitive information.  

- This fork of OpenSSH has not received the same level of auditing and analysis that OpenSSH has received.  
- At the time of writing, there are no vulnerabilities or weaknesses known in any of the post-quantum key exchange algorithms used in this fork.  However, it is advisable to wait on deploying post-quantum algorithms until further guidance is provided by the standards community, especially from the NIST Post-Quantum Cryptography project.
- This fork does not yet contain support for post-quantum authentication.
- The message format used in this fork is not standardized, and is subject to unilateral change at any time without regards to backwards compatibility with previous versions of this fork.

(Pre-draft) IETF Draft
----------------------

This repository contains an experimental (pre-draft) IETF draft for hybrid key exchange methods ECDH-SIKE and ECDH-BIKE. This documents has **not** been submitted to IETF.

Team
----

### Contributors

- Torben Hansen (Amazon AND Royal Holloway, University of London)
