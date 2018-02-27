open-quantum-safe/openssh-portable
==================================

This repository contains a fork of OpenSSH that adds quantum-safe key exchange algorithms using liboqs for prototyping purposes.

This README.md contains information about the modifications to OpenSSH by the Open Quantum Safe project.  For information about OpenSSH,
([see the original README file for OpenSSH](https://github.com/open-quantum-safe/openssh-portable/blob/master/README).)

Overview
--------

The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.

**liboqs** is an open source C library for quantum-safe cryptographic algorithms.  See more about liboqs at [https://github.com/open-quantum-safe/liboqs/](https://github.com/open-quantum-safe/liboqs/), including a list of supported algorithms.

OpenSSH is an open-source implementation of the Secure Shell protocol [https://openssh.org/](https://openssh.org/).

This repository contains a fork of OpenSSH that adds quantum-safe key exchange algorithms using liboqs for prototyping purposes.

See the Limitations section below.


Contents
--------

### Key exchange mechanisms

open-quantum-safe/openssh currently supports the following key exchange mechanisms:

- `kex_rlwe_bcns15`: key exchange from the ring learning with errors problem (Bos, Costello, Naehrig, Stebila, *IEEE Symposium on Security & Privacy 2015*, [https://eprint.iacr.org/2014/599](https://eprint.iacr.org/2014/599))
- `kex_rlwe_newhope`: "NewHope": key exchange from the ring learning with errors problem (Alkim, Ducas, Pöppelmann, Schwabe, *USENIX Security 2016*, [https://eprint.iacr.org/2015/1092](https://eprint.iacr.org/2015/1092)) (using the reference C implementation of NewHope from [https://github.com/tpoeppelmann/newhope](https://github.com/tpoeppelmann/newhope))
- `kex_rlwe_msrln16`: Microsoft Research implementation of Peikert's ring-LWE key exchange (Longa, Naehrig, *CANS 2016*, [https://eprint.iacr.org/2016/504](https://eprint.iacr.org/2016/504)) (based on the implementation of Alkim, Ducas, Pöppelmann, and Schwabe, with improvements from Longa and Naehrig, see [https://www.microsoft.com/en-us/research/project/lattice-cryptography-library/](https://www.microsoft.com/en-us/research/project/lattice-cryptography-library/))
- `kex_lwe_frodo`: "Frodo": key exchange from the learning with errors problem (Bos, Costello, Ducas, Mironov, Naehrig, Nikolaenko, Raghunathan, Stebila, *ACM Conference on Computer and Communications Security 2016*, [https://eprint.iacr.org/2016/659](https://eprint.iacr.org/2016/659))
- `kex_sidh_cln16`: key exchange from the supersingular isogeny Diffie-Hellman problem (Costello, Naehrig, Longa, *CRYPTO 2016*, [https://eprint.iacr.org/2016/413](https://eprint.iacr.org/2016/413)), using the implementation of Microsoft Research [https://www.microsoft.com/en-us/research/project/sidh-library/](https://www.microsoft.com/en-us/research/project/sidh-library/)
- `kex_mlwe_kyber`: Kyber: a CCA-secure module-lattice-based key exchange mechanism (Bos, Ducas, Kiltz, Lepoint, Lyubashevsky, Schwabe, Shanck, Stehlé, *Real World Crypto 2017*, [https://eprint.iacr.org/2017/634](https://eprint.iacr.org/2017/634)), using the reference C implementation of Kyber from [pq-crystals/kyber](https://github.com/pq-crystals/kyber)


Building and Running
--------------------

Builds have been tested on macOS 10.12 and Ubuntu 17.4.0

### Install dependencies for macOS

You need to install several tools using `brew`:

	brew install autoconf automake cmake libtool openssl

### Install dependencies for Ubuntu

You need to install several tools using `apt`:

	sudo apt install autoconf automake cmake libtool openssl

### Building

First, you will need to download and build `liboqs`:

	git clone --recursive https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	autoreconf -i
	./configure --prefix=/path/to/install/liboqs/in --with-pic
	make clean;make
	make install

Next, you can build and install OpenSSH:

	git clone https://github.com/open-quantum-safe/openssh-portable.git
	cd openssh-portable
	aclocal
	autoheader
	autoconf
	./configure --with-ssl-dir=/path/to/openssl --prefix=/path/to/install/openssh/in --with-cflags=-I<liboqs include header path>  --with-libs=<liboqs.a with absolute path>
	make
	make install

### Running

In one terminal, run a server:

	/path/to/install/openssh/in/sbin/sshd -p 2222 -d -o 'KexAlgorithms=LIBOQSALGORITHM'

In another terminal, run a client:

	/path/to/install/openssh/in/bin/ssh -l <username> -o 'KexAlgorithms=LIBOQSALGORITHM' -p 2222 localhost

where `LIBOQSALGORITHM` is one of the following:

	oqs-bcns15-sha512@openquantumsafe.org
	oqs-newhope-sha512@openquantumsafe.org
	oqs-msrln16-sha512@openquantumsafe.org
	oqs-cln16-sha512@openquantumsafe.org
	oqs-frodo-sha512@openquantumsafe.org
	oqs-kyber-sha512@openquantumsafe.org


Limitations
-----------

This fork is developed for the purposes of prototyping and evaluating the use of post-quantum cryptography in SSH, and is not intended for use in production environments to protect the transmission of sensitive information.  

- This fork of OpenSSH has not received the same level of auditing and analysis that OpenSSH has received.  
- At the time of writing, there are no vulnerabilities or weaknesses known in any of the post-quantum key exchange algorithms used in this fork.  However, it is advisable to wait on deploying post-quantum algorithms until further guidance is provided by the standards community, especially from the NIST Post-Quantum Cryptography project.
- This fork does not yet contain support for post-quantum authentication.
- This fork does not yet contain support for hybrid key exchange, which would use traditional algorithms (like elliptic curve Diffie--Hellman) alongside post-quantum algorithms to provide potential resistance to quantum attacks while still maintaining the existing level of security.
- The message format used in this fork is not standardized, and is subject to unilateral change at any time without regards to backwards compatibility with previous versions of this fork.


License
-------

This fork is released under the same license as Portable OpenSSH. More information about this license can be found in the LICENSE file.


Team
----

### Contributors

- Karl Knopf (McMaster University)
- Douglas Stebila (McMaster University)
- Mira Belenkiy, Christian Paquin (Microsoft Research)

### Support

This repository was developed as part of a NSERC Undergraduate Student Research Award (USRA) project at McMaster University over the summer 2017 term.  As such, funding for this project came from both NSERC and from McMaster University.

liboqs was developed and published by the Open Quantum Safe project. It is lead by [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) (University of Waterloo) and [Douglas Stebila](https://www.douglas.stebila.ca/research/) (McMaster University).
