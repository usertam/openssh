open-quantum-safe/openssh
=========================
This repository contains a fork of OpenSSH that adds quantum-safe cryptographic algorithms and ciphersuites.

Overview
--------
The **Open Quantum Safe (OQS) project** has the goal of developing and prototyping quantum-resistant cryptography.

**liboqs** is an open source C library for quantum-safe cryptographic algorithms.  liboqs initially focuses on key exchange algorithms.  See more about liboqs at [https://github.com/open-quantum-safe/liboqs/](https://github.com/open-quantum-safe/liboqs/), including a list of supported algorithms.

OpenSSH is an open-source implementation of the Secure Shell protocol [https://openssh.org/](https://openssh.org/).  ([View the original README file for OpenSSH](https://github.com/dstebila/pq-openssh/blob/master/README).)

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

Builds have been tested on macOS 10.12 and Ubunutu 17.4.0

### Install dependencies for macOS

You need to install several tools using `brew`:

	brew install autoconf automake libtool openssl

### Install dependencies for Ubuntu
You need to install several tools using `apt`:

	sudo apt install autoconf automake libtool openssl

### Building
First, you will need to download and build `liboqs`:

	git clone https://github.com/open-quantum-safe/liboqs.git
	cd liboqs
	autoreconf -i
	./configure --prefix=/path/to/install
	make

Next, you can build and install OpenSSH:

	git clone --branch ds-dev https://github.com/open-quantum-safe/openssh.git
	cd pq-openssh
	aclocal
	autoheader
	autoconf
	./configure --with-ssl-dir=/usr/local/opt/openssl --with-liboqs-dir=/usr/local/opt/liboqs
	make
	make install


##Running 
In one terminal, run a server:

	/path/to/install/sbin/sshd -p 2222 -d

In another terminal, run a client:

	/path/to/install/bin/ssh -o 'KexAlgorithms=LIBOQSALGORITHM' -p 2222 localhost

where `LIBOQSALGORITHM` is one of the following:

	oqs-bcns15-sha512@openquantumsafe.org
	oqs-newhope-sha512@openquantumsafe.org
	oqs-msrln16-sha512@openquantumsafe.org
	oqs-cln16-sha512@openquantumsafe.org
	oqs-frodo-sha512@openquantumsafe.org
	oqs-kyber-sha512@openquantumsafe.org

License
-------
pq-openssh is released under the same license as Portable OpenSSH. More information about this license can be found in the LICENSE file.

Team
----
### Contributors
- Karl Knopf (McMaster University)
- Douglas Stebila (McMaster University)
- Mira Belenkiy, Christian Paquin (Microsoft Research)

### Support
This repository was developed as part of a NSERC USRA project at McMaster University over the summer 2017 term. As such, funding for this project came from both NSERC and from McMaster University.

Liboqs was developed and published by the Open Quantum Safe project. It is lead by [Michele Mosca](http://faculty.iqc.uwaterloo.ca/mmosca/) (University of Waterloo) and [Douglas Stebila](https://www.douglas.stebila.ca/research/) (McMaster University).
