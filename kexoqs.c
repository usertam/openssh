/*
* Copyright 2018 Amazon.com, Inc. or its affiliates. All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
*
* THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
* IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
* OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
* IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
* INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
* NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
* THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*/

#include "includes.h"

#ifdef WITH_OQS

#include "ssherr.h"
#include "packet.h"
#include "ssh2.h"
#include "kexoqs.h"

#define FRODO_SEED_LEN 16

static OQS_RAND oqs_rnd;

/* Private liboqs functions */
static uint8_t
oqs_rand_openssh_buf_8(OQS_RAND *oqs_rnd);
static uint32_t
oqs_rand_openssh_buf_32(OQS_RAND *oqs_rnd);
static uint64_t
oqs_rand_openssh_buf_64(OQS_RAND *oqs_rnd);
static void
oqs_rand_openssh_buf_n(OQS_RAND *, uint8_t *out, size_t out_num_bytes);
static void
oqs_rand_openssh_buf_free(OQS_RAND *oqs_rnd);
static void
oqs_rand_openssh_buf_init();
static int
oqs_need_seed(const OQS_ALG *oqs_alg);

/*
 * Mapping that maps relevant named SSH key exchange methods to the needed
 * corresponding liboqs key exchange scheme
 */
static const OQS_ALG oqs_alg_mapping[] = {
/* Hybrid key exchange methods */
#if defined(OPENSSL_HAS_ECC) && defined(WITH_HYBRID_KEX)
#ifdef HAVE_NEWHOPE
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-newhope-sha384"), OQS_KEX_alg_rlwe_newhope,
	0, NULL, SSH2_MSG_HY_ECDH_NEWHOPE_INIT, SSH2_MSG_HY_ECDH_NEWHOPE_REPLY},
#endif /* HAVE_NEWHOPE */
#ifdef HAVE_FRODO
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-frodo-recommended-sha384"), OQS_KEX_alg_lwe_frodo,
	FRODO_SEED_LEN, "recommended", SSH2_MSG_HY_ECDH_FRODO_INIT, SSH2_MSG_HY_ECDH_FRODO_REPLY},
#endif /* HAVE_FRODO */
#ifdef HAVE_SIDH_SIKE
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-msr503-sha384"), OQS_KEX_alg_sidh_msr_503,
	0, NULL, SSH2_MSG_HY_ECDH_SIDH_INIT, SSH2_MSG_HY_ECDH_SIDH_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sidh-msr751-sha384"), OQS_KEX_alg_sidh_msr_751,
	0, NULL, SSH2_MSG_HY_ECDH_SIDH_INIT, SSH2_MSG_HY_ECDH_SIDH_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-503-sha384"), OQS_KEX_alg_sike_msr_503,
	0, NULL, SSH2_MSG_HY_ECDH_SIKE_INIT, SSH2_MSG_HY_ECDH_SIKE_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-sike-751-sha384"), OQS_KEX_alg_sike_msr_751,
	0, NULL, SSH2_MSG_HY_ECDH_SIKE_INIT, SSH2_MSG_HY_ECDH_SIKE_REPLY},
#endif /* HAVE_SIDH_SIKE */
#ifdef HAVE_NTRU
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-ntru-sha384"), OQS_KEX_alg_ntru,
	0, NULL, SSH2_MSG_HY_ECDH_NTRU_INIT, SSH2_MSG_HY_ECDH_NTRU_REPLY},
#endif /* HAVE_NTRU */
#ifdef HAVE_BIKE
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-bike1-L1-sha384"), OQS_KEX_alg_code_bike1_l1,
	0, NULL, SSH2_MSG_HY_ECDH_BIKE_INIT, SSH2_MSG_HY_ECDH_BIKE_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-bike1-L3-sha384"), OQS_KEX_alg_code_bike1_l3,
	0, NULL, SSH2_MSG_HY_ECDH_BIKE_INIT, SSH2_MSG_HY_ECDH_BIKE_REPLY},
	{HYBRID_ECDH_OQS_KEX_SUFFIX("ecdh-nistp384-bike1-L5-sha384"), OQS_KEX_alg_code_bike1_l5,
	0, NULL, SSH2_MSG_HY_ECDH_BIKE_INIT, SSH2_MSG_HY_ECDH_BIKE_REPLY},
#endif /* HAVE_BIKE */
#endif /* defined(OPENSSL_HAS_ECC) && defined(WITH_HYBRID_KEX) */
/* PQ-only key exchange methods */
#ifdef WITH_PQ_KEX
#ifdef HAVE_NEWHOPE
	{PQ_OQS_KEX_SUFFIX("newhope-sha384"), OQS_KEX_alg_rlwe_newhope, 0, NULL,
		SSH2_MSG_PQ_NEWHOPE_INIT, SSH2_MSG_PQ_NEWHOPE_REPLY},
#endif /* HAVE_NEWHOPE */
#ifdef HAVE_FRODO
	{PQ_OQS_KEX_SUFFIX("frodo-recommended-sha384"), OQS_KEX_alg_lwe_frodo,
	FRODO_SEED_LEN, "recommended", SSH2_MSG_PQ_FRODO_INIT, SSH2_MSG_PQ_FRODO_REPLY},
#endif /* HAVE_FRODO */
#ifdef HAVE_SIDH_SIKE
	{PQ_OQS_KEX_SUFFIX("sidh-msr503-sha384"), OQS_KEX_alg_sidh_msr_503, 0, NULL,
		SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
	{PQ_OQS_KEX_SUFFIX("sidh-msr751-sha384"), OQS_KEX_alg_sidh_msr_751, 0, NULL,
		SSH2_MSG_PQ_SIDH_INIT, SSH2_MSG_PQ_SIDH_REPLY},
	{PQ_OQS_KEX_SUFFIX("sike-503-sha384"), OQS_KEX_alg_sike_msr_503, 0, NULL,
		SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("sike-751-sha384"), OQS_KEX_alg_sike_msr_751, 0, NULL,
		SSH2_MSG_PQ_SIKE_INIT, SSH2_MSG_PQ_SIKE_REPLY},
#endif /* HAVE_SIDH_SIKE */
#ifdef HAVE_NTRU
	{PQ_OQS_KEX_SUFFIX("ntru-sha384"), OQS_KEX_alg_ntru, 0, NULL,
		SSH2_MSG_PQ_NTRU_INIT, SSH2_MSG_PQ_NTRU_REPLY},
#endif /* HAVE_NTRU */
#ifdef HAVE_BIKE
	{PQ_OQS_KEX_SUFFIX("bike1-L1-sha384"), OQS_KEX_alg_code_bike1_l1, 0, NULL,
		SSH2_MSG_PQ_BIKE_INIT, SSH2_MSG_PQ_BIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("bike1-L3-sha384"), OQS_KEX_alg_code_bike1_l3, 0, NULL,
		SSH2_MSG_PQ_BIKE_INIT, SSH2_MSG_PQ_BIKE_REPLY},
	{PQ_OQS_KEX_SUFFIX("bike1-L5-sha384"), OQS_KEX_alg_code_bike1_l5, 0, NULL,
		SSH2_MSG_PQ_BIKE_INIT, SSH2_MSG_PQ_BIKE_REPLY},
#endif /* HAVE_BIKE */
#endif /* WITH_PQ_KEX */
	{NULL,0,0,NULL} /* End of list */
};

/*
 * @brief Maps the named SSH key exchange method's PQ kex algorithm
 * to liboqs key exchange algorithm
 */
const OQS_ALG *
oqs_mapping(const char *ssh_kex_name) {

	const OQS_ALG *alg = NULL;

	for (alg = oqs_alg_mapping; alg->kex_alg != NULL; alg++) {
		if (strcmp(alg->kex_alg, ssh_kex_name) == 0) {
			return alg;
		}
	}

	return NULL;
}

/*
 * @brief Initialise key exchange liboqs specific context
 */
int
oqs_init(OQS_KEX_CTX **oqs_kex_ctx, char *ssh_kex_name) {

	OQS_KEX_CTX *tmp_oqs_kex_ctx = NULL;
	const OQS_ALG *oqs_alg = NULL;
	int r = 0;

	if ((tmp_oqs_kex_ctx = calloc(sizeof(*(tmp_oqs_kex_ctx)), 1)) == NULL) {
		r = SSH_ERR_ALLOC_FAIL;
		goto out;
	}

	if ((oqs_alg = oqs_mapping(ssh_kex_name)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	tmp_oqs_kex_ctx->oqs_kex = NULL;
	tmp_oqs_kex_ctx->oqs_method = oqs_alg->alg_name;
	tmp_oqs_kex_ctx->oqs_param = oqs_alg->named_param;
	tmp_oqs_kex_ctx->oqs_local_priv = NULL;
	tmp_oqs_kex_ctx->oqs_local_msg = NULL;
	tmp_oqs_kex_ctx->oqs_local_msg_len = 0;
	tmp_oqs_kex_ctx->oqs_remote_msg = NULL;
	tmp_oqs_kex_ctx->oqs_remote_msg_len = 0;
	tmp_oqs_kex_ctx->oqs_seed = NULL;
	tmp_oqs_kex_ctx->oqs_seed_len = 0;
	tmp_oqs_kex_ctx->oqs_need_seed = oqs_need_seed(oqs_alg);
	tmp_oqs_kex_ctx->oqs_need_seed_len = oqs_alg->need_seed_length;

	oqs_rand_openssh_buf_init();

	*oqs_kex_ctx = tmp_oqs_kex_ctx;
	tmp_oqs_kex_ctx = NULL;

out:
	if (tmp_oqs_kex_ctx != NULL)
		free(tmp_oqs_kex_ctx);

	return r;
}

/*
 * @brief Free memory allocated for oqs part of key exchange
 */
void
oqs_free(OQS_KEX_CTX *oqs_kex_ctx) {

	if (oqs_kex_ctx->oqs_local_msg != NULL) {
		free(oqs_kex_ctx->oqs_local_msg);
		oqs_kex_ctx->oqs_local_msg = NULL;
	}
	if (oqs_kex_ctx->oqs_remote_msg != NULL) {
		free(oqs_kex_ctx->oqs_remote_msg);
		oqs_kex_ctx->oqs_remote_msg = NULL;
	}
	if (oqs_kex_ctx->oqs_local_priv != NULL) {
		OQS_KEX_alice_priv_free(oqs_kex_ctx->oqs_kex,
			oqs_kex_ctx->oqs_local_priv);
		oqs_kex_ctx->oqs_local_priv = NULL;

	}
	if (OQS_NEED_SEED == oqs_kex_ctx->oqs_need_seed) {
		if (oqs_kex_ctx->oqs_seed != NULL) {
			/* It is probably overly paranoid to zeroise */
			explicit_bzero(oqs_kex_ctx->oqs_seed, oqs_kex_ctx->oqs_seed_len);
			free(oqs_kex_ctx->oqs_seed);
			oqs_kex_ctx->oqs_seed = NULL;
		}
	}
	if (oqs_kex_ctx->oqs_kex != NULL) {
		OQS_KEX_free(oqs_kex_ctx->oqs_kex);
		oqs_kex_ctx->oqs_kex = NULL;
	}
}

/*
 * @brief SSH hybrid key exchange init message name
 */
int
oqs_ssh2_init_msg(const OQS_ALG *oqs_alg) {
	return oqs_alg->ssh2_init_msg;
}

/*
 * @brief SSH hybrid key exchange reply message name
 */
int
oqs_ssh2_reply_msg(const OQS_ALG *oqs_alg) {
	return oqs_alg->ssh2_reply_msg;
}

/*
 * @brief Info on whether liboqs key exchange method require a seed
 */
static int
oqs_need_seed(const OQS_ALG *oqs_alg) {

	if (oqs_alg->need_seed_length == 0) {
		return OQS_NO_SEED;
	}
	else {
		return OQS_NEED_SEED;
	}
}

/*
 * @brief liboqs PRNG provided by OpenSSH
 * @return 1 byte of output from PRNG
 */
static uint8_t
oqs_rand_openssh_buf_8(OQS_RAND *oqs_rnd) {

	uint8_t out = 0;

	arc4random_buf(&out, 1);

	return out;
}

/*
 * @brief liboqs PRNG provided by OpenSSH
 * @return 4 bytes of output from PRNG
 */
static uint32_t
oqs_rand_openssh_buf_32(OQS_RAND *oqs_rnd) {

	uint32_t out = 0;

	arc4random_buf(&out, 4);

	return out;
}

/*
 * @brief liboqs PRNG provided by OpenSSH
 * @return 8 bytes of output from PRNG
 */
static uint64_t
oqs_rand_openssh_buf_64(OQS_RAND *oqs_rnd) {

	uint64_t out = 0;

	arc4random_buf(&out, 8);

	return out;
}

/*
 * @brief liboqs PRNG provided by OpenSSH
 * Copies out_num_bytes bytes of output from PRNG to out
 */
static void
oqs_rand_openssh_buf_n(OQS_RAND *oqs_rnd, uint8_t *out, size_t out_num_bytes) {

	arc4random_buf(out, out_num_bytes);
}

/*
 * @brief Do nothing function to satisfy OQS_RAND struct
 */
static void
oqs_rand_openssh_buf_free(OQS_RAND *oqs_rnd) {

	(void)oqs_rnd;
}

/*
 * @brief Initialises OQS_RAND struct
 * Use OpenSSH provided PRNG.
 * This is necessary when the sshd daemon runs in sandbox mode.
 */
static void
oqs_rand_openssh_buf_init() {

	oqs_rnd.method_name = "arc4random_buf";
	oqs_rnd.estimated_classical_security = 128;
	oqs_rnd.estimated_quantum_security = 64; // Grover search
	/* Use PRNG provided by OpenSSH instad of liboqs's PRNG */
	oqs_rnd.rand_8 = &oqs_rand_openssh_buf_8;
	oqs_rnd.rand_32 = &oqs_rand_openssh_buf_32;
	oqs_rnd.rand_64 = &oqs_rand_openssh_buf_64;
	oqs_rnd.rand_n = &oqs_rand_openssh_buf_n;
	oqs_rnd.free = &oqs_rand_openssh_buf_free;
}

/*
 * @brief Generates the client side part of the liboqs kex
 */
int
oqs_client_gen(OQS_KEX_CTX *oqs_kex_ctx) {

	OQS_KEX *oqs_kex = NULL;
	int r = 0;

	if (OQS_NEED_SEED == oqs_kex_ctx->oqs_need_seed) {
		if ((oqs_kex_ctx->oqs_seed = calloc(sizeof(*oqs_kex_ctx->oqs_seed),
			oqs_kex_ctx->oqs_need_seed_len)) == NULL) {
			r = SSH_ERR_ALLOC_FAIL;
			goto out;
		}

		oqs_rand_openssh_buf_n(&oqs_rnd, oqs_kex_ctx->oqs_seed,
			oqs_kex_ctx->oqs_need_seed_len);
		oqs_kex_ctx->oqs_seed_len = oqs_kex_ctx->oqs_need_seed_len;

		if (oqs_kex_ctx->oqs_seed == NULL ||
			oqs_kex_ctx->oqs_seed_len != oqs_kex_ctx->oqs_need_seed_len) {
			r = SSH_ERR_INTERNAL_ERROR;
			goto out;
		}
	}
	else {
		oqs_kex_ctx->oqs_seed = NULL;
		oqs_kex_ctx->oqs_seed_len = 0;
	}

	if ((oqs_kex = OQS_KEX_new(&oqs_rnd, oqs_kex_ctx->oqs_method,
		oqs_kex_ctx->oqs_seed, oqs_kex_ctx->oqs_seed_len,
		oqs_kex_ctx->oqs_param)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	/* Generate client side part of kex */
	if (OQS_KEX_alice_0(oqs_kex, &(oqs_kex_ctx->oqs_local_priv),
		&(oqs_kex_ctx->oqs_local_msg),
		&(oqs_kex_ctx->oqs_local_msg_len)) != OQS_SUCCESS) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	oqs_kex_ctx->oqs_kex = oqs_kex;
	oqs_kex = NULL;

out:
	if (oqs_kex != NULL) {
		OQS_KEX_free(oqs_kex);
	}

	return r;
}

/*
 * @brief Deserialise liboqs specific parts of incoming packet
 */
int
oqs_deserialise(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx,
	enum oqs_client_or_server client_or_server) {

	int r = 0;

	/*
	 * If a seed is used, this should be extracted first
	 */
	if (OQS_IS_SERVER == client_or_server &&
		OQS_NEED_SEED == oqs_kex_ctx->oqs_need_seed) {
		if ((r = sshpkt_get_string(ssh, &(oqs_kex_ctx->oqs_seed),
			&(oqs_kex_ctx->oqs_seed_len))) != 0) {
			goto out;
		}
	}

	r = sshpkt_get_string(ssh, &(oqs_kex_ctx->oqs_remote_msg),
		&(oqs_kex_ctx->oqs_remote_msg_len));

out:
	return r;
}

/*
 * @brief Serialise liboqs specific parts of outgoing packet
 */
int
oqs_serialise(struct ssh *ssh, OQS_KEX_CTX *oqs_kex_ctx,
	enum oqs_client_or_server client_or_server) {

	int r = 0;

	if (OQS_IS_CLIENT == client_or_server
		&& OQS_NEED_SEED == oqs_kex_ctx->oqs_need_seed) {
		if ((r = sshpkt_put_string(ssh, oqs_kex_ctx->oqs_seed,
			oqs_kex_ctx->oqs_seed_len)) != 0)
			goto out;
	}

	r = sshpkt_put_string(ssh, oqs_kex_ctx->oqs_local_msg,
		oqs_kex_ctx->oqs_local_msg_len);

out:
	return r;
}

/*
 * @brief Generates liboqs kex shared secret
 */
int
oqs_client_shared_secret(OQS_KEX_CTX *oqs_kex_ctx,
	u_char **oqs_shared_secret, size_t *oqs_shared_secret_len) {

	uint8_t *tmp_oqs_shared_secret = NULL;
	size_t tmp_oqs_shared_secret_len = 0;
	int r = 0;

	/* Generate shared secret from client private key and server public key */
	if (OQS_KEX_alice_1(oqs_kex_ctx->oqs_kex, oqs_kex_ctx->oqs_local_priv,
		oqs_kex_ctx->oqs_remote_msg, oqs_kex_ctx->oqs_remote_msg_len,
		&tmp_oqs_shared_secret, &tmp_oqs_shared_secret_len) != OQS_SUCCESS) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	*oqs_shared_secret = (u_char *) tmp_oqs_shared_secret;
	*oqs_shared_secret_len = tmp_oqs_shared_secret_len;

	tmp_oqs_shared_secret = NULL;

out:
	if (tmp_oqs_shared_secret != NULL) {
		explicit_bzero(tmp_oqs_shared_secret, tmp_oqs_shared_secret_len);
		free(tmp_oqs_shared_secret);
	}

	return r;
}

/*
 * @brief Generates server message and, simultanously generates
 * the shared secret from server private key and client public key
 */
int
oqs_server_gen_msg_and_ss(OQS_KEX_CTX *oqs_kex_ctx,
	u_char **oqs_shared_secret, size_t *oqs_shared_secret_len) {

	OQS_KEX *oqs_kex = NULL;
	uint8_t *tmp_oqs_shared_secret = NULL;
	size_t tmp_oqs_shared_secret_len = 0;
	int r = 0;

	if (OQS_NEED_SEED == oqs_kex_ctx->oqs_need_seed) {
		if (oqs_kex_ctx->oqs_seed == NULL ||
			oqs_kex_ctx->oqs_seed_len != oqs_kex_ctx->oqs_need_seed_len) {
			fprintf(stderr, "seed failed\n");
			r = SSH_ERR_INTERNAL_ERROR;
			goto out;
		}
	}
	else {
		oqs_kex_ctx->oqs_seed = NULL;
		oqs_kex_ctx->oqs_seed_len = 0;
	}

	if ((oqs_kex = OQS_KEX_new(&oqs_rnd, oqs_kex_ctx->oqs_method,
		oqs_kex_ctx->oqs_seed, oqs_kex_ctx->oqs_seed_len,
		oqs_kex_ctx->oqs_param)) == NULL) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	if (OQS_KEX_bob(oqs_kex, oqs_kex_ctx->oqs_remote_msg,
		oqs_kex_ctx->oqs_remote_msg_len, &(oqs_kex_ctx->oqs_local_msg),
		&(oqs_kex_ctx->oqs_local_msg_len), &tmp_oqs_shared_secret,
		&tmp_oqs_shared_secret_len) != OQS_SUCCESS) {
		r = SSH_ERR_INTERNAL_ERROR;
		goto out;
	}

	*oqs_shared_secret = (u_char *) tmp_oqs_shared_secret;
	*oqs_shared_secret_len = tmp_oqs_shared_secret_len;

	tmp_oqs_shared_secret = NULL;

out:
	if (oqs_kex != NULL) {
		OQS_KEX_free(oqs_kex);
	}
	if (tmp_oqs_shared_secret != NULL) {
		explicit_bzero(tmp_oqs_shared_secret, tmp_oqs_shared_secret_len);
		free(tmp_oqs_shared_secret);
	}

	return r;
}

#endif /* WITH_OQS */
