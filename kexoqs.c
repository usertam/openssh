/* $OpenBSD: kexoqs.c,v 1.10 2016/05/02 08:49:03 djm Exp $ */
/*
 * Copyright (c) 2001, 2013 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2013 Aris Adamantiadis.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
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

#include <sys/types.h>

#include <signal.h>
#include <string.h>

#include <oqs/rand.h>
#include <oqs/kex.h>

#include "sshbuf.h"
#include "ssh2.h"
#include "sshkey.h"
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "digest.h"
#include "ssherr.h"

uint8_t 
OQS_RAND_arc4random_buf_8(OQS_RAND *r) {
	uint8_t x;
	arc4random_buf(&x, 1);
	return x;
}

uint32_t 
OQS_RAND_arc4random_buf_32(OQS_RAND *r) {
	uint32_t x;
	arc4random_buf(&x, 4);
	return x;
}

uint64_t 
OQS_RAND_arc4random_buf_64(OQS_RAND *r) {
	uint64_t x;
	arc4random_buf(&x, 8);
	return x;
}

void 
OQS_RAND_arc4random_buf_n(OQS_RAND *r, uint8_t *out, size_t n) {
	arc4random_buf(out, n);
}

void 
OQS_RAND_arc4random_buf_free(OQS_RAND *r) {
	free(r);
}

OQS_RAND 
*OQS_RAND_arc4random_buf_new() {
	OQS_RAND *r = malloc(sizeof(OQS_RAND));
	if (r == NULL) {
	    return NULL;
	}
	r->method_name = strdup("arc4random_buf");
	r->estimated_classical_security = 128;
	r->estimated_quantum_security = 64; // Grover search
	r->rand_8 = &OQS_RAND_arc4random_buf_8;
	r->rand_32 = &OQS_RAND_arc4random_buf_32;
	r->rand_64 = &OQS_RAND_arc4random_buf_64;
	r->rand_n = &OQS_RAND_arc4random_buf_n;
	r->free = &OQS_RAND_arc4random_buf_free;
	return r;
}

struct oqs_kex_info {
	u_int kex_type; // use enum kex_exchange defined in kex.h
	int alg_name; // use enum OQS_KEX_alg_name defined in liboqs kex.h
	int seed_needed; // 0 if seed is not required, 1 if otherwise
	char *named_parameters;
};

struct oqs_kex_info oqs_kex_mapping[] = {
	{ KEX_BCNS15_SHA512, OQS_KEX_alg_rlwe_bcns15, 0, NULL},
	{ KEX_NEWHOPE_SHA512, OQS_KEX_alg_rlwe_newhope, 0, NULL},
	{ KEX_MSRLN16_SHA512,  OQS_KEX_alg_rlwe_msrln16, 0, NULL},
	{ KEX_CLN16_SHA512, OQS_KEX_alg_sidh_cln16, 0, NULL},
	{ KEX_FRODO_SHA512, OQS_KEX_alg_lwe_frodo, 1, "recommended"},
	{ KEX_KYBER_SHA512, OQS_KEX_alg_mlwe_kyber, 0, NULL},
	{0,-1,0,NULL}, // the -1 indicates this is the end of the list
};

uint8_t * 
get_oqs_kex_mapping(struct kex * kex) {
	struct oqs_kex_info *k;
	for (k = oqs_kex_mapping; k->alg_name != -1; k++) {
	    if(k->kex_type==kex->kex_type)
	        return k->alg_name;
	}
	return NULL;
}

uint8_t * 
get_oqs_kex_seedNeed(struct kex * kex) {
	struct oqs_kex_info *k;
	for (k = oqs_kex_mapping; k->alg_name != -1; k++) {
	    if(k->kex_type==kex->kex_type)
	        return k->seed_needed;
	}
	return NULL;
}

void
kexoqs_keygen() {
}

int
kex_oqs_hash(
    int hash_alg,
    const char *client_version_string,
    const char *server_version_string,
    const u_char *ckexinit, size_t ckexinitlen,
    const u_char *skexinit, size_t skexinitlen,
    const u_char *serverhostkeyblob, size_t sbloblen,
    const u_char *client_pubkey, size_t client_pubkey_len,
    const u_char *server_pubkey, size_t server_pubkey_len,
    const u_char *shared_secret, size_t secretlen,
    u_char *hash, size_t *hashlen)
{
        struct sshbuf *b;
	int r;

	if (*hashlen < ssh_digest_bytes(hash_alg))
		return SSH_ERR_INVALID_ARGUMENT;
	if ((b = sshbuf_new()) == NULL)
		return SSH_ERR_ALLOC_FAIL;
	if ((r = sshbuf_put_cstring(b, client_version_string)) < 0 ||
	    (r = sshbuf_put_cstring(b, server_version_string)) < 0 ||
	    /* kexinit messages: fake header: len+SSH2_MSG_KEXINIT */
	    (r = sshbuf_put_u32(b, ckexinitlen+1)) < 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_KEXINIT)) < 0 ||
	    (r = sshbuf_put(b, ckexinit, ckexinitlen)) < 0 ||
	    (r = sshbuf_put_u32(b, skexinitlen+1)) < 0 ||
	    (r = sshbuf_put_u8(b, SSH2_MSG_KEXINIT)) < 0 ||
	    (r = sshbuf_put(b, skexinit, skexinitlen)) < 0 ||
	    (r = sshbuf_put_string(b, serverhostkeyblob, sbloblen)) < 0 ||
	    (r = sshbuf_put_string(b, client_pubkey, client_pubkey_len)) < 0 ||
	    (r = sshbuf_put_string(b, server_pubkey, server_pubkey_len)) < 0 ||
	    (r = sshbuf_put(b, shared_secret, secretlen)) < 0) {
		sshbuf_free(b);
		return r;
	}
#ifdef DEBUG_KEX
	sshbuf_dump(b, stderr);
#endif
	if (ssh_digest_buffer(hash_alg, b, hash, *hashlen) != 0) {
	    sshbuf_free(b);
	    return SSH_ERR_LIBCRYPTO_ERROR;
	}
	sshbuf_free(b);
	*hashlen = ssh_digest_bytes(hash_alg);
#ifdef DEBUG_KEX
	dump_digest("hash", hash, *hashlen);
#endif
	return 0;
}
