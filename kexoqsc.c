/* $OpenBSD: kexoqsc.c,v 1.8 2017/05/31 04:17:12 djm Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
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

#include <stdio.h>
#include <string.h>
#include <signal.h>

#include "sshkey.h"
#include "cipher.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "ssh2.h"
#include "sshbuf.h"
#include "digest.h"
#include "ssherr.h"

#include <openssl/rand.h>

#include <oqs/kex.h>

#define FRODO_SEED_LEN 16
#define FRODO_RANDOM_LEN 64

static int
input_kex_oqs_reply(int type, u_int32_t seq, struct ssh *ssh);

int
kexoqs_client(struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	OQS_RAND *oqsrand = NULL;
	OQS_KEX *oqskex = NULL;
	oqsrand = OQS_RAND_arc4random_buf_new();
	int r;

	if (oqsrand == NULL) 
	    return 0;
	
	if(kex->kex_type == KEX_FRODO_SHA512){
	    uint8_t map_value = get_oqs_kex_mapping(kex);
	    oqskex = OQS_KEX_new(oqsrand, map_value, kex->client_random, 
	    FRODO_SEED_LEN, "recommended");
	}
	else{
	    uint8_t map_value = get_oqs_kex_mapping(kex);
	    oqskex = OQS_KEX_new(oqsrand, map_value, NULL, 0, NULL);
	    kex->client_random = OQS_RAND_arc4random_buf_new();
	}
	
	if (oqskex == NULL) {
	    OQS_RAND_free(oqsrand);
	    return 0;
	}

	r = OQS_KEX_alice_0(oqskex, &(kex->oqs_client_key), 
	&(kex->oqs_client_pubkey), &(kex->oqs_client_pubkey_len));
	OQS_KEX_free(oqskex);
	OQS_RAND_free(oqsrand);
	if (r != 1)
	    return 0;
	

	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_OQS_INIT)) != 0 ||
	    (r = sshpkt_put_string(ssh, kex->oqs_client_pubkey,
	    kex->oqs_client_pubkey_len)) != 0 ||
	    (r = sshpkt_put_string(ssh, kex->client_random,
	    FRODO_RANDOM_LEN)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		return r;

	debug("expecting SSH2_MSG_KEX_OQS_REPLY");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_OQS_REPLY, &input_kex_oqs_reply);
	return 0;
}

static int
input_kex_oqs_reply(int type, u_int32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	struct sshkey *server_host_key = NULL;
	struct sshbuf *shared_secret = NULL;
	u_char *client_shared_secret = NULL;
	size_t client_shared_secret_len = 0;
	u_char *server_pubkey = NULL;
	size_t server_pubkey_len;
	u_char *server_host_key_blob = NULL, *signature = NULL;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, sbloblen, hashlen;
	int r;

	if (kex->verify_host_key == NULL) {
	    r = SSH_ERR_INVALID_ARGUMENT;
	    goto out;
	}

	/* hostkey */
	if ((r = sshpkt_get_string(ssh, &server_host_key_blob,
	    &sbloblen)) != 0 ||
	    (r = sshkey_from_blob(server_host_key_blob, sbloblen,
	    &server_host_key)) != 0)
		goto out;
	if (server_host_key->type != kex->hostkey_type ||
	    (kex->hostkey_type == KEY_ECDSA &&
	    server_host_key->ecdsa_nid != kex->hostkey_nid)) {
		r = SSH_ERR_KEY_TYPE_MISMATCH;
		goto out;
	}
	if (kex->verify_host_key(server_host_key, ssh) == -1) {
	    r = SSH_ERR_SIGNATURE_INVALID;
	    goto out;
	}

	/* Q_S, server public key */
	/* signed H */
	if ((r = sshpkt_get_string(ssh, &server_pubkey, &server_pubkey_len)) 
	    != 0 ||
	    (r = sshpkt_get_string(ssh, &signature, &slen)) != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;

#ifdef DEBUG_KEXECDH
	dump_digest("server public key:", server_pubkey, server_pubkey_len);
#endif

	OQS_RAND *oqsrand = NULL;
	OQS_KEX *oqskex = NULL;
	oqsrand = OQS_RAND_arc4random_buf_new();
	if (oqsrand == NULL) 
	    goto out;
	
	
	if(get_oqs_kex_seedNeed(kex) == 1) {
	    uint8_t map_value = get_oqs_kex_mapping(kex);
	    kex->client_random = malloc(FRODO_RANDOM_LEN);
	    memset(kex->client_random, 'a', FRODO_RANDOM_LEN);
	    oqskex = OQS_KEX_new(oqsrand, map_value, kex->client_random, 
	    FRODO_SEED_LEN, "recommended");
	}
	else{
	    uint8_t map_value = get_oqs_kex_mapping(kex);
	    oqskex = OQS_KEX_new(oqsrand, map_value, NULL, 0, NULL);
	}

	if (oqskex == NULL) {
	    OQS_RAND_free(oqsrand);
	    goto out;
	}

	r = OQS_KEX_alice_1(oqskex, kex->oqs_client_key, server_pubkey, 
	server_pubkey_len, &client_shared_secret, &client_shared_secret_len);
	OQS_KEX_free(oqskex);
	OQS_RAND_free(oqsrand);
	if (r != 1) 
	    goto out;
	
	if ((shared_secret = sshbuf_new()) == NULL) {
	    r = SSH_ERR_ALLOC_FAIL;
	    goto out;
	}
	sshbuf_put_string(shared_secret, client_shared_secret, 
	client_shared_secret_len);

	/* calc and verify H */
	hashlen = sizeof(hash);
	if ((r = kex_oqs_hash(
	    kex->hash_alg,
	    kex->client_version_string,
	    kex->server_version_string,
	    sshbuf_ptr(kex->my), sshbuf_len(kex->my),
	    sshbuf_ptr(kex->peer), sshbuf_len(kex->peer),
	    server_host_key_blob, sbloblen,
	    kex->oqs_client_pubkey, kex->oqs_client_pubkey_len,
	    server_pubkey, server_pubkey_len,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) < 0)
		goto out;

	if ((r = sshkey_verify(server_host_key, signature, slen, hash, hashlen,
	    ssh->compat)) != 0)
		goto out;

	/* save session id */
	if (kex->session_id == NULL) {
	    kex->session_id_len = hashlen;
	    kex->session_id = malloc(kex->session_id_len);
	    if (kex->session_id == NULL) {
	        r = SSH_ERR_ALLOC_FAIL;
	            goto out;
	    }
	    memcpy(kex->session_id, hash, kex->session_id_len);
	}

	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) == 0)
	    r = kex_send_newkeys(ssh);
out:
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(client_shared_secret, client_shared_secret_len);
	free(client_shared_secret);
	OQS_KEX_alice_priv_free(NULL, kex->oqs_client_key);
	free(kex->oqs_client_pubkey);
	free(server_host_key_blob);
	free(server_pubkey);
	free(signature);
	sshkey_free(server_host_key);
	sshbuf_free(shared_secret);
	return r;
}
