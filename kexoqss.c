/* $OpenBSD: kexoqss.c,v 1.10 2015/12/04 16:41:28 markus Exp $ */
/*
 * Copyright (c) 2001 Markus Friedl.  All rights reserved.
 * Copyright (c) 2010 Damien Miller.  All rights reserved.
 * Copyright (c) 2013 Aris Adamantiadis.  All rights reserved.
 *
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
#include "digest.h"
#include "kex.h"
#include "log.h"
#include "packet.h"
#include "ssh2.h"
#include "sshbuf.h"
#include "ssherr.h"

#include <openssl/rand.h>

#include <oqs/kex.h>

#define FRODO_SEED_LEN 16
#define FRODO_RANDOM_LEN 64


static int input_kex_oqs_init(int, u_int32_t, struct ssh *);

int
kexoqs_server(struct ssh *ssh)
{
	debug("expecting SSH2_MSG_KEX_OQS_INIT");
	ssh_dispatch_set(ssh, SSH2_MSG_KEX_OQS_INIT, &input_kex_oqs_init);
	return 0;
}

static int
input_kex_oqs_init(int type, u_int32_t seq, struct ssh *ssh)
{
	struct kex *kex = ssh->kex;
	struct sshkey *server_host_private, *server_host_public;
	struct sshbuf *shared_secret = NULL;
	u_char *server_host_key_blob = NULL, *signature = NULL;
	u_char *server_shared_secret = NULL;
	size_t server_shared_secret_len = 0;
	u_char *client_pubkey = NULL;
	size_t client_pubkey_len;
	u_char *server_pubkey = NULL;
	size_t server_pubkey_len ;
	u_char hash[SSH_DIGEST_MAX_LENGTH];
	size_t slen, sbloblen, hashlen;
	uint8_t * client_random;
	size_t client_random_len;
	int r;

	if (kex->load_host_public_key == NULL ||
	    kex->load_host_private_key == NULL) {
		r = SSH_ERR_INVALID_ARGUMENT;
		goto out;
	}
	server_host_public = kex->load_host_public_key(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	server_host_private = kex->load_host_private_key(kex->hostkey_type,
	    kex->hostkey_nid, ssh);
	if (server_host_public == NULL) {
	    r = SSH_ERR_NO_HOSTKEY_LOADED;
	    goto out;
	}

	if ((r = sshpkt_get_string(ssh, &client_pubkey, &client_pubkey_len))
	    != 0 ||
	    (r = sshpkt_get_string(ssh, &client_random, &client_random_len)) 
	    != 0 ||
	    (r = sshpkt_get_end(ssh)) != 0)
		goto out;
#ifdef DEBUG_KEXECDH
	dump_digest("client public key:", client_pubkey, client_pubkey_len);
#endif

	OQS_RAND *oqsrand = NULL;
	OQS_KEX *oqskex = NULL;
	oqsrand = OQS_RAND_arc4random_buf_new();
	if (oqsrand == NULL) 
	    return 0;
	
	if(get_oqs_kex_seedNeed(kex) == 1) {
	    uint8_t map_value = get_oqs_kex_mapping(kex);
	    oqskex = OQS_KEX_new(oqsrand, map_value, client_random,
	    FRODO_SEED_LEN, "recommended");
	}
	else{
	    uint8_t map_value = get_oqs_kex_mapping(kex);
	    oqskex = OQS_KEX_new(oqsrand, map_value, NULL, 0, NULL);
	}
	if (oqskex == NULL) {
	    OQS_RAND_free(oqsrand);
	    return 0;
	}

	r = OQS_KEX_bob(oqskex, client_pubkey, client_pubkey_len, 
	&server_pubkey, &server_pubkey_len, &server_shared_secret, 
	&server_shared_secret_len);
	OQS_KEX_free(oqskex);
	OQS_RAND_free(oqsrand);
	if (r != 1)
	    return 0;
	

	if ((shared_secret = sshbuf_new()) == NULL) {
	    r = SSH_ERR_ALLOC_FAIL;
	    goto out;
	}
	sshbuf_put_string(shared_secret, server_shared_secret, 
	server_shared_secret_len);

	/* calc H */
	if ((r = sshkey_to_blob(server_host_public, &server_host_key_blob,
	    &sbloblen)) != 0)
		goto out;
	hashlen = sizeof(hash);
	if ((r = kex_oqs_hash(
	    kex->hash_alg,
	    kex->client_version_string,
	    kex->server_version_string,
	    sshbuf_ptr(kex->peer), sshbuf_len(kex->peer),
	    sshbuf_ptr(kex->my), sshbuf_len(kex->my),
	    server_host_key_blob, sbloblen,
	    client_pubkey, client_pubkey_len,
	    server_pubkey, server_pubkey_len,
	    sshbuf_ptr(shared_secret), sshbuf_len(shared_secret),
	    hash, &hashlen)) < 0)
		goto out;
	/* save session id := H */
	if (kex->session_id == NULL) {
	    kex->session_id_len = hashlen;
	    kex->session_id = malloc(kex->session_id_len);
	    if (kex->session_id == NULL) {
	        r = SSH_ERR_ALLOC_FAIL;
	        goto out;
	    }
	    memcpy(kex->session_id, hash, kex->session_id_len);
	}

	/* sign H */
	if ((r = kex->sign(server_host_private, server_host_public, &signature,
	     &slen, hash, hashlen, kex->hostkey_alg, ssh->compat)) < 0)
		goto out;

	/* send server hostkey, ECDH pubkey 'Q_S' and signed H */
	if ((r = sshpkt_start(ssh, SSH2_MSG_KEX_OQS_REPLY)) != 0 ||
	    (r = sshpkt_put_string(ssh, server_host_key_blob, sbloblen)) 
	    != 0 ||
	    (r = sshpkt_put_string(ssh, server_pubkey, server_pubkey_len)) 
	    != 0 ||
	    (r = sshpkt_put_string(ssh, signature, slen)) != 0 ||
	    (r = sshpkt_send(ssh)) != 0)
		goto out;

	if ((r = kex_derive_keys(ssh, hash, hashlen, shared_secret)) == 0)
	    r = kex_send_newkeys(ssh);
out:
	explicit_bzero(hash, sizeof(hash));
	explicit_bzero(server_shared_secret, server_shared_secret_len);
	free(server_shared_secret);
	free(server_pubkey);
	free(server_host_key_blob);
	free(signature);
	free(client_pubkey);
	free(client_random);
	sshbuf_free(shared_secret);
	return r;
}
