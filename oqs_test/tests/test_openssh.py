import helpers
import os
import sys
import time

sig_algs = ['ssh-ed25519']
if 'WITH_PQAUTH' in os.environ and os.environ['WITH_PQAUTH'] == 'true':
    # post-quantum
    sig_algs += [
##### OQS_TEMPLATE_FRAGMENT_LIST_SIGS_START
    # post-quantum only sigs
    'ssh-oqsdefault','ssh-dilithium2','ssh-dilithium4','ssh-mqdss3148','ssh-picnicl1fs','ssh-picnicl1ur','ssh-picnicl3fs','ssh-picnicl3ur','ssh-picnicl5fs','ssh-picnicl5ur','ssh-picnic2l1fs','ssh-picnic2l3fs','ssh-qteslai','ssh-qteslaiiisize','ssh-qteslaiiispeed','ssh-sphincsharaka128frobust',
    # hybrid sigs
    'ssh-rsa3072-oqsdefault','ssh-p256-oqsdefault','ssh-rsa3072-dilithium2','ssh-p256-dilithium2','ssh-p384-dilithium4','ssh-rsa3072-mqdss3148','ssh-p256-mqdss3148','ssh-rsa3072-picnicl1fs','ssh-p256-picnicl1fs','ssh-rsa3072-picnicl1ur','ssh-p256-picnicl1ur','ssh-p384-picnicl3fs','ssh-p384-picnicl3ur','ssh-p521-picnicl5fs','ssh-p521-picnicl5ur','ssh-rsa3072-picnic2l1fs','ssh-p256-picnic2l1fs','ssh-p384-picnic2l3fs','ssh-rsa3072-qteslai','ssh-p256-qteslai','ssh-p384-qteslaiiisize','ssh-p384-qteslaiiispeed','ssh-rsa3072-sphincsharaka128frobust','ssh-p256-sphincsharaka128frobust',
##### OQS_TEMPLATE_FRAGMENT_LIST_SIGS_END
]

kex_algs = [
##### OQS_TEMPLATE_FRAGMENT_LIST_KEXS_START
    # post-quantum only kex
    'bike1-L1-sha384@openquantumsafe.org','bike1-L3-sha384@openquantumsafe.org','bike1-L5-sha384@openquantumsafe.org','bike2-L1-sha384@openquantumsafe.org','bike2-L3-sha384@openquantumsafe.org','bike2-L5-sha384@openquantumsafe.org','frodo-640-aes-sha384@openquantumsafe.org','frodo-976-aes-sha384@openquantumsafe.org','kyber-512-sha384@openquantumsafe.org','kyber-768-sha384@openquantumsafe.org','kyber-1024-sha384@openquantumsafe.org','newhope-512-sha384@openquantumsafe.org','newhope-1024-sha384@openquantumsafe.org','ntru-hps-2048-509-sha384@openquantumsafe.org','ntru-hps-2048-677-sha384@openquantumsafe.org','saber-lightsaber-sha384@openquantumsafe.org','saber-saber-sha384@openquantumsafe.org','saber-firesaber-sha384@openquantumsafe.org','sidh-503-sha384@openquantumsafe.org','sidh-751-sha384@openquantumsafe.org','sike-503-sha384@openquantumsafe.org','sike-751-sha384@openquantumsafe.org',
    # hybrid kex
    'ecdh-nistp384-bike1-L1-sha384@openquantumsafe.org','ecdh-nistp384-bike1-L3-sha384@openquantumsafe.org','ecdh-nistp384-bike1-L5-sha384@openquantumsafe.org','ecdh-nistp384-bike2-L1-sha384@openquantumsafe.org','ecdh-nistp384-bike2-L3-sha384@openquantumsafe.org','ecdh-nistp384-bike2-L5-sha384@openquantumsafe.org','ecdh-nistp384-frodo-640-aes-sha384@openquantumsafe.org','ecdh-nistp384-frodo-976-aes-sha384@openquantumsafe.org','ecdh-nistp384-kyber-512-sha384@openquantumsafe.org','ecdh-nistp384-kyber-768-sha384@openquantumsafe.org','ecdh-nistp384-kyber-1024-sha384@openquantumsafe.org','ecdh-nistp384-newhope-512-sha384@openquantumsafe.org','ecdh-nistp384-newhope-1024-sha384@openquantumsafe.org','ecdh-nistp384-ntru-hps-2048-509-sha384@openquantumsafe.org','ecdh-nistp384-ntru-hps-2048-677-sha384@openquantumsafe.org','ecdh-nistp384-saber-lightsaber-sha384@openquantumsafe.org','ecdh-nistp384-saber-saber-sha384@openquantumsafe.org','ecdh-nistp384-saber-firesaber-sha384@openquantumsafe.org','ecdh-nistp384-sidh-503-sha384@openquantumsafe.org','ecdh-nistp384-sidh-751-sha384@openquantumsafe.org','ecdh-nistp384-sike-503-sha384@openquantumsafe.org','ecdh-nistp384-sike-751-sha384@openquantumsafe.org',
##### OQS_TEMPLATE_FRAGMENT_LIST_KEXS_END
        ]


def test_gen_keys():
    global sig_algs
    helpers.run_subprocess(
        ['rm', '-rf', 'ssh_client'],
        os.path.join('tmp', 'install')
    )
    helpers.run_subprocess(
        ['rm', '-rf', 'ssh_server'],
        os.path.join('tmp', 'install')
    )
    os.mkdir(os.path.join('tmp', 'install', 'ssh_client'), mode=0o700)
    os.mkdir(os.path.join('tmp', 'install', 'ssh_server'), mode=0o700)
    for party in ['client', 'server']:
        for sig_alg in sig_algs:
            yield (gen_keys, sig_alg, party)

def gen_keys(sig_alg, party):
    helpers.run_subprocess(
        [
            'bin/ssh-keygen',
            '-t', sig_alg,
            '-N', '',
            '-f', os.path.join('ssh_{}'.format(party), 'id_{}'.format(sig_alg))
        ],
        os.path.join('tmp', 'install')
    )

def test_connection():
    global sig_algs, kex_algs
    port = 22345
    for sig_alg in sig_algs:
        for kex_alg in kex_algs:
            if 'CIRCLECI' in os.environ:
                if 'bike' in kex_alg:
                    continue # FIXME: BIKE doesn't work on CircleCI due to symbol _CMP_LT_OS not being defined
            if 'WITH_OPENSSL' in os.environ and os.environ['WITH_OPENSSL'] != 'true':
                if 'ecdh' in kex_alg:
                    continue
            yield(run_connection, sig_alg, kex_alg, port)
            port = port + 1

def run_connection(sig_alg, kex_alg, port):
    helpers.run_subprocess(
        [os.path.join('scripts', 'do_openssh.sh')],
        env={
            'SIGALG': sig_alg,
            'KEXALG': kex_alg,
            'PORT': str(port),
            'PREFIX': os.path.join(os.getcwd(), 'tmp', 'install')
        }
    )

if __name__ == '__main__':
    try:
        import nose2
        nose2.main()
    except ImportError:
        import nose
        nose.runmodule()
