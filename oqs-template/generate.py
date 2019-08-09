#!/usr/bin/env python3

import copy
import glob
import jinja2
import jinja2.ext
import os
import shutil
import subprocess
import sys
import yaml

Jinja2 = jinja2.Environment(loader=jinja2.FileSystemLoader(searchpath="."),extensions=['jinja2.ext.do'])

def file_get_contents(filename, encoding=None):
    with open(filename, mode='r', encoding=encoding) as fh:
        return fh.read()

def file_put_contents(filename, s, encoding=None):
    with open(filename, mode='w', encoding=encoding) as fh:
        fh.write(s)

def replacer(filename, instructions, delimiter):
    fragments = glob.glob(os.path.join('oqs-template', filename, '*.fragment'))
    contents = file_get_contents(filename)
    for fragment in fragments:
        identifier = os.path.splitext(os.path.basename(fragment))[0]
        identifier_start = '{} OQS_TEMPLATE_FRAGMENT_{}_START'.format(delimiter, identifier.upper())
        identifier_end = '{} OQS_TEMPLATE_FRAGMENT_{}_END'.format(delimiter, identifier.upper())
        preamble = contents[:contents.find(identifier_start)]
        postamble = contents[contents.find(identifier_end):]
        contents = preamble + identifier_start + Jinja2.get_template(fragment).render({'config': config}) + postamble
    file_put_contents(filename, contents)

def load_config():
    config = file_get_contents(os.path.join('oqs-template', 'generate.yml'), encoding='utf-8')
    config = yaml.safe_load(config)
    return config

config = load_config()

# add kems
replacer('kex.c', config, '/////')
replacer('kex.h', config, '/////')
replacer('kexoqs.c', config, '/////')
replacer('myproposal.h', config, '/////')
replacer('regress/unittests/kex/test_kex.c', config, '/////')
replacer('ssh2.h', config, '/////')
replacer('configure.ac', config, '#####')

# add sigs
replacer('oqs-utils.h', config, '/////')
replacer('pathnames.h', config, '/////')
replacer('readconf.c', config, '/////')
replacer('servconf.c', config, '/////')
replacer('ssh-add.c', config, '/////')
replacer('ssh-keygen.c', config, '/////')
replacer('ssh-keyscan.c', config, '/////')
replacer('ssh-keysign.c', config, '/////')
replacer('ssh-oqs.c', config, '/////')
replacer('ssh.c', config, '/////')
replacer('sshconnect.c', config, '/////')
replacer('sshkey.c', config, '/////')
replacer('sshkey.h', config, '/////')

# then, update test suite
replacer('oqs_test/tests/test_openssh.py', config, '#####')
