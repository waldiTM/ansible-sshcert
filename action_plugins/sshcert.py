# -*- coding: utf-8 -*-
# Copyright: 2015,2016 Bastian Blank
# License: MIT, see LICENSE for details.


import base64
import codecs
import collections
import os
import re
import shutil
import struct
import subprocess
import tempfile

from datetime import datetime, timedelta

from ansible.plugins.action import ActionBase


class ActionModule(ActionBase):
    def _download(self, name, tmp, task_vars):
        result = self._execute_module(
            module_name='slurp',
            module_args={'path': name},
            tmp=tmp,
            task_vars=task_vars)

        if 'content' in result:
            content = result['content']
            if result['encoding'] == 'base64':
                return base64.b64decode(content)
            else:
                raise NotImplementedError("unknown encoding, failed: %s" % result)

    def run(self, tmp=None, task_vars=None):
        result = super(ActionModule, self).run(tmp, task_vars)

        signkey = self._task.args.get('signkey')
        pubkey = self._task.args.get('pubkey')
        cert = self._task.args.get('cert')
        cert_id = self._task.args.get('cert_id')
        cert_names = self._task.args.get('cert_names')
        cert_resign = self._task.args.get('cert_resign')
        cert_valid = self._task.args.get('cert_valid')

        if cert_resign:
            m = re.match(r'^(\d+)([sSmMhHdDwW])?$', str(cert_resign))
            if m:
                m_time = int(m.group(1))
                m_qual = m.group(2)
                if m_qual in ('w', 'W'):
                    cert_resign = datetime.utcnow() + timedelta(weeks=m_time)
                elif m_qual in ('d', 'd'):
                    cert_resign = datetime.utcnow() + timedelta(days=m_time)
                elif m_qual in ('h', 'h'):
                    cert_resign = datetime.utcnow() + timedelta(hours=m_time)
                elif m_qual in ('m', 'm'):
                    cert_resign = datetime.utcnow() + timedelta(minutes=m_time)
                else:
                    cert_resign = datetime.utcnow() + timedelta(seconds=m_time)
            else:
                cert_resign = datetime.max

        if not os.path.exists(signkey):
            result['failed'] = True
            result['msg'] = "could not find signing key"
            return result

        pubkey_content = self._download(pubkey, tmp, task_vars)
        if pubkey_content:
            try:
                pubkey_data = SshFile.read(pubkey_content)
            except Exception as e:
                result['failed'] = True
                result['msg'] = "could not parse public key {}: {}".format(pubkey, e)
                return result
        else:
            result['skipped'] = True
            result['msg'] = "could not find public key {}".format(pubkey)
            return result

        cert_content = self._download(cert, tmp, task_vars)
        if cert_content:
            # XXX: Check existing cert
            try:
                cert_data = SshFile.read(cert_content)
            except Exception as e:
                # Re-sign invalid certificates
                pass
            else:
                if cert_resign and cert_resign > cert_data.validbefore:
                    pass
                else:
                    return result

        tmp_local = tempfile.mkdtemp()
        try:
            base_local = os.path.join(tmp_local, 'key')
            pubkey_local = base_local + '.pub'
            cert_local = base_local + '-cert.pub'

            with open(pubkey_local, 'w') as f:
                f.write(pubkey_content)

            out = subprocess.check_output(
                (
                    'ssh-keygen',
                    '-s', signkey,
                    '-h',
                    '-I', cert_id,
                    '-n', ','.join(cert_names),
                    '-V', cert_valid,
                    base_local
                ),
                stderr=subprocess.STDOUT,
            )

            result['sign'] = out.strip()

            res = self._execute_module(
                module_name='copy',
                module_args = {
                    'src': cert_local,
                    'dest': cert,
                },
                task_vars=task_vars)
            res.update(result)
            del res['src']
            return res

        except subprocess.CalledProcessError as e:
            result['failed'] = True
            result['msg'] = 'could not sign key: {}'.format(e.output.strip())
            return result

        finally:
            shutil.rmtree(tmp_local)


class SshWirestring(object):
    __slots__ = '__s',

    def __init__(self, s):
        self.__s = memoryview(s)

    def read_string(self):
        s = self.__s
        l = struct.unpack_from('!L', s)[0]
        self.__s = s[4+l:]
        return s[4:4+l]

    def read_uint32(self):
        s = self.__s
        self.__s = s[4:]
        return struct.unpack_from('!L', s)[0]

    def read_uint64(self):
        s = self.__s
        self.__s = s[8:]
        return struct.unpack_from('!Q', s)[0]


class SshKeyRsa(collections.namedtuple('SshKeyRsa', ('e', 'n'))):
    __slots__ = ()

    def __new__(cls, key):
        return super(SshKeyRsa, cls).__new__(cls,
                key.read_string(),
                key.read_string())


class SshKeyDsa(collections.namedtuple('SshKeyRsa', ('p', 'q', 'g', 'y'))):
    __slots__ = ()

    def __new__(cls, key):
        return super(SshKeyDsa, cls).__new__(cls,
                key.read_string(),
                key.read_string(),
                key.read_string(),
                key.read_string())


class SshKeyEcdsa(collections.namedtuple('SshKeyRsa', ('curve', 'pk'))):
    __slots__ = ()

    def __new__(cls, key):
        return super(SshKeyEcdsa, cls).__new__(cls,
                key.read_string(),
                key.read_string())


class SshKeyEd25519(collections.namedtuple('SshKeyRsa', ('pk', ))):
    __slots__ = ()

    def __new__(cls, key):
        return super(SshKeyEd25519, cls).__new__(cls,
                key.read_string())


class SshCert(collections.namedtuple('SshCert', ('key', 'princs', 'validafter', 'validbefore'))):
    __slots__ = ()

    def __new__(cls, cert, key_type):
        nonce = cert.read_string()
        key = key_type(cert)
        serial = cert.read_uint64()
        type = cert.read_uint32()
        keyid = cert.read_string().tobytes().decode('utf-8')
        princs = cert.read_string().tobytes().decode('utf-8').split(',')
        validafter = datetime.utcfromtimestamp(cert.read_uint64())
        validbefore = datetime.utcfromtimestamp(cert.read_uint64())
        return super(SshCert, cls).__new__(cls, key, princs, validafter, validbefore)


class SshFile(object):
    types = {
        b'ssh-rsa': SshKeyRsa,
        b'ssh-dss': SshKeyDsa,
        b'ecdsa-sha2-nistp256': SshKeyEcdsa,
        b'ecdsa-sha2-nistp384': SshKeyEcdsa,
        b'ecdsa-sha2-nistp521': SshKeyEcdsa,
        b'ssh-ed25519': SshKeyEd25519,
    }

    @classmethod
    def read(cls, i):
        i = i.split(' ', 2)
        i_type = i[0]
        i_data = SshWirestring(codecs.decode(i[1], 'base64'))
        i_datatype = i_data.read_string()
        if i_type != i_datatype:
            raise RuntimeError('Key type mismatch')

        if i_type.endswith('-cert-v01@openssh.com'):
            return SshCert(i_data, cls.types[i_type[0:-21]])
        else:
            return cls.types[i_type](i_data)
