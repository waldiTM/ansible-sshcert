# -*- coding: utf-8 -*-
# Copyright: 2015 Bastian Blank
# License: MIT, see LICENSE for details.


import base64
import os
import shutil
import subprocess
import tempfile

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
                raise Exception("unknown encoding, failed: %s" % result)

    def run(self, tmp=None, task_vars=None):
        result = super(ActionModule, self).run(tmp, task_vars)

        signkey = self._task.args.get('signkey')
        pubkey = self._task.args.get('pubkey')
        cert = self._task.args.get('cert')
        cert_id = self._task.args.get('cert_id')
        cert_names = self._task.args.get('cert_names')
        cert_valid = self._task.args.get('cert_valid')

        if not os.path.exists(signkey):
            result['failed'] = True
            result['msg'] = "could not find signing key"
            return result

        pubkey_content = self._download(pubkey, tmp, task_vars)
        cert_content = self._download(cert, tmp, task_vars)

        if not pubkey_content:
            result['skipped'] = True
            result['msg'] = "could not find public key"
            return result

        # XXX: Check existing cert

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

            result.update(self._execute_module(
                module_name='copy',
                module_args = {
                    'src': cert_local,
                    'dest': cert,
                },
                task_vars=task_vars))
            return result

        finally:
            shutil.rmtree(tmp_local)
