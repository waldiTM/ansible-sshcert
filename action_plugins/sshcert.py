import base64
import os
import shutil
import subprocess
import tempfile

from ansible import utils
from ansible.runner.return_data import ReturnData


class ActionModule(object):
    def __init__(self, runner):
        self.runner = runner

    def _download(self, conn, tmp, name, inject):
        result = self.runner._execute_module(conn, tmp, 'slurp', "path=%s" % name, inject=inject, persist_files=True)

        if 'content' in result.result:
            content = result.result['content']
            if result.result['encoding'] == 'base64':
                return base64.b64decode(content)
            else:
                raise Exception("unknown encoding, failed: %s" % result.result)

    def run(self, conn, tmp, module_name, module_args, inject, complex_args=None, **kwargs):
        options = {}
        if complex_args:
            options.update(complex_args)
        options.update(utils.parse_kv(module_args))

        signkey = options['signkey']
        pubkey = options['pubkey']
        cert = options['cert']

        if not os.path.exists(signkey):
            result=dict(failed=True, msg="could not find signing key")
            return ReturnData(conn=conn, result=result)

        pubkey_content = self._download(conn, tmp, pubkey, inject)
        cert_content = self._download(conn, tmp, cert, inject)

        if not pubkey_content:
            result=dict(skipped=True, msg="could not find public key")
            return ReturnData(conn=conn, result=result)

        # XXX: Check existing cert

        tmp_local = tempfile.mkdtemp()
        try:
            pubkey_local = os.path.join(tmp_local, 'key.pub')
            cert_local = os.path.join(tmp_local, 'key-cert.pub')

            with open(pubkey_local, 'w') as f:
                f.write(pubkey_content)

            out = subprocess.check_output(
                (
                    'ssh-keygen',
                    '-s', signkey,
                    '-I', inject['inventory_hostname'],
                    '-n', inject['inventory_hostname'],
                    '-h',
                    pubkey_local
                ),
                stderr=subprocess.STDOUT,
            )

            copy_result = self.runner._execute_module(
                conn, tmp, 'copy',
                utils.merge_module_args('', {
                    'src': cert_local,
                    'dest': cert,
                }),
                inject=inject, complex_args=complex_args, delete_remote_tmp=True)

            # XXX: Check copy_result

        finally:
            shutil.rmtree(tmp_local)

        result=dict(changed=True)
        return ReturnData(conn=conn, result=result)

