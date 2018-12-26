# Copyright (c) 2018 Ansible Project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import (absolute_import, division, print_function)

__metaclass__ = type

DOCUMENTATION = """
author: Steve Boyd (steve@ui.net)
connection: pslocal
short_description: Run tasks on the local windows machine using PowerShell
when the controller software is running in the Windows bash environment.
description:
- Run commands via PowerShell or put/fetch via bash interop
version_added: "2.7"
requirements:
- n/a
options:
  # transport options
  powershell_user:
    description:
    - The user to log in as.
    vars:
    - name: ansible_user
    - name: ansible_pslocal_user

  # protocol options
  operation_timeout:
    description:
    - Sets the timeout for each operation.
    - This is measured in seconds.
    vars:
    - name: ansible_pslocal_operation_timeout
    default: 20
"""

import base64
import json
import os
import subprocess

from ansible.errors import AnsibleError, AnsibleFileNotFound
from ansible.module_utils._text import to_bytes, to_native, to_text
from ansible.module_utils.six import binary_type, text_type
from ansible.plugins.connection import ConnectionBase
from ansible.plugins.shell.powershell import _common_args
from ansible.utils.display import Display
from ansible.utils.hashing import secure_hash
from ansible.utils.path import makedirs_safe

display = Display()


class Connection(ConnectionBase):
    transport = 'pslocal'
    module_implementation_preferences = ('.ps1', '.exe', '')

    become_methods = ['runas']
    allow_executable = False
    has_pipelining = True

    # allow_extras = True

    def __init__(self, *args, **kwargs):
        self.always_pipeline_modules = True
        self._psrp_host = 'LOCAL-POWERSHELL'
        # self.has_native_async = True

        self._shell_type = 'powershell'
        super(Connection, self).__init__(*args, **kwargs)

    def _connect(self):
        super(Connection, self)._connect()
        # self._build_kwargs()

        if not self._connected:
            display.vvv("ESTABLISH POWERSHELL LOCAL CONNECTION FOR USER: {}".format(self._play_context.remote_user),
                        host=self._play_context.remote_addr)
            self._connected = True
        return self

    def exec_command(self, cmd, in_data=None, sudoable=True):
        super(Connection, self).exec_command(cmd, in_data=in_data, sudoable=sudoable)

        if cmd == "-" and not in_data.startswith(b"#!"):
            # The pslocal plugin sets cmd to '-' when we are executing a
            # PowerShell script with in_data being the script to execute.
            script = in_data
            in_data = None
            display.vvv("PSLOCAL: EXEC (via pipeline wrapper)",
                        host=self._psrp_host)
        elif cmd == "-":
            # ANSIBALLZ wrapper, we need to get the interpreter and execute
            # that as the script - note this won't work as basic.py relies
            # on packages not available on Windows, once fixed we can enable
            # this path
            interpreter = to_native(in_data.splitlines()[0][2:])
            # script = "$input | &'%s' -" % interpreter
            # in_data = to_text(in_data)
            raise AnsibleError("cannot run the interpreter '%s' on the psrp "
                               "connection plugin" % interpreter)
        elif cmd.startswith(" ".join(_common_args) + " -EncodedCommand"):
            # This is a PowerShell script encoded by the shell plugin, we will
            # decode the script and execute it in the runspace instead of
            # starting a new interpreter to save on time
            b_command = base64.b64decode(cmd.split(" ")[-1])
            script = to_text(b_command, 'utf-16-le')
            in_data = to_text(in_data, errors="surrogate_or_strict", nonstring="passthru")
            display.vvv("PSLOCAL: EXEC {}".format(script), host=self._psrp_host)
        else:
            # in other cases we want to execute the cmd as the script
            script = cmd
            display.vvv("PSLOCAL: EXEC {}".format(script), host=self._psrp_host)

        rc, stdout, stderr = self._exec_powershell_script(script, in_data)
        return rc, stdout, stderr

    def _exec_powershell_script(self, cmd, in_data=None, sudoable=True):
        ''' run a command on the local host '''

        super(Connection, self).exec_command(cmd, in_data=in_data, sudoable=sudoable)

        display.debug("in local.exec_command()")

        # executable = C.DEFAULT_EXECUTABLE.split()[0] if C.DEFAULT_EXECUTABLE else None
        executable = '/mnt/c/Windows/System32/WindowsPowerShell/v1.0/powershell.exe'

        if not os.path.exists(to_bytes(executable, errors='surrogate_or_strict')):
            raise AnsibleError("failed to find the executable specified %s."
                               " Please verify if the executable exists and re-try." % executable)

        display.vvv(u"EXEC {0}".format(to_text(cmd)), host=self._play_context.remote_addr)
        display.debug("opening command with Popen()")

        if isinstance(cmd, (text_type, binary_type)):
            cmd = to_bytes(cmd)
        else:
            cmd = map(to_bytes, cmd)

        display.display("Popen: cmd = {}".format(to_text(cmd)), screen_only=True, color='bright green')
        display.display("Popen: shell = {}".format(isinstance(cmd, (text_type, binary_type))), screen_only=True,
                        color='bright green')
        display.display("Popen: executable = {}".format(to_text(executable)), screen_only=True, color='bright green')

        p = subprocess.Popen(
            cmd,
            shell=isinstance(cmd, (text_type, binary_type)),
            executable=executable,  # cwd=...
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        display.display("done running command with Popen()")

        if self._play_context.prompt and sudoable:
            fcntl.fcntl(p.stdout, fcntl.F_SETFL, fcntl.fcntl(p.stdout, fcntl.F_GETFL) | os.O_NONBLOCK)
            fcntl.fcntl(p.stderr, fcntl.F_SETFL, fcntl.fcntl(p.stderr, fcntl.F_GETFL) | os.O_NONBLOCK)
            selector = selectors.DefaultSelector()
            selector.register(p.stdout, selectors.EVENT_READ)
            selector.register(p.stderr, selectors.EVENT_READ)

            become_output = b''
            try:
                while not self.check_become_success(become_output) and not self.check_password_prompt(become_output):
                    events = selector.select(self._play_context.timeout)
                    if not events:
                        stdout, stderr = p.communicate()
                        raise AnsibleError(
                            'timeout waiting for privilege escalation password prompt:\n' + to_native(become_output))

                    for key, event in events:
                        if key.fileobj == p.stdout:
                            chunk = p.stdout.read()
                        elif key.fileobj == p.stderr:
                            chunk = p.stderr.read()

                    if not chunk:
                        stdout, stderr = p.communicate()
                        raise AnsibleError(
                            'privilege output closed while waiting for password prompt:\n' + to_native(become_output))
                    become_output += chunk
            finally:
                selector.close()

            if not self.check_become_success(become_output):
                p.stdin.write(to_bytes(self._play_context.become_pass, errors='surrogate_or_strict') + b'\n')
            fcntl.fcntl(p.stdout, fcntl.F_SETFL, fcntl.fcntl(p.stdout, fcntl.F_GETFL) & ~os.O_NONBLOCK)
            fcntl.fcntl(p.stderr, fcntl.F_SETFL, fcntl.fcntl(p.stderr, fcntl.F_GETFL) & ~os.O_NONBLOCK)

        display.debug("getting output with communicate()")
        stdout, stderr = p.communicate(in_data)
        display.debug("done communicating")

        display.debug("done with local.exec_command()")
        return (p.returncode, stdout, stderr)

    def put_file(self, in_path, out_path):
        super(Connection, self).put_file(in_path, out_path)
        display.vvv("PUT %s TO %s" % (in_path, out_path), host=self._psrp_host)

        out_path = self._shell._unquote(out_path)
        script = u'''begin {
    $ErrorActionPreference = "Stop"

    $path = '%s'
    $fd = [System.IO.File]::Create($path)
    $algo = [System.Security.Cryptography.SHA1CryptoServiceProvider]::Create()
    $bytes = @()
} process {
    $bytes = [System.Convert]::FromBase64String($input)
    $algo.TransformBlock($bytes, 0, $bytes.Length, $bytes, 0) > $null
    $fd.Write($bytes, 0, $bytes.Length)
} end {
    $fd.Close()
    $algo.TransformFinalBlock($bytes, 0, 0) > $null
    $hash = [System.BitConverter]::ToString($algo.Hash)
    $hash = $hash.Replace("-", "").ToLowerInvariant()

    Write-Output -InputObject "{`"sha1`":`"$hash`"}"
}''' % self._shell._escape(out_path)

        cmd_parts = self._shell._encode_script(script, as_list=True,
                                               strict_mode=False,
                                               preserve_rc=False)
        b_in_path = to_bytes(in_path, errors='surrogate_or_strict')
        if not os.path.exists(b_in_path):
            raise AnsibleFileNotFound('file or module does not exist: "%s"'
                                      % to_native(in_path))

        in_size = os.path.getsize(b_in_path)
        buffer_size = int(self.runspace.connection.max_payload_size / 4 * 3)

        # copying files is faster when using the raw WinRM shell and not PSRP
        # we will create a WinRS shell just for this process
        # TODO: speed this up as there is overhead creating a shell for this
        with WinRS(self.runspace.connection, codepage=65001) as shell:
            process = Process(shell, cmd_parts[0], cmd_parts[1:])
            process.begin_invoke()

            offset = 0
            with open(b_in_path, 'rb') as src_file:
                for data in iter((lambda: src_file.read(buffer_size)), b""):
                    offset += len(data)
                    display.vvvvv("PSRP PUT %s to %s (offset=%d, size=%d" %
                                  (in_path, out_path, offset, len(data)),
                                  host=self._psrp_host)
                    b64_data = base64.b64encode(data) + b"\r\n"
                    process.send(b64_data, end=(src_file.tell() == in_size))

                # the file was empty, return empty buffer
                if offset == 0:
                    process.send(b"", end=True)

            process.end_invoke()
            process.signal(SignalCode.CTRL_C)

        if process.rc != 0:
            raise AnsibleError(to_native(process.stderr))

        put_output = json.loads(process.stdout)
        remote_sha1 = put_output.get("sha1")

        if not remote_sha1:
            raise AnsibleError("Remote sha1 was not returned, stdout: '%s', "
                               "stderr: '%s'" % (to_native(process.stdout),
                                                 to_native(process.stderr)))

        local_sha1 = secure_hash(in_path)
        if not remote_sha1 == local_sha1:
            raise AnsibleError("Remote sha1 hash %s does not match local hash "
                               "%s" % (to_native(remote_sha1),
                                       to_native(local_sha1)))

    def fetch_file(self, in_path, out_path):
        super(Connection, self).fetch_file(in_path, out_path)
        display.vvv("FETCH %s TO %s" % (in_path, out_path),
                    host=self._psrp_host)

        in_path = self._shell._unquote(in_path)
        out_path = out_path.replace('\\', '/')

        # because we are dealing with base64 data we need to get the max size
        # of the bytes that the base64 size would equal
        max_b64_size = int(self.runspace.connection.max_payload_size -
                           (self.runspace.connection.max_payload_size / 4 * 3))
        buffer_size = max_b64_size - (max_b64_size % 1024)

        # setup the file stream with read only mode
        setup_script = '''$ErrorActionPreference = "Stop"
$path = "%s"

if (Test-Path -Path $path -PathType Leaf) {
    $fs = New-Object -TypeName System.IO.FileStream -ArgumentList @(
        $path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    $buffer_size = %d
} elseif (Test-Path -Path $path -PathType Container) {
    Write-Output -InputObject "[DIR]"
} else {
    Write-Error -Message "$path does not exist"
    $host.SetShouldExit(1)
}''' % (self._shell._escape(in_path), buffer_size)

        # read the file stream at the offset and return the b64 string
        read_script = '''$ErrorActionPreference = "Stop"
$fs.Seek(%d, [System.IO.SeekOrigin]::Begin) > $null
$buffer = New-Object -TypeName byte[] -ArgumentList $buffer_size
$bytes_read = $fs.Read($buffer, 0, $buffer_size)

if ($bytes_read -gt 0) {
    $bytes = $buffer[0..($bytes_read - 1)]
    Write-Output -InputObject ([System.Convert]::ToBase64String($bytes))
}'''

        # need to run the setup script outside of the local scope so the
        # file stream stays active between fetch operations
        rc, stdout, stderr = self._exec_psrp_script(setup_script,
                                                    use_local_scope=False)
        if rc != 0:
            raise AnsibleError("failed to setup file stream for fetch '%s': %s"
                               % (out_path, to_native(stderr)))
        elif stdout.strip() == '[DIR]':
            # in_path was a dir so we need to create the dir locally
            makedirs_safe(out_path)
            return

        b_out_path = to_bytes(out_path, errors='surrogate_or_strict')
        makedirs_safe(os.path.dirname(b_out_path))
        offset = 0
        with open(b_out_path, 'wb') as out_file:
            while True:
                display.vvvvv("PSRP FETCH %s to %s (offset=%d" %
                              (in_path, out_path, offset), host=self._psrp_host)
                rc, stdout, stderr = \
                    self._exec_psrp_script(read_script % offset)
                if rc != 0:
                    raise AnsibleError("failed to transfer file to '%s': %s"
                                       % (out_path, to_native(stderr)))

                data = base64.b64decode(stdout.strip())
                out_file.write(data)
                if len(data) < buffer_size:
                    break

            rc, stdout, stderr = self._exec_psrp_script("$fs.Close()")
            if rc != 0:
                display.warning("failed to close remote file stream of file "
                                "'%s': %s" % (in_path, to_native(stderr)))

    def close(self):
        ''' terminate the connection; nothing to do here '''
        self._connected = False
