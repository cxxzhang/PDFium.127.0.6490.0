#!/usr/bin/env python3

# Copyright 2012 The Goma Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
# TODO: remove GOMA_COMPILER_PROXY_PORT from code.
#                    it could be 8089, 8090, ... actually.
"""A Script to manage compiler_proxy.

It starts/stops compiler_proxy.exe or compiler_proxy.
"""




import collections
import csv
import ctypes
import datetime
import glob
import gzip
import hashlib
import io
import json
import os
import random
import re
import shutil
import signal
import socket
import string
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
_DEFAULT_ENV = [
    ('USE_SSL', 'true'),
    ('PING_TIMEOUT_SEC', '60'),
    ('LOG_CLEAN_INTERVAL', str(24 * 60 * 60)),
    ]
_DEFAULT_NO_SSL_ENV = [
    ('SERVER_PORT', '80'),
    ]
_DEFAULT_PROXY_PORT = '19080'
_MAX_COOLDOWN_WAIT = 10  # seconds to wait for compiler_proxy to shutdown.
_COOLDOWN_SLEEP = 1  # seconds to each wait for compiler_proxy to shutdown.
_CRASH_DUMP_DIR = 'goma_crash'
_CACHE_DIR = 'goma_cache'
_PRODUCT_NAME = 'Goma'  # product name used for crash report.
_DUMP_FILE_SUFFIX = '.dmp'
_CHECKSUM_FILE = 'sha256.json'
_PORT_UNAVAILABLE = object()

_TIMESTAMP_PATTERN = re.compile('(\d{4}/\d{2}/\d{2} \d{2}:\d{2}:\d{2})')
_TIMESTAMP_FORMAT = '%Y/%m/%d %H:%M:%S'

_CRASH_SERVER = 'https://clients2.google.com/cr/report'
_STAGING_CRASH_SERVER = 'https://clients2.google.com/cr/staging_report'


def _IsFlagTrue(flag_name, default=False):
  """Return true when the given flag is true.

  Note:
  Implementation is based on client/env_flags.h.
  Any values that do not match _TRUE_PATTERN are False.

  Args:
    flag_name: name of an environment variable.
    default: default return value if the flag is not set.

  Returns:
    True if the flag is true.  Otherwise False.
  """
  flag_value = os.environ.get(flag_name, '')
  if not flag_value:
    return default

  # This comes from
  # https://github.com/abseil/abseil-cpp/blob/d902eb869bcfacc1bad14933ed9af4bed006d481/absl/strings/numbers.cc#L132
  if flag_value.lower() in ('true', 't', 'yes', 'y', '1'):
    return True
  if flag_value.lower() in ('false', 'f', 'no', 'n', '0'):
    return False

  raise Error('failed to parse bool flag: %s' % flag_value)

def _SetGomaFlagDefaultValueIfEmpty(flag_name, default_value):
  """Set default value to the given flag if it is not set.

  Args:
    flag_name: name of a GOMA flag without GOMA_ prefix.
    default_value: default value to be set if the flag is not set.
  """
  full_flag_name = 'GOMA_%s' % flag_name
  if full_flag_name not in os.environ:
    os.environ[full_flag_name] = default_value


def _DecodeBytes(data):
  """This function decodes bytes type to string.

  Args:
    data: arbitrary data type.  Can be None.

  Returns:
    returns utf-8 deocded data for bytes, otherwise return as-is.
  """
  if isinstance(data, bytes):
    return data.decode('utf-8', 'ignore')
  return data


def _ParseManifestContents(manifest):
  """Parse contents of MANIFEST into a dictionary.

  Args:
    manifest: a string of manifest to be parsed.

  Returns:
    The dictionary of key and values in string.
  """
  output = {}
  for line in manifest.splitlines():
    pair = line.strip().split('=', 1)
    if len(pair) == 2:
      output[pair[0].strip()] = pair[1].strip()
  return output


def _ParseLsof(data):
  """Parse lsof.

  Expected inputs are results of:
  - lsof -F pun <filename>
    e.g.
    p1234
    u5678
    f9
  - lsof -F pun -p <pid>
    e.g.
    p1234
    u5678
    fcwd
    n/
    fmem
    n/lib/ld.so
    (f and n repeats, which should be owned by pid:1234 & uid:5678)
  - lsof -F pun -P -i tcp:<port>
    e.g.
    p1234
    u5678
    f9
    nlocalhost:1112

  Although this function might only be used on Posix environment, I put this
  here for ease of testing.

  This function returns:
  | [{'uid': 1L, 'pid': 2L}]
  or
  | [{'uid': 1L, 'pid': 2L, 'name': '/tmp/goma.ipc'}]
  or
  | [{'uid': 1L, 'pid': 2L, 'name': 'localhost:8088'}]

  Args:
    data: result of lsof.

  Returns:
    a list of dictionaries parsed from data.
  """
  pid = None
  uid = None
  contents = []
  for line in data.splitlines():
    if not line:  # skip empty line.
      continue

    code = line[0]
    value = line[1:]

    if code == 'p':
      pid = int(value)
    elif code == 'u':
      uid = int(value)
    elif code == 'n':
      if uid is None or pid is None:
        raise Error('failed to parse lsof result: %s' % data)
      # Omit type=STREAM at the end.
      TYPE_STREAM = ' type=STREAM'
      if value.endswith(TYPE_STREAM):
        value = value[0:-len(TYPE_STREAM)]
      contents.append({'name': value,
                       'uid': uid,
                       'pid': pid})
  return contents


def _GetEnvMatchedCondition(candidates, condition, default_value):
  """Returns environmental variable that matched the condition.

  Args:
    candidates: a list of string to specify environmental variables.
    condition: a condition to decide which value to return.
    default_value: a string to be returned if no candidates matched.

  Returns:
    a string of enviromnental variable's value that matched the condition.
    Otherwise, default_value will be returned.
  """
  for candidate in candidates:
    value = os.environ.get(candidate, '')
    if value and condition(value):
      return value
  return default_value


def _GetTempDirectory():
  """Get temp directory.

  Returns:
    a directory name.
  """
  candidates = ['TMPDIR', 'TMP']
  return _GetEnvMatchedCondition(candidates, os.path.isdir, '/tmp')


def _GetLogDirectory():
  """Get directory where log exists.

  Returns:
    a directory name.
  """
  candidates = ['GLOG_log_dir', 'TEST_TMPDIR', 'TMPDIR', 'TMP']
  return _GetEnvMatchedCondition(candidates, os.path.isdir, '/tmp')


def _GetUsernameEnv():
  """Get user name.

  Returns:
    an user name that runs this script.
  """
  candidates = ['SUDO_USER', 'USERNAME', 'USER', 'LOGNAME']
  return _GetEnvMatchedCondition(candidates,
                                 lambda x: x != 'root',
                                 '')


def _GetHostname():
  """Gets hostname.

  Returns:
    a hostname of the machine running this script.
  """
  return socket.gethostname()


def _FindCommandInPath(command, find_subdir_rule=os.path.join):
  """Find command in the PATH.

  Args:
    command: a string of command name to find out.
    find_subdir_rule: a function to explore sub directory.

  Returns:
    a string of a full path name if the command is found. Otherwise, None.
  """
  for directory in os.environ['PATH'].split(os.path.pathsep):
    fullpath = find_subdir_rule(directory, command)
    if fullpath and os.path.isfile(fullpath) and os.access(fullpath, os.X_OK):
      return fullpath
  return None


def _ParseFlagz(flagz):
  """Returns a dictionary of user-configured flagz.

  Note that the dictionary will not contain auto configured flags.

  Args:
    flagz: a string returned by compiler_proxy's /flagz.

  Returns:
    a dictionary of user-configured flags.
  """
  envs = {}
  for line in flagz.splitlines():
    line = line.strip()
    if line.endswith('(auto configured)'):
      continue
    pair = line.split('=', 1)
    if len(pair) == 2:
      envs[pair[0].strip()] = pair[1].strip()
  return envs


def _IsGomaFlagUpdated(envs):
  """Returns true if environment is updated from the argument.

  Note: caller MUST NOT set environ after call of this method.
  Otherwise, this function may always return true.

  Args:
    a dictionary of environment to check. e.g. {
      'GOMA_USE_SSL': 'true',
    }

  Returns:
    True if one of values is different from given one.
  """
  for key, original in envs.items():
    new = os.environ.get(key)
    if new != original:
      return True
  for key, value in os.environ.items():
    if key.startswith('GOMA_'):
      if value != envs.get(key):
        return True
  return False


def _CalculateChecksum(filename):
  """Calculate SHA256 checksum of given file.

  Args:
    filename: a string filename to calculate checksum.

  Returns:
    hexdigest string of file contents.
  """
  with open(filename, 'rb') as f:
    return hashlib.sha256(f.read()).hexdigest()


def _GetLogFileTimestamp(glog_log):
  """Returns timestamp when the given glog log was created.

  Args:
    glog_log: a filename of a google-glog log.

  Returns:
    datetime instance when the logfile was created.
    Or, returns None if not a glog file.

  Raises:
    IOError if this function cannot open glog_log.
  """
  with open(glog_log) as f:
    matched = _TIMESTAMP_PATTERN.search(f.readline())
    if matched:
      return datetime.datetime.strptime(matched.group(1), _TIMESTAMP_FORMAT)
  return None


def _OverrideEnvVar(key, value):
  """Sets env var `key` to `value`, overriding the existing value.

  Args:
    key: The environment variable name
    value: The value to set the environment variable. Use value=None to unset.
  """
  if value is not None:
    print('override %s=%s' % (key, value))
    os.environ[key] = value
  elif key in os.environ:
    print('override unset %s' % key)
    del os.environ[key]


class ConfigError(Exception):
  """Raises when an error found in configurations."""


class NotLoginError(Exception):
  """Raises when user is not logged in yet."""


class Error(Exception):
  """Raises when an error found in the system."""


class CalledProcessError(Error):
  """Raises when failed for check call using PopenWithCheck."""

  def __init__(self, returncode, stdout=None, stderr=None):
    super(Exception, self).__init__()
    self.returncode = returncode
    self.stdout = stdout
    self.stderr = stderr

  def __str__(self):
    return "Command returned non-zero exit status %d" % self.returncode


class Popen(subprocess.Popen):
  """subprocess.Popen with automatic bytes output to string conversion."""

  def communicate(self, input=None, timeout=None):
    # pylint: disable=W0622
    # To keep the interface consisntent with subprocess.Popen,
    # we need to use |input| here.
    stdout, stderr = super().communicate(input, timeout)
    return _DecodeBytes(stdout), _DecodeBytes(stderr)


class PopenWithCheck(Popen):
  """subprocess.Popen with automatic exit status check on communicate."""

  def communicate(self, input=None, timeout=None):
    # I do not think argument name |input| is good but this is from the original
    # communicate method.
    # pylint: disable=W0622
    stdout, stderr = super().communicate(input, timeout)
    if self.returncode is None or self.returncode != 0:
      raise CalledProcessError(
          returncode=self.returncode,
          stdout=stdout,
          stderr=stderr)
    return stdout, stderr


def _CheckOutput(args, **kwargs):
  """subprocess.check_output that works with python2 and python3.

  This function uses PopenWithCheck inside to silently converts bytes to
  string.
  """
  return PopenWithCheck(args,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        **kwargs).communicate()[0]


class HttpProxyDriver:
  """Driver of http_proxy."""

  _PID_FILENAME = 'http_proxy.pid'
  _LOG_FILENAME = 'http_proxy.log'
  _HOST_FILENAME = 'http_proxy.host'

  def __init__(self, env, var_dir):
    """initialize.

    Args:
      env: a GomaEnv
      var_dir: a directory name to store the pid, log.
    """
    self._env = env
    self._pid_file = os.path.join(var_dir, self._PID_FILENAME)
    self._log_file = os.path.join(var_dir, self._LOG_FILENAME)
    self._host_file = os.path.join(var_dir, self._HOST_FILENAME)

  def UpdateEnvIfNeeded(self):
    if not self._env.use_http_proxy:
      return
    print('Enable http_proxy')
    self._env.UpdateEnvForHttpProxy()

  def IsUpdated(self):
    if not self._env.use_http_proxy:
      # if |use_http_proxy| is false and http_proxy not running,
      # then considered as updated.
      return os.path.exists(self._host_file)
    # if |use_http_proxy| is true and http_proxy is not running
    # or it is running for different server host, then considered
    # as updated.
    try:
      with open(self._host_file) as f:
        return f.read() != self._env.server_host
    except IOError:
      pass
    return True

  def Start(self):
    if not self._env.use_http_proxy:
      return
    with open(self._log_file, 'w') as logfile:
      p = self._env.ExecHttpProxy(logfile)
    with open(self._pid_file, 'w') as f:
      f.write(str(p.pid))
    with open(self._host_file, 'w') as f:
      f.write(self._env.server_host)

  def Stop(self):
    pid = -1
    try:
      with open(self._pid_file) as f:
        pid = int(f.read())
    except IOError:  # http_proxy might not be started by goma_ctl before.
      pass
    if pid > 0:  # http_proxy should not need to be killed gracefully.
      print('killing http_proxy (pid=%d)...' % pid)
      try:
        os.kill(pid, signal.SIGTERM)
      except OSError as ex:
        try:
          os.kill(pid, 0)
          sys.stderr.write('failed to kill http_proxy (pid=%d %s): %s\n' %
                           (pid, self._pid_file, ex))
        except OSError:
          # if it failed to send signal 0 to pid, pid doesn't exist,
          # so self._pid_file has stale pid.
          pass
      os.remove(self._pid_file)
      os.remove(self._host_file)

  @property
  def log_filename(self):
    return self._log_file


class GomaDriver:
  """Driver of Goma control."""

  def __init__(self, env):
    """Initialize GomaDriver.

    Args:
      env: an instance of GomaEnv subclass.
    """
    self._env = env
    self._latest_package_dir = 'latest'
    self._action_mappings = {
        'audit': self._CheckAudit,
        'ensure_start': self._EnsureStartCompilerProxy,
        'ensure_stop': self._EnsureStopCompilerProxy,
        'histogram': self._PrintHistogram,
        'jsonstatus': self._PrintJsonStatus,
        'rbe_stats': self._PrintRbeStats,
        'report': self._Report,
        'restart': self._RestartCompilerProxy,
        'showflags': self._PrintFlags,
        'start': self._StartCompilerProxy,
        'stat': self._PrintStatistics,
        'status': self._CheckStatus,
        'stop': self._StopCompilerProxyAndWait,
        'version': self._PrintVersion,
        'goma_dir': self._PrintGomaDir,
        'update_hook': self._UpdateHook,
    }
    self._version = 0
    self._manifest = {}
    self._args = []
    self._ReadManifest()
    self._compiler_proxy_running = None
    self._http_proxy_driver = HttpProxyDriver(self._env,
                                              self._env.GetGomaTmpDir())

  def _ReadManifest(self):
    """Reads MANIFEST file.
    """
    self._manifest = self._env.ReadManifest()
    if 'VERSION' in self._manifest:
      self._version = int(self._manifest['VERSION'])

  def _GetRunningCompilerProxyVersion(self):
    versionz = self._env.ControlCompilerProxy('/versionz', check_running=True)
    if versionz['status']:
      return versionz['message'].strip()
    return None

  def _GetDiskCompilerProxyVersion(self):
    return self._env.GetCompilerProxyVersion().replace('GOMA version',
                                                       '').strip()

  def _GetCompilerProxyHealthz(self):
    """Returns compiler proxy healthz message."""
    healthz = self._env.ControlCompilerProxy('/healthz', check_running=False)
    if healthz['status']:
      return healthz['message'].split()[0].strip()
    return 'unavailable /healthz'

  def _IsCompilerProxySilentlyUpdated(self):
    """Returns True if compiler_proxy is different from running version."""
    disk_version = self._GetDiskCompilerProxyVersion()
    running_version = self._GetRunningCompilerProxyVersion()
    if running_version:
      return running_version != disk_version
    return False

  def _IsGomaFlagUpdated(self):
    flagz = self._env.ControlCompilerProxy('/flagz', check_running=False)
    if flagz['status']:
      if _IsGomaFlagUpdated(_ParseFlagz(flagz['message'].strip())):
        return True
    return self._http_proxy_driver.IsUpdated()

  def _GenericStartCompilerProxy(self, ensure=False):
    self._env.CheckAuthConfig()
    self._env.CheckConfig()
    self._http_proxy_driver.UpdateEnvIfNeeded()
    if self._compiler_proxy_running is None:
      self._compiler_proxy_running = self._env.CompilerProxyRunning()
    if (not ensure and self._env.MayUsingDefaultIPCPort() and
        self._compiler_proxy_running):
      self._KillStakeholders()
      self._compiler_proxy_running = False

    if 'VERSION' in self._manifest:
      print('Using goma VERSION=%s' % self._manifest['VERSION'])
    disk_version = self._GetDiskCompilerProxyVersion()
    print('GOMA version %s' % disk_version)
    if ensure and self._compiler_proxy_running:
      healthz = self._GetCompilerProxyHealthz()
      if healthz != 'ok':
        print('goma is not in healthy state: %s' % healthz)
      updated = self._IsCompilerProxySilentlyUpdated()
      flag_updated = self._IsGomaFlagUpdated()
      if flag_updated:
        print('flagz is updated from the previous time.')
      if healthz != 'ok' or updated or flag_updated:
        self._ShutdownCompilerProxy()
        if not self._WaitCooldown():
          self._KillStakeholders()
        self._compiler_proxy_running = False

    if ensure and self._compiler_proxy_running:
      print()
      print('server: %s' % self._env.server_host)
      print('goma is already running.')
      print()
      return

    if not self._compiler_proxy_running:
      print('server: %s' % self._env.server_host)
      self._http_proxy_driver.Start()
      self._env.ExecCompilerProxy()
      self._compiler_proxy_running = True

    if self._GetStatus():
      running_version = self._GetRunningCompilerProxyVersion()
      if running_version != disk_version:
        print('Updated GOMA version %s' % running_version)
      print()
      print('Now goma is ready!')
      print()
      return
    sys.stderr.write('Failed to start compiler_proxy.\n')
    try:
      subprocess.check_call([
          sys.executable,
          os.path.join(self._env.GetScriptDir(), 'goma_auth.py'), 'info'
      ])
      sys.stderr.write('Temporary error?  try again\n')
    except subprocess.CalledProcessError:
      pass
    sys.exit(1)

  def _StartCompilerProxy(self):
    self._GenericStartCompilerProxy(ensure=False)

  def _EnsureStartCompilerProxy(self):
    self._GenericStartCompilerProxy(ensure=True)

  def _EnsureStopCompilerProxy(self):
    self._ShutdownCompilerProxy()
    if not self._WaitCooldown():
      self._KillStakeholders()

  def _StopCompilerProxyAndWait(self):
    self._ShutdownCompilerProxy()
    if not self._WaitCooldown(wait_seconds=5):
      print('Compiler proxy is still running, consider running '
            '`goma_ctl ensure_stop` or manually killing the process.')

  def _CheckStatus(self):
    status = self._GetStatus()
    if not status:
      sys.exit(1)

  def _GetStatus(self):
    reply = self._env.ControlCompilerProxy('/healthz', need_pids=True)
    print('compiler proxy (pid=%(pid)s) status: %(url)s %(message)s' % reply)
    if reply['message'].startswith('error:'):
      reply['status'] = False
    return reply['status']

  def _ShutdownCompilerProxy(self):
    self._http_proxy_driver.Stop()
    print('Killing compiler proxy.')
    reply = self._env.ControlCompilerProxy('/quitquitquit')
    print('compiler proxy status: %(url)s %(message)s' % reply)

  def _PrintVersion(self):
    """Print binary/running version of goma. """
    binary_version = self._GetDiskCompilerProxyVersion()
    print('compiler_proxy binary %s' % binary_version)
    binary_path = self._env.CompilerProxyBinary()
    print(' %s' % binary_path)
    versionz = self._env.ControlCompilerProxy('/versionz', check_running=True)
    if versionz['status']:
      running_version = versionz['message'].strip()
      print('running compiler_proxy version %s' % running_version)
      progz = self._env.ControlCompilerProxy('/progz', check_running=False)
      if progz['status']:
        running_binary_path = os.path.normcase(progz['message'].strip())
        print(' %s' % running_binary_path)
      else:
        # old binary doesn't support /progz. ignores
        running_binary_path = binary_path
        print(' unknown running binary path')
      if binary_path == running_binary_path:
        if binary_version == running_version:
          print('running binary is up-to-date')
        else:
          print('WARNING: binary was updated. restart required')
      else:
        print('WARNING: different binary is running')
    else:
      print('no running compiler_proxy')

  def _PrintGomaDir(self):
    """Print goma dir."""
    goma_dir_source = '$GOMA_DIR'
    goma_dir = os.environ.get('GOMA_DIR')
    if not goma_dir:
      progz = self._env.ControlCompilerProxy('/progz', check_running=True)
      if progz['status']:
        running_binary_path = progz['message'].strip()
        goma_dir = os.path.dirname(running_binary_path)
        goma_dir_source = 'running compiler_proxy'
      else:
        goma_dir = self._env._dir
        goma_dir_source = 'goma_ctl.py path'
    if not os.path.exists(os.path.join(goma_dir, self._env._GOMACC)):
      sys.stderr.write('%s not exists in %s (%s)\n' %
                       (self._env._GOMACC, goma_dir, goma_dir_source))
      sys.exit(1)
    print('%s' % goma_dir)

  def _UpdateHook(self):
    """Restart compiler_proxy if binary is updated."""
    binary_version = self._GetDiskCompilerProxyVersion()
    binary_path = self._env.CompilerProxyBinary()
    versionz = self._env.ControlCompilerProxy('/versionz', check_running=True)
    if versionz['status']:
      running_version =  versionz['message'].strip()
      running_binary_path = ''
      progz = self._env.ControlCompilerProxy('/progz', check_running=False)
      if progz['status']:
        running_binary_path = os.path.normcase(progz['message'].strip())
      if binary_path == running_binary_path and \
        binary_version != running_version:
        print('update %s -> %s @%s' % (running_version, binary_version,
                                       binary_path))
        # TODO: preserve flag?
        self._RestartCompilerProxy()
      else:
        print(
            'update %s@%s -> %s@%s, skip restart' %
            (running_version, running_binary_path, binary_version, binary_path))
    else:
      print('compiler_proxy is not running')

  def _WaitCooldown(self, wait_seconds=_MAX_COOLDOWN_WAIT):
    """Wait until compiler_proxy process have finished.

    This will give up after waiting for wait_second.
    It would return False, if other compiler_proxy is running on other IPC port.

    Returns:
      True if compiler_proxy successfully shutdown.  Otherwise, False.
    """
    if not self._env.CompilerProxyRunning():
      return True
    if self._env.IsCompilerProxyPortUnavailable():
      return False
    print('Wait for compiler_proxy process to terminate...')
    for cnt in range(wait_seconds):
      if not self._env.CompilerProxyRunning():
        break
      print(wait_seconds - cnt)
      sys.stdout.flush()
      time.sleep(_COOLDOWN_SLEEP)
    else:
      print('Cannot shutdown compiler_proxy in %ss' % wait_seconds)
      return False
    print()
    return True

  def _KillStakeholders(self):
    """Kill and wait until its shutdown."""
    self._env.KillStakeholders()
    if not self._WaitCooldown():
      print('Could not kill compiler_proxy.')
      print('trying to kill it forcefully.')
      self._env.KillStakeholders(force=True)
    if not self._WaitCooldown():
      print('Could not kill compiler_proxy.')
      print('Probably, somebody else also runs compiler_proxy.')

  def _RestartCompilerProxy(self):
    if self._compiler_proxy_running is None:
      self._compiler_proxy_running = self._env.CompilerProxyRunning()
    if self._compiler_proxy_running:
      self._ShutdownCompilerProxy()
      if not self._WaitCooldown():
        self._KillStakeholders()
      self._compiler_proxy_running = False
    self._StartCompilerProxy()

  def _PrintStatistics(self):
    print(self._env.ControlCompilerProxy('/statz')['message'])

  def _PrintRbeStats(self):
    print(self._env.ControlCompilerProxy('/api/rbe_statsz')['message'])

  def _PrintHistogram(self):
    print(self._env.ControlCompilerProxy('/histogramz')['message'])

  def _PrintFlags(self):
    flagz = self._env.ControlCompilerProxy('/flagz', check_running=True)
    print(json.dumps(_ParseFlagz(flagz['message'].strip())))

  def _PrintJsonStatus(self):
    status = self._GetJsonStatus()
    if len(self._args) > 1:
      with open(self._args[1], 'w') as f:
        f.write(status)
    else:
      print(status)

  def _CopyLatestInfoFile(self, command_name, dst):
    """Copies latest *.INFO.* file to destination.

    Args:
      command_name: command_name of *.INFO.* file to copy.
                    e.g. compiler_proxy.
      dst: destination directory name.
    """

    infolog_path = self._env.FindLatestLogFile(command_name, 'INFO')
    if infolog_path:
      self._env.CopyFile(infolog_path,
                         os.path.join(dst, os.path.basename(infolog_path)))
    else:
      print('%s log was not found' % command_name)

  def _CopyGomaccInfoFiles(self, dst):
    """Copies gomacc *.INFO.* file to destination. all gomacc logs after
    latest compiler_proxy started.

    Args:
      dst: destination directory name.
    """

    infolog_path = self._env.FindLatestLogFile('compiler_proxy', 'INFO')
    if not infolog_path:
      return
    compiler_proxy_start_time = _GetLogFileTimestamp(infolog_path)
    if not compiler_proxy_start_time:
      print('compiler_proxy start time could not be inferred. ' +
            'gomacc logs won\'t be included.')
      return
    logs = glob.glob(os.path.join(_GetLogDirectory(), 'gomacc.*.INFO.*'))
    for log in logs:
      timestamp = _GetLogFileTimestamp(log)
      if timestamp and timestamp > compiler_proxy_start_time:
        self._env.CopyFile(log, os.path.join(dst, os.path.basename(log)))

  def _InferBuildDirectory(self):
    """Infer latest build directory from compiler_proxy.INFO.

    This would work for chromium build. Not sure for android etc.

    Returns:
      build directory if inferred. None otherwise.
    """

    infolog_path = self._env.FindLatestLogFile('compiler_proxy', 'INFO')
    if not infolog_path:
      print('compiler_proxy log was not found')
      return None

    build_re = re.compile('.*Task:.*Start.* build_dir=(.*)')

    # List build_dir from compiler_proxy, and take only last 10 build dirs.
    # TODO: move this code to GomaEnv to write tests.
    build_dirs = collections.deque()
    with open(infolog_path) as f:
      for line in f.readlines():
        m = build_re.match(line)
        if m:
          build_dirs.append(m.group(1))
          if len(build_dirs) > 10:
            build_dirs.popleft()

    if not build_dirs:
      return None

    counter = collections.Counter(build_dirs)
    for candidate, _ in counter.most_common():
      if os.path.exists(os.path.join(candidate, '.ninja_log')):
        return candidate
    return None

  def _Report(self):
    tempdir = None
    try:
      tempdir = tempfile.mkdtemp()

      self._env.WriteFile(
          os.path.join(tempdir, 'goma_env'), '\n'.join([
              '%s=%s' % (k, v)
              for k, v in os.environ.items()
              if k.startswith('GOMA_') or k.startswith('GOMACTL_')
          ]))

      compiler_proxy_is_working = True
      # Check compiler_proxy is working.
      ret = self._env.ControlCompilerProxy('/healthz')
      if ret.get('status', False):
        print('compiler_proxy is working:')
      else:
        compiler_proxy_is_working = False
        print('compiler_proxy is not working:')
        print('  omit compiler_proxy stats')

      if compiler_proxy_is_working:
        keys = ['compilerinfoz', 'histogramz', 'serverz', 'statz']
        for key in keys:
          ret = self._env.ControlCompilerProxy('/' + key)
          if not ret.get('status', False):
            # Failed to get the message. compiler_proxy has died?
            print('  failed to get %s: %s' % (key, ret['message']))
            continue
          print('  include /%s' % key)
          self._env.WriteFile(os.path.join(tempdir, key + '-output'),
                              ret['message'])

      print('copy compiler_proxy log')
      self._CopyLatestInfoFile('compiler_proxy', tempdir)
      print('copy compiler_proxy-subproc log')
      self._CopyLatestInfoFile('compiler_proxy-subproc', tempdir)
      print('copy goma_fetch log')
      self._CopyLatestInfoFile('goma_fetch', tempdir)
      print('copy gomacc log')
      self._CopyGomaccInfoFiles(tempdir)
      print('copy http_proxy log')
      http_proxy_log = self._http_proxy_driver.log_filename
      if os.path.exists(http_proxy_log):
        self._env.CopyFile(
            http_proxy_log,
            os.path.join(tempdir, os.path.basename(http_proxy_log)))
      print('copy goma_auth config')
      try:
        self._env.WriteFile(
            os.path.join(tempdir, 'goma_auth_config'), self._env.AuthConfig())
      except NotLoginError:
        pass
      except ConfigError as ex:
        print('failed to get auth config %s' % ex)

      build_dir = self._InferBuildDirectory()
      if build_dir:
        print('build directory is inferred as', build_dir)
        src_ninja_log = os.path.join(build_dir, '.ninja_log')
        if os.path.exists(src_ninja_log):
          dst_ninja_log = os.path.join(tempdir, 'ninja_log')
          self._env.CopyFile(src_ninja_log, dst_ninja_log)
        print('  include ninja_log')
      else:
        print('build directory cannot be inferred:')
        print('  omit ninja_log')

      output_filename = os.path.join(_GetTempDirectory(), 'goma-report.tgz')
      self._env.MakeTgzFromDirectory(tempdir, output_filename)

      print()
      print('A report file is successfully created:')
      print(' ', output_filename)
    finally:
      if tempdir:
        shutil.rmtree(tempdir, ignore_errors=True)

  def _GetJsonStatus(self):
    reply = self._env.ControlCompilerProxy('/errorz')
    if not reply['status']:
      return json.dumps({
          'notice': [
              {
                  'version': 1,
                  'compile_error': 'COMPILER_PROXY_UNREACHABLE',
              },
          ]})
    return reply['message']

  def _CheckAudit(self):
    """Audit files in the goma client package.  Exit failure on error."""
    if not self._Audit():
      sys.exit(1)

  def _Audit(self):
    """Audit files in the goma client package.

    Returns:
      False if failed to verify.
    """
    cksums = self._env.LoadChecksum()
    if not cksums:
      print('No checksum could be loaded.')
      return True
    for filename, checksum in cksums.items():
      # TODO: remove following two lines after the next release.
      # Windows checksum file has non-existing .pdb files.
      if os.path.splitext(filename)[1] == '.pdb':
        continue
      digest = self._env.CalculateChecksum(filename)
      if checksum != digest:
        print('%s differs: %s != %s' % (filename, checksum, digest))
        return False
    print('All files verified.')
    return True

  def _OldCrashDumps(self):
    """List old crash dump filenames."""
    return filter(self._env.IsOldFile, self._env.GetCrashDumps())

  def _UploadCrashDump(self):
    """Upload crash dump if exists.

    Important Notice:
    You should not too much trust version number shown in the crash report.
    A version number shown in the crash report may different from what actually
    created a crash dump. Since the version to be sent is collected when
    goma_ctl.py starts up, it may pick the wrong version number if
    compiler_proxy was silently changed without using goma_ctl.py.

    Returns:
      crash dump filesnames that are ok to remove.
    """
    if self._env.IsProductionBinary():
      server_url = _CRASH_SERVER
    else:
      # Set this for testing crash dump upload feature.
      server_url = os.environ.get('GOMACTL_CRASH_SERVER')
      if server_url == 'staging':
        server_url = _STAGING_CRASH_SERVER

    if not server_url:
      # We do not upload crash dump made by the developer's binary.
      return self._OldCrashDumps()

    try:
      (hash_value, timestamp) = self._GetDiskCompilerProxyVersion().split('@')
      version = '%s.%s' % (hash_value[:8], timestamp)
    except OSError:  # means file not exist and we can ignore it.
      version = ''

    if self._version and version:
      version = 'ver %d %s' % (self._version, version)

    send_user_info_default = False
    if _IsFlagTrue('GOMA_SEND_USER_INFO', default=send_user_info_default):
      guid = '%s@%s' % (self._env.GetUsername(), _GetHostname())
    else:
      guid = None

    old_files = []
    for dump_file in self._env.GetCrashDumps():
      uploaded = False
      # Upload crash dumps only when we know its version number.
      if version:
        sys.stderr.write(
            'Uploading crash dump: %s to %s\n' % (dump_file, server_url))
        try:
          report_id = self._env.UploadCrashDump(server_url, _PRODUCT_NAME,
                                                version, dump_file, guid=guid)
          report_id_file = os.environ.get('GOMACTL_CRASH_REPORT_ID_FILE')
          if report_id_file:
            with open(report_id_file, 'w') as f:
              f.write(report_id)
          sys.stderr.write('Report Id: %s\n' % report_id)
          uploaded = True
        except Error as inst:
          sys.stderr.write('Failed to upload crash dump: %s\n' % inst)
      if uploaded or self._env.IsOldFile(dump_file):
        old_files.append(dump_file)
    return old_files

  def _RemoveCrashDumps(self, old_files):
    """Remove old crash dumps if exists.

    Args:
      old_files: dump file names to remove.
    """

    for dump_file in old_files:
      try:
        self._env.RemoveFile(dump_file)
      except OSError as e:
        print('failed to remove %s: %s.' % (dump_file, e))

  def _CreateDirectory(self, dir_name, purpose, suppress_message=False):
    info = {
        'purpose': purpose,
        'dir': dir_name,
        }
    if not self._env.IsDirectoryExist(info['dir']):
      if not suppress_message:
        sys.stderr.write('INFO: creating %(purpose)s dir (%(dir)s).\n' % info)
      self._env.MakeDirectory(info['dir'])
    else:
      if not self._env.EnsureDirectoryOwnedByUser(info['dir']):
        sys.stderr.write(
            'Error: %(purpose)s dir (%(dir)s) is not owned by you.\n' % info)
        raise Error('%(purpose)s dir (%(dir)s) is not owned by you.' % info)

  def _CreateGomaTmpDirectory(self):
    tmp_dir = self._env.GetGomaTmpDir()
    self._CreateDirectory(tmp_dir, 'temp')
    sys.stderr.write('using %s as tmpdir\n' % tmp_dir)
    os.environ['GOMA_TMP_DIR'] = tmp_dir

  def _CreateCrashDumpDirectory(self):
    self._CreateDirectory(self._env.GetCrashDumpDirectory(), 'crash dump',
                          suppress_message=True)

  def _CreateCacheDirectory(self):
    self._CreateDirectory(self._env.GetCacheDirectory(), 'cache')

  def _Usage(self):
    """Print usage."""
    program_name = self._env.GetGomaCtlScriptName()
    print('Usage: %s <subcommand>, available subcommands are:' % program_name)
    print('  audit                 audit goma client.')
    print('  ensure_start          start compiler proxy if it is not running')
    print('  ensure_stop           synchronous stop of compiler proxy')
    print('  goma_dir              show goma dir')
    print('  histogram             show histogram')
    print('  jsonstatus [outfile]  show status report in JSON')
    print('  rbe_stats             show Goma-RBE compilation stats')
    print('  report                create a report file.')
    print('  restart               restart compiler proxy')
    print('  showflags             show flag settings in json')
    print('  start                 start compiler proxy')
    print('  stat                  show statistics')
    print('  status                get compiler proxy status')
    print('  stop                  asynchronous stop of compiler proxy')
    print('  update_hook           restart if binary is updated.')
    print('  version               show binary/running version')


  def _DefaultAction(self):
    if self._args and not self._args[0] in ('-h', '--help', 'help'):
      print('unknown command: %s' % ' '.join(self._args))
      print()
    self._Usage()

  def Dispatch(self, args):
    """Parse and dispatch commands."""
    is_audit = args and (args[0] == 'audit')
    if not is_audit:
      # when audit, we don't want to run gomacc to detect temp directory,
      # since gomacc might be binary for different platform.
      self._CreateGomaTmpDirectory()
      upload_crash_dump = False
      if upload_crash_dump:
        old_files = self._UploadCrashDump()
      else:
        old_files = self._OldCrashDumps()
      self._RemoveCrashDumps(old_files)
      self._CreateCrashDumpDirectory()
      self._CreateCacheDirectory()
    self._args = args
    if not args:
      self._GetStatus()
    else:
      self._action_mappings.get(args[0], self._DefaultAction)()


class GomaEnv:
  """Goma running environment."""
  # You must implement following protected variables in subclass.
  _GOMACC = ''
  _COMPILER_PROXY = ''
  _GOMA_FETCH = ''
  _HTTP_PROXY = ''
  _COMPILER_PROXY_IDENTIFIER_ENV_NAME = ''
  _DEFAULT_ENV = []
  _DEFAULT_SSL_ENV = []

  def __init__(self, script_dir=SCRIPT_DIR):
    self._dir = os.path.abspath(script_dir)
    self._http_proxy_binary = os.path.join(self._dir, self._HTTP_PROXY)
    self._compiler_proxy_binary = os.path.normcase(
        os.environ.get('GOMA_COMPILER_PROXY_BINARY',
                       os.path.join(self._dir, self._COMPILER_PROXY)))
    self._goma_fetch = None
    if os.path.exists(os.path.join(self._dir, self._GOMA_FETCH)):
      self._goma_fetch = os.path.join(self._dir, self._GOMA_FETCH)
    self._is_daemon_mode = False
    self._gomacc_binary = os.path.join(self._dir, self._GOMACC)
    self._manifest = self.ReadManifest(self._dir)
    self._platform = self._manifest.get('PLATFORM', '')
    # If manifest does not have PLATFORM, goma_ctl.py tries to get it from env.
    # See: b/16274764
    if not self._platform:
      self._platform = os.environ.get('PLATFORM', '')
    self._version = self._manifest.get('VERSION', '')
    self._time = time.time()
    self._goma_params = None
    self._gomacc_socket = None
    self._gomacc_port = None
    self._backup = None
    self._goma_tmp_dir = None
    # TODO: remove this in python3
    self._delete_tmp_dir = False
    self._SetupEnviron()
    self._server_host = None
    self._use_http_proxy = None
    self._http_proxy_port = None

  def __del__(self):
    if self._delete_tmp_dir:
      shutil.rmtree(self._goma_tmp_dir)

  # methods that may interfere with external environment.
  def MayUsingDefaultIPCPort(self):
    """Returns True if IPC port is not configured in environmental variables.

    If os.environ has self._COMPILER_PORT_IDENTIFIER_ENV_NAME, it may use
    non-default IPC port.  Otherwise, it would use default port.

    Returns:
      True if os.environ does not have self._COMPILER_IDENTIFIER_ENV_NAME.
    """
    return self._COMPILER_PROXY_IDENTIFIER_ENV_NAME not in os.environ

  def GetCompilerProxyVersion(self):
    """Returns compiler proxy version."""
    return PopenWithCheck([self._compiler_proxy_binary, '--version'],
                          stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT).communicate()[0].rstrip()

  def CompilerProxyBinary(self):
    """Returns compiler_proxy binary path."""
    return self._compiler_proxy_binary

  def GetScriptDir(self):
    return self._dir

  def ReadManifest(self, directory=''):
    """Read manifest from MANIFEST file in the directory.

    Args:
      directory: a string of directory name to read the manifest file.

    Returns:
      A dictionary of manifest if the manifest file exist.
      Otherwise, an empty dictionary.
    """
    manifest_path = os.path.join(self._dir, directory, 'MANIFEST')
    if not os.path.isfile(manifest_path):
      return {}
    return _ParseManifestContents(open(manifest_path, 'r').read())

  def AuthConfig(self):
    """Get `goma_auth.py config` output.

    Returns:
      output of `goma_auth.py config`.
    Raises:
      NotLoginError if not logged in.
      ConfigError if `goma_auth.py config` failed.
    """
    for k in [
        'GOMA_SERVICE_ACCOUNT_JSON_FILE', 'GOMA_GCE_SERVICE_ACCOUNT',
        'LUCI_CONTEXT'
    ]:
      if k in os.environ:
        return '# %s=%s\n' % (k, os.environ[k])
    # not service account.
    try:
      out = PopenWithCheck(
          [sys.executable,
           os.path.join(SCRIPT_DIR, 'goma_auth.py'), 'config'],
          stdout=subprocess.PIPE,
          stderr=subprocess.PIPE).communicate()[0]
      return out
    except CalledProcessError as ex:
      if ex.stdout:
        sys.stdout.write(ex.stdout + '\n')
      if ex.stderr:
        sys.stderr.write(ex.stderr + '\n')
      if ex.returncode == 1:
        raise NotLoginError('not logged in') from ex
      raise ConfigError('goma_auth.py config failed.') from ex

  def CheckAuthConfig(self):
    """Checks `goma_auth.py config` unless service accounts.

    Updates goma flags by `goma_auth.py config` outputs.
    If `goma_auth.py config` exits with 1, it shows stdout/stderr
    and exit the program. Other exit status raises ConfigError.

    Raises:
      ConfigError if `goma_auth.py config` failed.
    """
    if _IsFlagTrue('GOMACTL_SKIP_AUTH'):
      return
    try:
      out = self.AuthConfig()
    except NotLoginError:
      sys.exit(1)
    for line in out.splitlines():
      if line.startswith('#'):
        print(line)
        continue
      if '=' not in line:
        print(line)
        continue
      k, v = line.split('=', 1)
      if not k.startswith('GOMA_') and not k.startswith('GOMACTL_'):
        print('bad goma_auth config?: %s=%s' % (k, v))
        continue
      if k in os.environ:
        print('user set %s=%s (ignore %s)' % (k, os.environ[k], v))
        continue
      _OverrideEnvVar(k, v)

  def CheckConfig(self):
    """Checks GomaEnv configurations."""
    socket_name = os.environ.get(self._COMPILER_PROXY_IDENTIFIER_ENV_NAME, '')
    if self._gomacc_socket != socket_name:
      self._gomacc_socket = socket_name
      self._gomacc_port = None # invalidate
    if not os.path.isdir(self._dir):
      raise ConfigError('%s is not directory' % (self._dir))
    if not os.path.isfile(self._compiler_proxy_binary):
      raise ConfigError('compiler_proxy(%s) not exist' % (
          self._compiler_proxy_binary))
    if not os.path.isfile(self._gomacc_binary):
      raise ConfigError('gomacc(%s) not exist' % self._gomacc_binary)
    self._CheckPlatformConfig()

  def IsCompilerProxyPortUnavailable(self):
    """Returns compiler_proxy port unavailability state."""
    return self._gomacc_port == _PORT_UNAVAILABLE

  def _GetCompilerProxyPort(self, proc=None):
    """Gets compiler_proxy's port by "gomacc port".

    Args:
      proc: an instance of subprocess.Popen to poll.

    Returns:
      a string of compiler proxy port number.

    Raises:
      Error: if it cannot get compiler proxy port.
    """
    if self.IsCompilerProxyPortUnavailable():
      raise Error('compiler_proxy port unavailable')

    if self._gomacc_port:
      return self._gomacc_port

    port_error = ''
    stderr = ''

    # output glog output to stderr but ignore it because it is usually about
    # failure of connecting IPC port.
    env = os.environ.copy()
    env['GLOG_logtostderr'] = 'true'

    port_start_time = time.time()
    port_timeout_sec = int(os.environ.get('GOMACTL_PORT_TIMEOUT_SEC', '10'))
    port_deadline = port_start_time + port_timeout_sec
    if proc:
      # Wait for GOMA_PING_TIMEOUT_SEC if compiler_proxy was launched just now.
      ping_timeout_sec = int(os.environ.get('GOMA_PING_TIMEOUT_SEC', '0'))
      port_deadline += ping_timeout_sec
    port_print_time = port_start_time
    while True:
      current_time = time.time()
      if current_time > port_deadline:
        break

      if current_time - port_print_time > 1:
        print('waiting for compiler_proxy port (timeout in %d)...' %
              int(round(port_deadline - current_time)))
        port_print_time = current_time

      with tempfile.TemporaryFile() as tf:
        # "gomacc port" command may fail until compiler_proxy gets ready.
        # We know gomacc port only output port number to stdout, whose size
        # should be within pipe buffer.
        portcmd = subprocess.Popen([self._gomacc_binary, 'port'],
                                   stdout=subprocess.PIPE,
                                   stderr=tf,
                                   env=env)
        self._WaitWithTimeout(portcmd, 1)
        if portcmd.poll() is None:
          # port takes long time
          portcmd.kill()
          port_error = 'compiler_proxy port request has timed out'
          tf.seek(0)
          stderr = tf.read()
          continue
        portcmd.wait()
        port = portcmd.stdout.read()
        tf.seek(0)
        stderr = tf.read()
      if port and int(port) != 0:
        self._gomacc_port = str(int(port))
        return self._gomacc_port
      if proc and not self._is_daemon_mode:
        proc.poll()
        if proc.returncode is not None:
          raise Error('compiler_proxy is not running %d' % proc.returncode)
    if port_error:
      print(port_error)
    if stderr:
      sys.stderr.write(stderr.decode('utf-8'))
    e = Error('compiler_proxy is not ready?')
    self._GetDetailedFailureReason()
    if proc:
      e = Error('compiler_proxy is not ready? pid=%d' % proc.pid)
      if proc.returncode is not None:
        e = Error('compiler_proxy is not running %d' % proc.returncode)
      proc.kill()
    else:
      # A running compiler_proxy is not responding, don't try to interact with
      # it in upcoming _GetCompilerProxyPort() calls.
      self._gomacc_port = _PORT_UNAVAILABLE
    raise e

  def ControlCompilerProxy(self, command, check_running=True, need_pids=False):
    """Send comamnd to compiler proxy.

    Args:
      command: a string of command to send to the compiler proxy.
      check_running: True if it needs to check compiler_proxy is running
        if not running, returns {'status': False, ...}.
        False it waits for compiler_proxy running.
      need_pids: True if it needs stakeholder pids.

    Returns:
      Dict of boolean status, message string, url prefix, and pids.
      if need_pids is True, pid field will be stakeholder's pids if
      compiler_proxy is available.  Otherwise, pid='unknown'.
    """
    self.CheckConfig()
    pids = 'unknown'
    if check_running and not self.CompilerProxyRunning():
      return {'status': False, 'message': 'goma is not running.', 'url': '',
              'pid': pids}
    url_prefix = 'http://127.0.0.1:0'
    try:
      url_prefix = 'http://127.0.0.1:%s' % self._GetCompilerProxyPort()
      url = '%s%s' % (url_prefix, command)
      # When a user set HTTP proxy environment variables (e.g. http_proxy),
      # urllib.urlopen uses them even for communicating with compiler_proxy
      # running in 127.0.0.1, and trying to make the proxy connect to
      # 127.0.0.1 (i.e. the proxy itself), which should not work.
      # We should make urllib.urlopen ignore the proxy environment variables.
      no_proxy_env = os.environ.get('no_proxy')
      os.environ['no_proxy'] = '*'
      try:
        resp = urllib.request.urlopen(url)
        reply = _DecodeBytes(resp.read())
      finally:
        if no_proxy_env is None:
          del os.environ['no_proxy']
        else:
          os.environ['no_proxy'] = no_proxy_env

      if need_pids:
        pids = ','.join(self._GetStakeholderPids())
      return {'status': True, 'message': reply, 'url': url_prefix, 'pid': pids}
    except (Error, OSError) as ex:
      # urllib.urlopen(url) may raise socket.error, such as [Errno 10054]
      # An existing connection was forcibly closed by the remote host.
      # note: socket.error changed to an alias of OSError in python 3.3.
      #
      # for http error, such as 400 Not Found,
      # urllib.urlopen(url) raises HTTPError, which is subclass
      # of URLError, which is subclass of OSError.
      msg = repr(ex)
    return {'status': False, 'message': msg, 'url': url_prefix, 'pid': pids}

  def HttpDownload(self, source_url):
    """Download data from the given URL to the file.

    If self._goma_fetch defined, prefer goma_fetch to urllib2.

    Args:
      source_url: URL to retrieve data.

    Returns:
      None if provided destination_file, downloaded contents otherwise.

    Raises:
      Error if fetch failed.
    """
    if self._goma_fetch:
      # for proxy, goma_fetch uses $GOMA_PROXY_HOST, $GOMA_PROXY_PORT.
      # headers is used to set Authorization header, but goma_fetch will
      # set appropriate authorization headers from goma env flags.
      # increate timeout.
      env = os.environ.copy()
      env['GOMA_HTTP_SOCKET_READ_TIMEOUT_SECS'] = '300.0'
      return PopenWithCheck([self._goma_fetch, '--auth', source_url],
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            env=env).communicate()[0]

    if sys.hexversion < 0x2070900:
      raise Error('Please use python version >= 2.7.9')

    http_req = urllib.request.Request(source_url)
    r = urllib.request.urlopen(http_req)
    return r.read()

  def GetGomaTmpDir(self):
    """Get a directory path for goma.

    Returns:
      a directory name.
    """
    if self._goma_tmp_dir:
      return self._goma_tmp_dir

    if not os.path.exists(self._gomacc_binary):
      # When installing goma from `goma_ctl.py update`, gomacc does not exist.
      # In such case, we need to get tempdir from other than gomacc.

      # TODO: Use tmpfile.TemporaryDirectory in python3
      self._goma_tmp_dir = tempfile.mkdtemp()
      self._delete_tmp_dir = True
      return self._goma_tmp_dir

    env = os.environ.copy()
    env['GLOG_logtostderr'] = 'true'
    self._goma_tmp_dir = _CheckOutput([self._gomacc_binary, 'tmp_dir'],
                          env=env).rstrip()
    return self._goma_tmp_dir

  def GetCrashDumpDirectory(self):
    """Get a directory path that may contain crash dump.

    Returns:
      a directory name.
    """
    return os.path.join(self.GetGomaTmpDir(), _CRASH_DUMP_DIR)

  def GetCacheDirectory(self):
    """Get a directory path that may contain cache.

    Returns:
      a directory name.
    """
    cache_dir = os.environ.get('GOMA_CACHE_DIR')
    if cache_dir:
      return cache_dir

    return os.path.join(self.GetGomaTmpDir(), _CACHE_DIR)

  def GetCrashDumps(self):
    """Get file names of crash dumps.

    Returns:
      a list of full qualified crash dump file names.
      If no crash dump, empty list is returned.
    """
    crash_dir = self.GetCrashDumpDirectory()
    return glob.glob(os.path.join(crash_dir, '*' + _DUMP_FILE_SUFFIX))

  @staticmethod
  def FindLatestLogFile(command_name, log_type):
    """Finds latest *.|log_type|.* file.

    Args:
      command_name: command name of *.|log_type|.* file. e.g. compiler_proxy.

    Returns:
      The latest *.|log_type|.* file path. None if not found.
    """

    info_pattern = os.path.join(_GetLogDirectory(),
                                '%s.*.%s.*' % (command_name, log_type))
    candidates = glob.glob(info_pattern)
    if candidates:
      return sorted(candidates, reverse=True)[0]
    return None

  @classmethod
  def _GetCompressedLatestLog(cls, command_name, log_type):
    """Returns compressed log file if exist.

    Args:
      command_name: command name of *.|log_type|.* file. e.g. compiler_proxy.

    Returns:
      compressed *.|log_type|.* file name.
      Note: caller should remove the file by themselves.
    """
    logfile = cls.FindLatestLogFile(command_name, log_type)
    if not logfile:
      return None

    tf = tempfile.NamedTemporaryFile(delete=False)
    with tf as f_out:
      with gzip.GzipFile(fileobj=f_out) as gzipf_out:
        with open(logfile) as f_in:
          shutil.copyfileobj(f_in, gzipf_out)
    return tf.name

  @staticmethod
  def _BuildFormData(form, boundary, out_fh):
    """Build multipart/form-data from given input.

    Since we cannot always expect existent of requests module,
    we need to have the way to build form data by ourselves.
    Please see also:
    https://tools.ietf.org/html/rfc2046#section-5.1.1

    Args:
      form: a list of list or tuple that represents form input.
            first element of each tuple or list would be treated as a name
            of a form data.
            If a value starts from '@', it is treated as a file like curl.
            e.g. [['prod', 'goma'], ['ver', '160']]
      bondary: a string to represent what value should be used as a boundary.
      out_fh: file handle to output.  Note that you can use BytesIO.
    """
    out_fh.write(('--%s\r\n' % boundary).encode())
    if isinstance(form, dict):
      form = form.items()
    for i, item in enumerate(form):
      name, value = item
      filename = None
      content_type = None
      content = value.encode()
      if isinstance(value, str) and value.startswith('@'):  # means file.
        filename = value[1:]
        content_type = 'application/octet-stream'
        with open(filename, 'rb') as f:
          content = f.read()
      if filename:
        out_fh.write(('content-disposition: form-data; '
                      'name="%s"; '
                      'filename="%s"\r\n' % (name, filename)).encode())
      else:
        out_fh.write(
            ('content-disposition: form-data; name="%s"\r\n' % name).encode())
      if content_type:
        out_fh.write(('content-type: %s\r\n' % content_type).encode())
      out_fh.write(b'\r\n')
      out_fh.write(content)
      if i == len(form) - 1:
        out_fh.write(('\r\n--%s--\r\n' % boundary).encode())
      else:
        out_fh.write(('\r\n--%s\r\n' % boundary).encode())

  def UploadCrashDump(self, destination_url, product, version, dump_file,
                      guid=None):
    """Upload crash dump.

    Args:
      destination_url: URL to post data.
      product: a product name string.
      version: a version number string.
      dump_file: a dump file name.
      guid: a unique identifier for this client.

    Returns:
      any messages returned by a server.
    """
    form = {
        'prod': product,
        'ver': version,
        'upload_file_minidump': '@%s' % dump_file,
    }

    dump_size = -1
    try:
      dump_size = os.path.getsize(dump_file)
      sys.stderr.write('Crash dump size: %d\n' % dump_size)
      form['comments'] = 'dump_size:%x' % dump_size
    except OSError:
      pass

    if guid:
      form['guid'] = guid

    cp_logfile = None
    subproc_logfile = None
    form_body_file = None
    try:
      # Since we test goma client with ASan, if we see a goma client crash,
      # it is usually a crash caused by abort.
      # In such a case, ERROR logs should be left.
      # Also, INFO logs are huge, let us avoid to upload them.
      cp_logfile = self._GetCompressedLatestLog(
          'compiler_proxy', 'ERROR')
      subproc_logfile = self._GetCompressedLatestLog(
          'compiler_proxy-subproc', 'ERROR')
      if cp_logfile:
        form['compiler_proxy_logfile'] = '@%s' % cp_logfile
      if subproc_logfile:
        form['subproc_logfile'] = '@%s' % subproc_logfile

      boundary = ''.join(
          random.choice(string.ascii_letters + string.digits)
          for _ in range(32))
      if self._goma_fetch:
        tf = None
        try:
          tf = tempfile.NamedTemporaryFile(delete=False)
          with tf as f:
            self._BuildFormData(form, boundary, f)
          return _CheckOutput(
              [self._goma_fetch,
               '--noauth',
               '--content_type',
               'multipart/form-data; boundary=%s' % boundary,
               '--data_file', tf.name,
               '--post', destination_url])
        finally:
          if tf:
            os.remove(tf.name)

      if sys.hexversion < 0x2070900:
        raise Error('Please use python version >= 2.7.9')

      body = io.BytesIO()
      self._BuildFormData(form, boundary, body)

      headers = {
          'content-type': 'multipart/form-data; boundary=%s' % boundary,
      }
      http_req = urllib.request.Request(
          destination_url, data=body.getvalue(), headers=headers)
      r = urllib.request.urlopen(http_req)
      out = r.read()
    finally:
      if cp_logfile:
        os.remove(cp_logfile)
      if subproc_logfile:
        os.remove(subproc_logfile)
      if form_body_file:
        os.remove(form_body_file)
    return out

  def WriteFile(self, filename, content):
    with open(filename, 'w') as f:
      f.write(content)

  def CopyFile(self, from_file, to_file):
    shutil.copy(from_file, to_file)

  def MakeTgzFromDirectory(self, dir_name, output_filename):
    with tarfile.open(output_filename, 'w:gz') as tf:
      tf.add(dir_name)

  def RemoveFile(self, filename):
    filename = os.path.join(self._dir, filename)
    os.remove(filename)

  def MakeDirectory(self, directory):
    directory = os.path.join(self._dir, directory)
    os.mkdir(directory, 0o700)
    if not os.path.exists(directory):
      raise Error('Unable to create directory: %s.' % directory)

  def IsDirectoryExist(self, directory):
    directory = os.path.join(self._dir, directory)
    # To avoid symlink attack, the directory should not be symlink.
    return os.path.isdir(directory) and not os.path.islink(directory)

  def IsOldFile(self, filename):
    log_clean_interval = int(os.environ.get('GOMA_LOG_CLEAN_INTERVAL', '-1'))
    if log_clean_interval < 0:
      return False
    return os.path.getmtime(filename) < self._time - log_clean_interval

  def _SetupEnviron(self):
    """Sets default environment variables if they are not configured."""
    os.environ['GLOG_logfile_mode'] = str(0o600)
    for flag_name, default_value in _DEFAULT_ENV:
      _SetGomaFlagDefaultValueIfEmpty(flag_name, default_value)
    for flag_name, default_value in self._DEFAULT_ENV:
      _SetGomaFlagDefaultValueIfEmpty(flag_name, default_value)

    if not _IsFlagTrue('GOMA_USE_SSL'):
      for flag_name, default_value in _DEFAULT_NO_SSL_ENV:
        _SetGomaFlagDefaultValueIfEmpty(flag_name, default_value)

    if _IsFlagTrue('GOMA_USE_SSL'):
      for flag_name, default_value in self._DEFAULT_SSL_ENV:
        _SetGomaFlagDefaultValueIfEmpty(flag_name, default_value)

  def _GenerateHttpProxyCommand(self):
    """Generate a command line to execute http_proxy."""
    cmd = [self._http_proxy_binary]
    # TODO: fix http_proxy behavior.
    host, _ = self.server_host.split(':', 1)
    if host:
      cmd += ['--server-host', host]
    if self._http_proxy_port:
      cmd += ['--port', self._http_proxy_port]
    return cmd

  def ExecHttpProxy(self, logfile):
    """Execute http proxy in platform dependent way.

    Args:
      logfile: a file descriptor to write logs.

    Returns:
      An instance of PopenWithCheck that runs http_proxy.
    """
    cmd = self._GenerateHttpProxyCommand()
    logfile.write('%s\n' % ' '.join(cmd))
    return self._CreateDetachedProcess(
        cmd, stdout=logfile, stderr=subprocess.STDOUT)

  def ExecCompilerProxy(self):
    """Execute compiler proxy in platform dependent way."""
    self._gomacc_port = None  # invalidate gomacc_port cache.
    proc = self._ExecCompilerProxy()
    return self._GetCompilerProxyPort(proc=proc)  # set the new gomacc_port.

  def IsProductionBinary(self):
    """Returns True if compiler_proxy is release version.

    Since all of our release binaries are compiled by chrome-bot,
    we can assume that any binaries compiled by chrome bot would be
    release or release candidate.

    Returns:
      True if compiler_proxy is built by chrome-bot.
      Otherwise, False.
    """
    info = PopenWithCheck([self._compiler_proxy_binary, '--build-info'],
                          stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT).communicate()[0].rstrip()
    return 'built by chrome-bot' in info

  def LoadChecksum(self):
    """Returns a dictionary of checksum.

    For backward compatibility, it returns an empty dictionary if a JSON
    file does not exist.

    Returns:
      a dictionary of filename and checksum.
      e.g. {'compiler_proxy': 'abcdef...', ...}
    """
    json_file = os.path.join(self._dir, _CHECKSUM_FILE)
    if not os.path.exists(json_file):
      print('%s not exist' % json_file)
      return {}

    with open(json_file) as f:
      return json.load(f)

  def CalculateChecksum(self, filename):
    """Returns checksum of a file.

    Args:
      filename: a string filename under script dir.

    Returns:
      a checksum of a file.
    """
    return _CalculateChecksum(os.path.join(self._dir, filename))

  # methods need to be implemented in subclasses.
  def _ProcessRunning(self, image_name):
    """Test if any process with image_name is running.

    Args:
      image_name: executable image file name

    Returns:
      boolean value indicating the result.
    """
    raise NotImplementedError('_ProcessRunning should be implemented.')

  def _CheckPlatformConfig(self):
    """Checks platform dependent GomaEnv configurations."""

  def _CreateDetachedProcess(self, cmd, **kwargs):
    """Execute a program in a detached way.

    Args:
      cmd: a list of string to be executed with detached.
      kwargs: kwargs used by PopenWithCheck.

    Returns:
      An instance of PopenWithCheck that runs http_proxy.
    """
    raise NotImplementedError('_CreateDetachedProcess should be implemented.')

  def _ExecCompilerProxy(self):
    """Execute compiler proxy in platform dependent way."""
    raise NotImplementedError('_ExecCompilerProxy should be implemented.')

  def _GetDetailedFailureReason(self, proc=None):
    """Gets detailed failure reason if possible."""

  def GetGomaCtlScriptName(self):
    """Get the name of goma_ctl script to be executed by command line."""
    # Subclass may uses its specific variable.
    # pylint: disable=R0201
    return os.environ.get('GOMA_CTL_SCRIPT_NAME',
                          os.path.basename(os.path.realpath(__file__)))

  @staticmethod
  def GetPackageExtension(platform):
    raise NotImplementedError('GetPackageExtension should be implemented.')

  def CompilerProxyRunning(self):
    """Returns True if compiler proxy running.

    Returns:
      True if compiler_proxy is running.  Otherwise, False.
    """
    raise NotImplementedError('CompilerProxyRunning should be implemented.')

  def KillStakeholders(self, force=False):
    """Kills stake holder processes.

    Args:
      force: kills forcefully.

    This will kill all processes having locks compiler_proxy needs.
    """
    raise NotImplementedError('KillStakeholders should be implemented.')

  def WarnNonProtectedFile(self, filename):
    """Warn if access to the file is not limited.

    Args:
      filename: filename to check.
    """
    raise NotImplementedError('WarnNonProtectedFile should be implemented.')

  def EnsureDirectoryOwnedByUser(self, directory):
    """Ensure the directory is owned by the user.

    Args:
      directory: a name of a directory to be checked.

    Returns:
      True if the directory is owned by the user.
    """
    raise NotImplementedError(
        'EnsureDirectoryOwnedByUser should be implemented.')

  def _WaitWithTimeout(self, proc, timeout_sec):
    """Wait proc finish until timeout_sec.

    Args:
      proc: an instance of subprocess.Popen
      timeout_sec: an integer number to represent timeout in sec.
    """
    raise NotImplementedError

  def GetUsername(self):
    user = _GetUsernameEnv()
    if user:
      return user
    user = self._GetUsernameNoEnv()
    if user:
      os.environ['USER'] = user
      return user
    return 'unknown'

  def _GetUsernameNoEnv(self):
    """OS specific way of getting username without environment variables.

    Returns:
      a string of an user name if available.  If not, empty string.
    """
    raise NotImplementedError

  def _GetServerHost(self):
    """Returns server host used by compiler_proxy."""
    try:
      return PopenWithCheck(
          [self._compiler_proxy_binary, '--print-server-host'],
          stdout=subprocess.PIPE,
          stderr=subprocess.STDOUT).communicate()[0].rstrip()
    except (CalledProcessError, subprocess.CalledProcessError):
      return 'unknown'

  def _GetStakeholderPids(self):
    """Return PIDs that owns Goma related ports and files.

    Returns:
      a list of PIDs in string that owns Goma related ports and files.
    """
    raise NotImplementedError

  def UpdateEnvForHttpProxy(self):
    self._server_host = self._GetServerHost()
    self._http_proxy_port = os.environ.get('GOMACTL_PROXY_PORT',
                                           _DEFAULT_PROXY_PORT)
    _OverrideEnvVar('GOMA_SERVER_HOST', '127.0.0.1')
    _OverrideEnvVar('GOMA_SERVER_PORT', self._http_proxy_port)
    _OverrideEnvVar('GOMA_USE_SSL', 'false')

  @property
  def server_host(self):
    if self._server_host is None:
      self._server_host = self._GetServerHost()
    ret = self._server_host
    if os.environ.get('GOMA_RPC_EXTRA_PARAMS'):
      ret += ' extra_params:%s' % os.environ['GOMA_RPC_EXTRA_PARAMS']
    if self.use_http_proxy:
      ret += ' (via http_proxy)'
    return ret

  @property
  def use_http_proxy(self):
    if self._use_http_proxy is None:
      self._use_http_proxy = _IsFlagTrue('GOMACTL_USE_PROXY', True)
    return self._use_http_proxy


class GomaEnvWin(GomaEnv):
  """Goma running environment for Windows."""

  _GOMACC = 'gomacc.exe'
  _COMPILER_PROXY = 'compiler_proxy.exe'
  _GOMA_FETCH = 'goma_fetch.exe'
  _HTTP_PROXY = 'http_proxy.exe'
  # TODO: could be in GomaEnv if env name is the same between
  # posix and win.
  _COMPILER_PROXY_IDENTIFIER_ENV_NAME = 'GOMA_COMPILER_PROXY_SOCKET_NAME'
  _DEFAULT_ENV = [
      ('COMPILER_PROXY_SOCKET_NAME', 'goma.ipc'),
      ]
  _DEFAULT_SSL_ENV = [
      # Longer read timeout seems to be required on Windows.
      ('HTTP_SOCKET_READ_TIMEOUT_SECS', '90.0'),
      ]
  _GOMA_CTL_SCRIPT_NAME = 'goma_ctl.bat'
  _DEPOT_TOOLS_DIR_PATTERN = re.compile(r'.*[/\\]depot_tools[/\\]?$')

  def __init__(self):
    GomaEnv.__init__(self)
    self._platform = 'win64'

  @staticmethod
  def GetPackageExtension(platform):
    return 'zip'

  def _GetProcessImagePid(self, image_name):
    """Returns process ID of the image."""
    process = PopenWithCheck(
        ['tasklist', '/FO', 'csv', '/FI',
         'IMAGENAME eq %s' % image_name],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        encoding='oem')
    output = process.communicate()[0]
    if image_name not in output:
      return []
    pids = []
    for entry in csv.DictReader(output.splitlines(), quoting=csv.QUOTE_ALL):
      try:
        pids.append(entry['PID'])
      except KeyError:
        raise Exception('strange output: %s' % output) from None
    return pids

  def _ProcessRunning(self, image_name):
    return bool(self._GetProcessImagePid(image_name))

  def _CheckPlatformConfig(self):
    """Checks platform dependent GomaEnv configurations."""
    if not os.path.isfile(os.path.join(self._dir, 'vcflags.exe')):
      raise ConfigError('vcflags.exe not found')

  def _CreateDetachedProcess(self, cmd, **kwargs):
    # https://docs.microsoft.com/en-us/windows/win32/procthread/process-creation-flags
    DETACHED_PROCESS = 8
    return PopenWithCheck(cmd, creationflags=DETACHED_PROCESS, **kwargs)

  def _ExecCompilerProxy(self):
    return self._CreateDetachedProcess([self._compiler_proxy_binary])

  def _GetDetailedFailureReason(self, proc=None):
    pids = self._GetStakeholderPids()
    print('ports are owned by following processes:')
    for pid in pids:
      print(
          PopenWithCheck(
              ['tasklist', '/FI', 'PID eq %s' % pid],
              stdout=subprocess.PIPE,
              stderr=subprocess.STDOUT,
              encoding='oem').communicate()[0])

  def GetGomaCtlScriptName(self):
    return os.environ.get('GOMA_CTL_SCRIPT_NAME', self._GOMA_CTL_SCRIPT_NAME)

  def CompilerProxyRunning(self):
    return self._ProcessRunning(self._COMPILER_PROXY)

  def _GetStakeholderPids(self):
    # List processes with compiler_proxy name.
    pids = set(self._GetProcessImagePid(self._COMPILER_PROXY))
    # List processes listening the TCP port.
    ports = []
    ports.append(os.environ.get('GOMA_COMPILER_PROXY_PORT', '8088'))
    ns = PopenWithCheck(['netstat', '-a', '-n', '-o'],
                        stdout=subprocess.PIPE,
                        stderr=subprocess.STDOUT,
                        encoding='oem').communicate()[0]
    listenline = re.compile('.*TCP.*(?:%s).*LISTENING *([0-9]*).*' %
                            '|'.join(ports))
    for line in ns.splitlines():
      m = listenline.match(line)
      if m:
        pids.add(m.group(1))
    return pids

  def KillStakeholders(self, force=False):
    pids = self._GetStakeholderPids()
    if pids:
      args = []
      if force:
        args.append('/F')
      for pid in pids:
        args.extend(['/PID', pid])
      try:
        subprocess.check_call(['taskkill'] + args)
      except subprocess.CalledProcessError as e:
        print('Failed to execute taskkill: %s' % e)

  def WarnNonProtectedFile(self, filename):
    # TODO: warn for Win.
    pass

  def EnsureDirectoryOwnedByUser(self, directory):
    # TODO: implement for Win.
    return True

  def _WaitWithTimeout(self, proc, timeout_sec):
    # https://docs.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights
    PROCESS_QUERY_INFORMATION = 0x400
    SYNCHRONIZE = 0x100000
    # https://docs.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
    WAIT_TIMEOUT = 0x102
    WAIT_OBJECT_0 = 0
    try:
      handle = ctypes.windll.kernel32.OpenProcess(
          PROCESS_QUERY_INFORMATION | SYNCHRONIZE, False, proc.pid)
      ret = ctypes.windll.kernel32.WaitForSingleObject(handle,
                                                       timeout_sec * 10**3)
      if ret in (WAIT_TIMEOUT, WAIT_OBJECT_0):
        return
      raise Error('WaitForSingleObject returned expected value %s' % ret)
    finally:
      if handle:
        ctypes.windll.kernel32.CloseHandle(handle)

  def _GetUsernameNoEnv(self):
    GetUserNameEx = ctypes.windll.secur32.GetUserNameExW
    # https://docs.microsoft.com/en-us/windows/win32/api/secext/ne-secext-extended_name_format
    NameSamCompatible = 2

    size = ctypes.pointer(ctypes.c_ulong(0))
    GetUserNameEx(NameSamCompatible, None, size)

    name_buffer = ctypes.create_unicode_buffer(size.contents.value)
    GetUserNameEx(NameSamCompatible, name_buffer, size)
    return name_buffer.value


class GomaEnvPosix(GomaEnv):
  """Goma running environment for POSIX."""

  _GOMACC = 'gomacc'
  _COMPILER_PROXY = 'compiler_proxy'
  _GOMA_FETCH = 'goma_fetch'
  _HTTP_PROXY = 'http_proxy'
  _COMPILER_PROXY_IDENTIFIER_ENV_NAME = 'GOMA_COMPILER_PROXY_SOCKET_NAME'
  _DEFAULT_ENV = [
      # goma_ctl.py runs compiler_proxy in daemon mode by default.
      ('COMPILER_PROXY_DAEMON_MODE', 'true'),
      ('COMPILER_PROXY_SOCKET_NAME', 'goma.ipc'),
      ('COMPILER_PROXY_LOCK_FILENAME', 'goma_compiler_proxy.lock'),
      ('COMPILER_PROXY_PORT', '8088'),
      ]
  _LSOF = 'lsof'
  _FUSER = 'fuser'
  _FUSER_PID_PATTERN = re.compile(r'(\d+)')
  _FUSER_USERNAME_PATTERN = re.compile(r'\((\w+)\)')

  def __init__(self):
    GomaEnv.__init__(self)
    # pylint: disable=E1101
    # Configure from sysname in uname.
    if os.uname()[0] == 'Darwin':
      self._platform = 'mac'
    self._fuser_path = None
    self._lsof_path = None
    self._pwd = __import__('pwd')

  @staticmethod
  def GetPackageExtension(platform):
    return 'tgz' if platform == 'mac' else 'txz'

  def _ProcessRunning(self, image_name):
    process = PopenWithCheck(['ps', '-Af'], stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE)
    output = process.communicate()[0]
    return image_name in output

  def _CreateDetachedProcess(self, cmd, **kwargs):
    # Connect stdin/out/err to /dev/null if not specified by the caller
    # so that the process stops using the current tty.
    kwargs.setdefault('stdin', subprocess.DEVNULL)
    kwargs.setdefault('stdout', subprocess.DEVNULL)
    kwargs.setdefault('stderr', subprocess.DEVNULL)
    return PopenWithCheck(cmd, start_new_session=True, **kwargs)

  def _ExecCompilerProxy(self):
    if _IsFlagTrue('GOMA_COMPILER_PROXY_DAEMON_MODE'):
      self._is_daemon_mode = True
    return self._CreateDetachedProcess([self._compiler_proxy_binary],
                                       stdout=open(os.devnull, "w"),
                                       stderr=subprocess.STDOUT)

  def _ExecLsof(self, cmd):
    if self._lsof_path is None:
      self._lsof_path = _FindCommandInPath(self._LSOF)
      if not self._lsof_path:
        raise Error('lsof command not found. '
                    'Please install lsof command, or put it in PATH.')
    lsof_command = [self._lsof_path, '-F', 'pun', '-P', '-n']
    if cmd['type'] == 'process':
      lsof_command.extend(['-p', cmd['name']])
    elif cmd['type'] == 'file':
      lsof_command.extend([cmd['name']])
    elif cmd['type'] == 'network':
      lsof_command.extend(['-i', cmd['name']])
    else:
      raise Error('unknown cmd type: %s' % cmd)

    # Lsof returns 1 for WARNING even if the result is good enough.
    # It also returns 1 if an owner process is not found.
    ret = Popen(lsof_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT).communicate()[0]
    if ret:
      return _ParseLsof(ret)
    return []

  def _GetOwners(self, name, network=False):
    """Get owner pid/uid of file or listen port.

    Args:
      name: name to check owner. e.g. <tmpdir>/goma.ipc or TCP:8088
      network: True if the request is for network socket.

    Returns:
      a list of dictionaries containing owner info.
    """
    # os.path.isfile is not feasible to check an unix domain socket.
    if not network and not os.path.exists(name):
      return []

    if not network and self._GetFuserPath():
      out, err = Popen([self._GetFuserPath(), '-u', name],
                       stdout=subprocess.PIPE,
                       stderr=subprocess.PIPE).communicate()
      if out:  # Found at least one owner.
        pids = self._FUSER_PID_PATTERN.findall(out)
        usernames = self._FUSER_USERNAME_PATTERN.findall(err)
        if pids and usernames:
          uids = [int(self._pwd.getpwnam(x).pw_uid) for x in usernames]
          return [{'pid': x[0], 'uid': x[1], 'resource': name}
                  for x in zip(pids, uids)]

    if network:
      return self._ExecLsof({'type': 'network', 'name': name})
    return self._ExecLsof({'type': 'file', 'name': name})

  def _GetStakeholderPids(self):
    """Get PID of stake holders.

    Returns:
      a list of pids holding compiler_proxy locks and a port.

    Raises:
      Error: if compiler_proxy's lock is onwed by others.
    """
    # os.getuid does not exist in Windows.
    # pylint: disable=E1101
    tmpdir = self.GetGomaTmpDir()
    socket_file = os.path.join(
        tmpdir, os.environ['GOMA_COMPILER_PROXY_SOCKET_NAME'])
    lock_prefix = os.path.join(
        tmpdir, os.environ['GOMA_COMPILER_PROXY_LOCK_FILENAME'])
    port = os.environ['GOMA_COMPILER_PROXY_PORT']
    lock_filename = '%s.%s' % (lock_prefix, port)

    results = []
    results.extend(self._GetOwners(socket_file))
    results.extend(self._GetOwners(lock_filename))
    results.extend(self._GetOwners('TCP:%s' % port, network=True))

    uid = os.getuid()
    if uid != 0:  # root can handle any processes.
      owned_by_others = [x for x in results if x['uid'] != uid]
      if owned_by_others:
        raise Error('compiler_proxy lock and/or socket is owned by others.'
                    ' details=%s' % owned_by_others)

    return set(str(x['pid']) for x in results)

  def KillStakeholders(self, force=False):
    pids = self._GetStakeholderPids()
    if pids:
      args = []
      if force:
        args.append('-9')
      args.extend(list(pids))
      subprocess.check_call(['kill'] + args)

  def _GetFuserPath(self):
    if self._fuser_path is None:
      self._fuser_path = _FindCommandInPath(self._FUSER)
      if not self._fuser_path:
        self._fuser_path = ''
    return self._fuser_path

  def CompilerProxyRunning(self):
    """Returns True if compiler proxy is running."""
    pids = ''
    try:
      # note: mac pgrep does not know --delimitor.
      pids = _CheckOutput(['pgrep', '-d', ',', self._COMPILER_PROXY]).strip()
    except CalledProcessError as e:
      if e.returncode == 1:
        # compiler_proxy is not running.
        return False
      # should be fatal error.
      raise e
    if not pids:
      raise Error('executed pgrep but result is not given')

    tmpdir = self.GetGomaTmpDir()
    socket_file = os.path.join(
        tmpdir, os.environ['GOMA_COMPILER_PROXY_SOCKET_NAME'])
    entries = self._ExecLsof({'type': 'process', 'name': pids})
    for entry in entries:
      if socket_file == entry['name']:
        return True
    return False

  def WarnNonProtectedFile(self, filename):
    # This is platform dependent part.
    # pylint: disable=R0201
    if os.path.exists(filename) and os.stat(filename).st_mode & 0o77:
      sys.stderr.write(
          'We recommend to limit access to the file: %(path)s\n'
          'e.g. chmod go-rwx %(path)s\n' % {'path': filename})

  def EnsureDirectoryOwnedByUser(self, directory):
    # This is platform dependent part.
    # pylint: disable=R0201
    # We must use lstat instead of stat to avoid symlink attack (b/69717657).
    st = os.lstat(directory)
    if st.st_uid != os.geteuid():
      return False
    try:
      os.chmod(directory, 0o700)
    except OSError as err:
      sys.stderr.write('chmod failure: %s\n' % err)
      return False
    return True

  def _WaitWithTimeout(self, proc, timeout_sec):

    class GomaCtlTimeoutError(Exception):
      """Raised on timeout."""

    def handle_timeout(_signum, _frame):
      raise GomaCtlTimeoutError('timed out')

    signal.signal(signal.SIGALRM, handle_timeout)
    try:
      signal.alarm(timeout_sec)
      proc.wait()
    except GomaCtlTimeoutError:
      pass
    finally:
      signal.alarm(0)
      signal.signal(signal.SIGALRM, signal.SIG_DFL)

  def _GetUsernameNoEnv(self):
    return self._pwd.getpwuid(os.getuid()).pw_name


_GOMA_ENVS = {
    # os.name, GomaEnv subclass name
    'nt': GomaEnvWin,
    'posix': GomaEnvPosix,
    }


def GetGomaDriver():
  """Returns a proper instance of GomaEnv subclass based on os.name."""
  if os.name not in _GOMA_ENVS:
    raise Error('Could not find proper GomaEnv for "%s"' % os.name)
  env = _GOMA_ENVS[os.name]()
  return GomaDriver(env)


def main():
  goma = GetGomaDriver()
  goma.Dispatch(sys.argv[1:])
  return 0


if __name__ == '__main__':
  sys.exit(main())
