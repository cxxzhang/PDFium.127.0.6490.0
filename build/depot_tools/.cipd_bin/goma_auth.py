#!/usr/bin/env python3

# Copyright 2015 The Goma Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.
"""A Script to set goma_client_oauth2_config."""

import argparse
import copy
import json
import os
import re
import string
import subprocess
import sys
import webbrowser
import random

from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from urllib.parse import parse_qs
from urllib.parse import urlencode
from urllib.parse import urlparse

SCRIPT_DIR = os.path.dirname(os.path.realpath(__file__))
GOOGLE_AUTH_URI = 'https://accounts.google.com/o/oauth2/auth'
OAUTH_SCOPES = 'https://www.googleapis.com/auth/userinfo.email'
OAUTH_TOKEN_ENDPOINT = 'https://oauth2.googleapis.com/token'
TOKEN_INFO_ENDPOINT = 'https://oauth2.googleapis.com/tokeninfo'
# TODO: drop oob flow support
OOB_CALLBACK_URN = 'urn:ietf:wg:oauth:2.0:oob'

DEFAULT_GOMA_SERVER_HOST = 'goma.chromium.org'
DEFAULT_GOMA_OAUTH2_CONFIG_FILE_NAME = '.goma_client_oauth2_config'

GOMA_PING_URL = ('https://%s/cxx-compiler-service/ping' %
                 DEFAULT_GOMA_SERVER_HOST)

OAUTH_STATE_LENGTH = 64

if os.name == 'nt':
  GOMA_FETCH = os.path.join(SCRIPT_DIR, 'goma_fetch.exe')
else:
  GOMA_FETCH = os.path.join(SCRIPT_DIR, 'goma_fetch')



def ConfirmUserAgreedToS():
  """Returns if user agreed on ToS."""
  print("""You can use Goma (distributed compiler service) if you agree on the
way we use data and the way we share data.

1. How do we use data?
a. the data used for compiling
- source code (including contents and file paths) to be compiled.
- header files (including contents and file paths) used during the compile.
- other files accessed by compilers. e.g. asan_blacklist.txt, crtbegin.o,
  profiling data for pgo.
- identifier of a compiler to use. (SHA256 hash value of a compiler, version,
  target).
- command line arguments and environment variables necessary for a compile,
  system include paths, current working directory.

b. the data used for authentication
- OAuth2 access token to use service, and email address gotten from access
  token.

Google may use data for logging and tracking (including abuse detection).
Google keeps identifier of each compile (goma client start time, goma client
id that changes when compiler_proxy starts, sequential compile id)

2. What data will be shared?

Contents in source code and header files are stored in Google servers and
shared among users who send SHA256 hash values of them.  Compile results
are shared among users who have sent the requests that bring the same
compile result.

3. How long data will be kept?

Contents in source code and header files will be kept at most 153 days
since last used.
""")

  yn = input('Do you agree to our data usage policy? (y/n) -->')
  if yn in ('Y', 'y'):
    print('You have agreed.')
    return
  sys.exit(1)


class Error(Exception):
  """Raised on Error."""


class GomaOAuth2Config(dict):
  """File-backed OAuth2 configuration."""

  def __init__(self):
    dict.__init__(self)
    self._path = self._GetLocation()

  @staticmethod
  def _GetLocation():
    """Returns Goma OAuth2 config file path."""
    env_name = 'GOMA_OAUTH2_CONFIG_FILE'
    env = os.environ.get(env_name)
    if env:
      return env
    homedir = os.path.expanduser('~')
    if homedir == '~':
      raise Error('Cannot find user\'s home directory.')
    return os.path.join(homedir, DEFAULT_GOMA_OAUTH2_CONFIG_FILE_NAME)

  def Load(self):
    """Loads config from a file."""
    if not os.path.exists(self._path):
      return False
    try:
      with open(self._path) as f:
        self.update(json.load(f))
    except ValueError:
      return False
    if not self.get('refresh_token'):
      return False
    return True

  def Save(self):
    """Saves config to a file."""
    # TODO: not save unnecessary data.
    with open(self._path, 'w') as f:
      if os.name == 'posix':
        os.fchmod(f.fileno(), 0o600)
      json.dump(self, f)

  def Delete(self):
    """Deletes a config file."""
    if not os.path.exists(self._path):
      return
    os.remove(self._path)


def HttpGetRequest(url):
  """Proceed an HTTP GET request, and returns an HTTP response body.

  Args:
    url: a URL string of an HTTP server.

  Returns:
    a response from the server.
  """
  cmd = [GOMA_FETCH, '--noauth', url]
  return subprocess.check_output(cmd)


def HttpPostRequest(url, post_dict):
  """Proceed an HTTP POST request, and returns an HTTP response body.

  Args:
    url: a URL string of an HTTP server.
    post_dict: a dictionary of a body to be posted.

  Returns:
    a response from the server.
  """
  body = urlencode(post_dict)
  cmd = [GOMA_FETCH, '--noauth', '--post', url, '--data', body]
  return subprocess.check_output(cmd)


def DefaultOAuth2Config():
  """Returns default OAuth2 config.

  same as oauth2.cc:DefaultOAuth2Config.
  TODO: run compiler_propxy to generate default oauth2 config?

  Returns:
    a dictionary of OAuth2 config.
  """
  return {
      'client_id': ('687418631491-r6m1c3pr0lth5atp4ie07f03ae8omefc.'
                    'apps.googleusercontent.com'),
      'client_secret': 'R7e-JO3L5sKVczuR-dKQrijF',
      'redirect_uri': OOB_CALLBACK_URN,
      'auth_uri': GOOGLE_AUTH_URI,
      'scope': OAUTH_SCOPES,
      'token_uri': OAUTH_TOKEN_ENDPOINT,
  }


class AuthorizationCodeHandler(BaseHTTPRequestHandler):
  """HTTP handler to get authorization code."""

  code = None
  state = None

  @classmethod
  def _SetCode(cls, code):
    """Internal function to set code to class variable."""
    if not code:
      raise Error('code is None')
    cls.code = code[0]

  def do_GET(self):
    """A handler to receive authorization code."""
    if self.client_address[0] not in ('127.0.0.1', '::1'):
      raise Error('should be localhost but %s' % self.client_address[0])
    form = parse_qs(urlparse(self.path).query)
    server_state = form.get('state', [''])[0]
    if server_state != self.state:
      raise Error('possibly XSRF: state from server (%s) is not %s' % (
          server_state, self.state))
    self._SetCode(form.get('code'))
    self.send_response(200, "OK")
    self.send_header('Content-type', 'text/html')
    self.end_headers()
    self.wfile.write(b'<html><head><title>Authentication Status</title></head>')
    self.wfile.write(b'<body><p>The authentication flow has completed.</p>')
    self.wfile.write(b'</body></html>')

  # pylint: disable=W0622
  def log_message(self, format, *args):
    """Do not log messages to stdout while running as command line program."""


def _RandomString(length):
  """Returns random string.

  Args:
    length: length of the string.

  Returns:
    random string.
  """
  generator = random.SystemRandom()
  return ''.join(generator.choice(string.ascii_letters + string.digits)
                 for _ in range(length))


def GetAuthorizationCodeViaBrowser(config):
  """Gets authorization code using browser.

  This way is useful for users with desktop machines.

  Args:
    config: a dictionary of config.

  Returns:
    authorization code.
  """
  print('Launching chrome browser to get OAuth2 token')

  AuthorizationCodeHandler.state = _RandomString(OAUTH_STATE_LENGTH)
  httpd = HTTPServer(('', 0), AuthorizationCodeHandler)
  config['redirect_uri'] = 'http://localhost:%d' % httpd.server_port
  body = urlencode({
      'scope': config['scope'],
      'redirect_uri': config['redirect_uri'],
      'client_id': config['client_id'],
      'state': AuthorizationCodeHandler.state,
      'response_type': 'code'})
  google_auth_url = '%s?%s' % (config['auth_uri'], body)
  # expect to use chrome only
  # webbrowser.open would use other browsers if chrome not found,
  # but these browser may not work with Google server.
  try:
    chrome = None
    print('Launching browser...')
    try:
      chrome = webbrowser.get('google-chrome')
    except webbrowser.Error:
      try:
        chrome = webbrowser.get('chrome')
      except webbrowser.Error as ex:
        chrome_path = \
          'c:\\Program Files\\Google\\Chrome\\Application\\chrome.exe'
        if not sys.platform == 'win32' or not os.path.exists(chrome_path):
          raise ex
        chrome = webbrowser.Chrome(chrome_path)
    chrome.open(google_auth_url)
  except webbrowser.Error as ex:
    print('ERROR: chrome not found: %s' % ex)

  print('If browser is not launched correctly,')
  print('Setup ssh portforwarding `-L %d:localhost:%d`' %
        (httpd.server_port, httpd.server_port))
  print('from machine that browser is available,')
  print('')
  print('If you already login with ssh from such machine,')
  print('1. enter `~C` to open ssh command line')
  print('2. set the following command line to `ssh>` prompt')
  print('-L %d:localhost:%d' % (httpd.server_port, httpd.server_port))
  print('')
  print('3. Browse the following URLs.')
  print(google_auth_url)
  print('')

  httpd.handle_request()
  httpd.server_close()
  print('If you set up port forwarding, you can cancel it now')
  print('1. enter `~C` to open ssh command line')
  print('2. set the following command line to `ssh>` prompt')
  print('-KL %d' % httpd.server_port)
  print('')
  return AuthorizationCodeHandler.code


def GetAuthorizationCodeViaCommandLine(config):
  """Gets authorization code via command line.

  This way is useful anywhere without a browser.

  Args:
    config: a dictionary of config.

  Returns:
    authorization code.
  """
  body = urlencode({
      'scope': config['scope'],
      'redirect_uri': config['redirect_uri'],
      'client_id': config['client_id'],
      'response_type': 'code'})
  google_auth_url = '%s?%s' % (config['auth_uri'], body)
  print('Please visit following URL with your browser, and approve access:')
  print(google_auth_url)
  return input('Please input the code:')


def GetRefreshToken(get_code_func, config):
  """Get refresh token with oauth 3 legged authentication.

  Args:
    get_code_func: a function for getting authorization code.
    config: a dictionary of config.

  Returns:
    a refresh token string.
  """
  code = get_code_func(config)
  assert code and isinstance(code, str)
  post_data = {
      'code': code,
      'client_id': config['client_id'],
      'client_secret': config['client_secret'],
      'redirect_uri': config['redirect_uri'],
      'grant_type': 'authorization_code'
  }
  resp = json.loads(HttpPostRequest(config['token_uri'], post_data))
  return resp['refresh_token']


def FetchTokenInfo(config):
  """Fetch token info from refresh token in config.

  Returns:
     token_info for refresh token in config.
  """
  post_data = {
      'client_id': config['client_id'],
      'client_secret': config['client_secret'],
      'refresh_token': config['refresh_token'],
      'grant_type': 'refresh_token'
  }
  resp = json.loads(HttpPostRequest(config['token_uri'], post_data))
  if 'error' in resp:
    return {'error_description': 'obtain access token: %s' % resp['error']}
  token_info = json.loads(HttpGetRequest(
    TOKEN_INFO_ENDPOINT + '?access_token=' + resp['access_token']))
  return token_info


def VerifyRefreshToken(config):
  """Verify refresh token in config.

  Returns:
     '' if a refresh token in config is valid.
     error message if something wrong.
  """
  if not 'refresh_token' in config:
    return 'no refresh token in config'
  token_info = FetchTokenInfo(config)
  if 'error_description' in token_info:
    return 'token info: %s' % token_info['error_description']
  if not 'email' in token_info:
    return 'no email in token_info %s' % token_info
  print('Login as ' + token_info['email'])
  return ''


def CheckPing(ping_url):
  """Check ping with current login user.

  Returns:
    true if ping success.
  """
  cmd = [GOMA_FETCH, '--auth', ping_url]
  try:
    subprocess.check_output(cmd, stderr=subprocess.STDOUT)  # discard outputs.
    return True
  except subprocess.CalledProcessError:
    pass  # expected if ping fails.
  return False


def CheckBackendAccess():
  """Check the current login user can access backend.

  Returns:
    true if the user can access.
  """
  server = os.environ.get('GOMA_SERVER_HOST', DEFAULT_GOMA_SERVER_HOST)
  port = os.environ.get('GOMA_SERVER_PORT', '443')
  use_ssl = re.match('[tTyY1]', os.environ.get('GOMA_USE_SSL', 'True'))
  scheme = 'https' if use_ssl else 'http'
  server_url = '%s://%s' % (scheme, server)
  need_port = (use_ssl and port != '443') or (not use_ssl and port != '80')
  if need_port:
    server_url = '%s:%s' % (server_url, port)

  # e.g. url='https://goma.chromium.org/cxx-compiler-service/ping'
  path_prefix = os.environ.get('GOMA_URL_PATH_PREFIX', '/cxx-compiler-service')
  rpc_extra_params = os.environ.get('GOMA_RPC_EXTRA_PARAMS', '')
  url = '%s%s/ping%s' % (server_url, path_prefix, rpc_extra_params)

  if CheckPing(url):
    print('Ready to use Goma service at %s' % server_url)
    return True

  print(('Current user is not registered with Goma service at %s with ' +
         'GOMA_RPC_EXTRA_PARAMS="%s". ' + 'Unable to use Goma.') %
        (server_url, rpc_extra_params))
  return False


def Login():
  """Performs interactive login and caches authentication token.

  Returns:
    non-zero value on error.
  """
  ConfirmUserAgreedToS()

  parser = argparse.ArgumentParser()
  parser.add_argument(
      '--no-browser',
      dest='browser',
      default=True,
      action='store_false',
      help='Deprecated; no-op.')
  options = parser.parse_args(sys.argv[2:])

  config = GomaOAuth2Config()
  config.update(DefaultOAuth2Config())
  func = GetAuthorizationCodeViaCommandLine
  if options.browser:
    func = GetAuthorizationCodeViaBrowser
  else:
    sys.stderr.write(
        'ERROR: The "--no-browser" flag is deprecated.\n\n'
        'It uses the deprecated out-of-band (OOB) auth flow, which stopped'
        ' working on 2022-10-03.\n\n'
        'If you need to "goma_auth login" over SSH, run without "--no-browser".'
        ' The tool prints instructions how to authenticate.')
    return 1

  config['refresh_token'] = GetRefreshToken(func, config)

  err = VerifyRefreshToken(config)
  if err:
    sys.stderr.write(err + '\n')
    return 1

  config.Save()
  flags = ConfigFlags(config)
  for k in flags:
    if k not in os.environ:
      os.environ[k] = flags[k]
  if not CheckBackendAccess():
    return 1
  return 0


def Logout():
  """Removes a cached authentication token.

  Returns:
    non-zero value on error.
  """
  config = GomaOAuth2Config()
  config.Delete()
  return 0


def Info():
  """Shows email associated with a cached authentication token.

  Returns:
    non-zero value on error.
  """
  config = GomaOAuth2Config()
  if not config.Load():
    sys.stderr.write('Not logged in\n')
    return 1
  err = VerifyRefreshToken(config)
  if err:
    sys.stderr.write(err + '\n')
    return 1
  flags = ConfigFlags(config)
  for k in flags:
    if k not in os.environ:
      os.environ[k] = flags[k]
  if not CheckBackendAccess():
    return 1
  return 0


class FlagsValue(dict):
  """compiler_proxy flags"""

  def __init__(self):
    dict.__init__(self)
    self.comment = ''

  def enableSendInfo(self):
    self.update({
        'GOMA_PROVIDE_INFO': 'true',
        'GOMA_SEND_USER_INFO': 'true',
        'GOMA_COMPILER_PROXY_ENABLE_CRASH_DUMP': 'true'
    })

  def enableATS(self):
    self.update({
        'GOMA_ARBITRARY_TOOLCHAIN_SUPPORT': 'true',
    })


def ConfigFlags(config):
  """returns compiler_proxy flags for login account

  Args:
    config: OAuth2 config
  Returns:
    FlagsValue
  """
  flags = FlagsValue()
  if not config.Load():
    # not logged in
    raise Error('Need to login.  Run `goma_auth login` to login.')

  token_info = FetchTokenInfo(config)
  if 'error_description' in token_info:
    raise Error(
        'Failed to fetch token info: %s' % token_info['error_description'])
  if not 'email' in token_info:
    raise Error('No email in token_info %s' % token_info)
  if token_info['email'].endswith('@google.com'):
    flags.comment = '# login as %s' % token_info['email']
    flags.enableSendInfo()
    flags.update({'GOMACTL_USE_PROXY': 'true'})
    if sys.platform in ('linux', 'linux2'):
      flags.enableATS()
    return flags
  return flags


def Config():
  """shows compiler_proxy flags for login account

  Returns:
    non-zero value on error.
  """
  config = GomaOAuth2Config()
  try:
    flags = ConfigFlags(config)
  except Error as e:
    sys.stderr.write('%s' % e)
    return 1
  print(flags.comment)
  for k in flags:
    print('%s=%s' % (k, flags.get(k)))
  return 0


def Help():
  """Print Usage"""
  print('''Usage: %(cmd)s <command> [options]

Commands are:
  login  performs interactive login and caches authentication token
  logout revokes cached authentication token
  info   shows email associated with a cached authentication token
  config shows compiler_proxy flags for login account

Options are:
  --no-browser deprecated, no-op
''' % {'cmd': sys.argv[0]})
  return 0


def main():
  action_mapping = {
      'login': Login,
      'logout': Logout,
      'info': Info,
      'config': Config,
  }
  action = Help
  if len(sys.argv) > 1:
    action = action_mapping.get(sys.argv[1], Help)
  return action()


if __name__ == '__main__':
  sys.exit(main())
