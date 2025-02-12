#!/usr/bin/env python3
# Copyright 2013 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

"""This script is a wrapper around the GN binary that is pulled from Google
Cloud Storage when you sync Chrome. The binaries go into platform-specific
subdirectories in the source tree.

This script makes there be one place for forwarding to the correct platform's
binary. It will also automatically try to find the gn binary when run inside
the chrome source tree, so users can just type "gn" on the command line
(normally depot_tools is on the path)."""

from __future__ import print_function

import gclient_paths
import os
import subprocess
import sys


def main(args):
  ninja_path = gclient_paths.GetNinjaBinaryPath()
  if not ninja_path:
    print('ninja.py: Could not find ninja.exe')
    return 1
  os.chdir(gclient_paths.GetPrimarySolutionPath())
  return subprocess.call([ninja_path] + args[1:])


if __name__ == '__main__':
  try:
    sys.exit(main(sys.argv))
  except KeyboardInterrupt:
    sys.stderr.write('interrupted\n')
    sys.exit(1)
