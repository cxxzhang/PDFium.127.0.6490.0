#!/bin/bash
# Copyright 2017 The Chromium Authors. All rights reserved.
# Use of this source code is governed by a BSD-style license that can be
# found in the LICENSE file.

# This alias allows invocations of `vpython` to work as expected under msys
# bash.  In particular, it detects if stdout+stdin are both attached to
# a pseudo-tty, and if so, invokes vpython in interactive mode. If this is not
# the case, or the user passes any arguments, vpython will be invoked
# unmodified.
vpython() {
  if [[ $# > 0 ]]; then
    vpython.bat "$@"
  else
    readlink /proc/$$/fd/0 | grep pty > /dev/null
    TTY0=$?
    readlink /proc/$$/fd/1 | grep pty > /dev/null
    TTY1=$?
    if [ $TTY0 == 0 ] && [ $TTY1 == 0 ]; then
      PYTHON_DIRECT=1 PYTHONUNBUFFERED=1 vpython.bat -i
    else
      vpython.bat
    fi
  fi
}
