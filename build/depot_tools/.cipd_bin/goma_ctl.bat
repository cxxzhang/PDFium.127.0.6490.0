@echo off

REM Copyright 2012 The Goma Authors. All rights reserved.
REM Use of this source code is governed by a BSD-style license that can be
REM found in the LICENSE file.

SET PY=vpython3
WHERE %PY% >NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
    SET PY=python3
    ECHO vpython3 not found, fallback to python3. This may have some issue ^
finding the necessary modules ^(e.g. pywin32^). Consider installing ^
depot_tools to get vpython3.
)

%PY% "%~dp0goma_ctl.py" %*
