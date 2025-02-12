@echo off

REM Copyright 2020 Google LLC.

SET PY=vpython
WHERE %PY% >NUL 2>&1
IF %ERRORLEVEL% NEQ 0 (
    SET PY=python
    ECHO vpython not found, fallback to python. This may have some issue ^
finding the necessary modules ^(e.g. pywin32^). Consider installing ^
depot_tools to get vpython.
)

%PY% "%~dp0goma_auth.py" %*
