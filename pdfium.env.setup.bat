@ECHO OFF

SET pdfium_root_dir=%~dp0
SET PATH=%pdfium_root_dir%build\depot_tools;%PATH%
SET DEPOT_TOOLS_WIN_TOOLCHAIN=0
