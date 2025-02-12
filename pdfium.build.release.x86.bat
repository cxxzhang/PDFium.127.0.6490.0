@ECHO OFF

:: 环境变量设置
CALL %~dp0pdfium.env.setup.bat

cd %~dp0pdfium

:: 编译
ninja -C out\Release_GN_x86 pdfium