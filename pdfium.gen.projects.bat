@ECHO OFF

:: 环境变量设置
CALL %~dp0pdfium.env.setup.bat


:: 设置PDFium工程生成参数
set GN_DEFINES=is_component_build=false pdf_enable_v8=false pdf_enable_xfa=false pdf_is_standalone=true pdf_use_partition_alloc=false treat_warnings_as_errors=false target_os="win" target_cpu="x86" is_debug=true

set GN_ARGUMENTS=--ide=vs2022 --sln=pdfium

:: 进入pdfium\gen目录
cd pdfium\gen

:: 工程生成
call pdf_create_projects.bat
cd %pdfium_root_dir%


:: cd src
:: gn args out\Release_GN_x86 --list --short > D:\pdfium.args.short.txt
:: gn args out\Release_GN_x86 --list > D:\pdfium.args.txt

:: 编译
:: ninja -C out\Release_GN_x86 pdfium