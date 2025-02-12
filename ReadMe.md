# pdfium 127.0.6490.0

原始代码从[github bblanchon](https://github.com/bblanchon/pdfium-binaries/commit/8905f251148f371b1fd319aaada777f52f9ddd1a)拉取

在原始代码的基础上，做了以下改动:

1.内置了depot_tools, 可以一键生成工程，一键编译。

2.做了XP的适配,生成的二进制可以在XP下使用。

3.增加了一个接口FPDF_RenderPagePrintWidget，解决标准的接口在Form打印时，可能有缺失的问题（例如打印发票的时候，电子签章没有打印上去）。


