# 真实代码

这是可以直接拿来用的代码，函数签名是：

- `EXPORT BOOL load_vectoredoverload(LPCWSTR exePath)`

传入要执行的exe路径即可

文件说明：
- VEHoverloading.c：源码
- VEHoverloading.dll：编译的dll文件
- 调用示例.c：调用dll文件的示例源码
- 调用示例.exe：调用dll文件的示例exe文件

直接拿VEHoverloading.dll用即可。

# 使用方式

1.双击运行`编译dll.bat`生成dll文件

2.双击运行`编译示例.bat`生成调用实例.exe即可