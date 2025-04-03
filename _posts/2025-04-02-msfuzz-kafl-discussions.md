---
date: 2025-04-02 10:21:56
layout: post
title: msFuzz - kAFL 一些思考
subtitle: 
description: >-
    hypervisors
image: >-
  /assets/img/uploads/cat.jpg
optimized_image: >-
  /assets/img/uploads/cat.jpg
category: hackedemic
tags:
  - kAFL
  - fuzzing
author: rosayxy
paginate: true
---


## 如何实现的 ring3 发 vmcall 指令：   
![alt text](/assets/img/uploads/5e466ee3c460e1b5c729817dbedbcd2.png)

摘自 [kAFL 论文](https://nyx-fuzz.com/papers/kafl.pdf)


## Harness 该如何处理结构体    

输入获取：Guest OS 里面的 User Agent 把 payload buffer 起始地址传给 Host OS，Host OS 在该地址建立 shared memory，进而把给 driver 发 Ioctl 的参数通过以下 Entry 数组的格式发给 Agent    
```c
struct Entry{
    uint32_t function_code = IOCTL;
    uint32_t Ioctlcode;
    uint32_t InputBufferLength;
    uint32_t OutputBufferLength;
    uint32_t inbuffer[InputBufferLength];
}entry[n];
```
然后 Agent 解析出每个 entry，把每个字段的内容当作参数 **原封不动的**发给 driver 的 Ioctl   

所以确实，目前的框架对结构体支持不太好（kAFL 原始论文，msFuzz 都没有将结构体识别作为贡献点）   


如果后续在 kAFL 上增加结构体识别的内容，**感觉在 Harness 和 Host 上做都是可以的**，因为 Host 上也能拿到 Harness 所能拿到的地址（当前的 kAFL 框架就可以拿到 Guest OS 的用户态 Agent 栈地址，并且有 shared mem），只是需要再 HyperCall 传递一步     

但是看后面，Host 的实现更加通用，所以可能更好在 Harness 上实现   

以及之前说到的 RedQueen 解析到的结构体字段信息是存在以下结构体    

```py

class RedqueenInfo:
    def __init__(self):
        self.addr_to_cmp = {}
        self.addr_to_inv_cmp = {}
        self.run_infos = set()
        self.boring_cmps = set()

```

## 变异约束   

之前组会分享提到了一个问题：虽然 kAFL 是 mutation-based fuzzer，但是它一开始 generate 初始测例肯定还是需要满足一些约束条件，比如一开始的 InputBufferLength 需要和传入 inputBuffer 的长度一致，这是怎么保证的呢？    
[this commit](https://github.com/0dayResearchLab/kafl.fuzzer/commit/5219464f4d6c9948922034fa84d9c713e4a59df3) has the answer.    
在 common/utils.py 里面有如下代码    

```py
# mark this has the adjustments
class IRP:
    '''This code from kirasys's IRPT'''
    def __init__(self, IoControlCode=0, InBuffer_length=0, OutBuffer_length=0, InBuffer=b'', Command=0):
        self.Command = Command
        self.IoControlCode = u32(IoControlCode)
        self.InBuffer_length = u32(InBuffer_length)
        self.OutBuffer_length = u32(OutBuffer_length)
        if InBuffer == b'':
            self.InBuffer = bytearray( b"\xff" * self.InBuffer_length)
        else:
            self.InBuffer = bytearray(InBuffer)
```

其中根据了 InBufferLength 初始化了 InBuffer，确保了长度的一致    

对于 msFuzz 从 angrPT 的静态部分拿到的参数，有   

```py
    def __generateIRP(self, iocode):
        inbuffer_ranges = interface_manager[iocode]["InBufferRange"]
        outbuffer_ranges = interface_manager[iocode]["OutBufferRange"]

        inlength = 0
        outlength = 0
        for rg in inbuffer_ranges:
            inlength = max(inlength, rg.stop - 1)
        for rg in outbuffer_ranges:
            outlength = max(outlength, rg.stop - 1)

        inlength = inlength if inlength != MAX_RANGE_VALUE-1 else MAX_BUFFER_LEN
        outlength = outlength if outlength != MAX_RANGE_VALUE-1 else MAX_BUFFER_LEN
        
        irp = IRP(p32(iocode), p32(inlength), p32(outlength),Command=b"IOIO")

        return irp.Command + p32(irp.IoControlCode) + p32(irp.InBuffer_length) + p32(irp.OutBuffer_length) + irp.InBuffer
    
    
    def generate(self, seed_dir):
    
        logger.info("[+] preparing seed files with irec result...")

        for iocode in interface_manager.get_all_codes():
            payload = self.__generateIRP(iocode)
            with open(seed_dir+f"/{hex(iocode)}","wb") as file:
                file.write(payload)
        import time
        time.sleep(3)
```
以下代码，从 angrPT 传入的 json 里面拿到信息，然后把 inputBuffer 初始化为 b"\xff"*InputBufferLength 然后写到 seed 里面去，从而确保了 seed 的合法性    

此外，也可以在 "{working_dir}/import/" 下手动指定 seed files    
```py
def copy_seed_files(working_directory, seed_directory):
    if len(os.listdir(seed_directory)) == 0:
        return False

    if len(os.listdir(working_directory)) == 0:
        return False

    i = 0
    for (directory, _, files) in os.walk(seed_directory):
        for f in files:
            path = os.path.join(directory, f)
            if os.path.exists(path):
                try:
                    copyfile(path, working_directory + "/imports/" + "seed_%05d" % i)
                    i += 1
                except PermissionError:
                    logger.error("Skipping seed file %s (permission denied)." % path)
    return True

```

从而保证了初始种子的合法性    

## 我们尝试用 Vagrant 跑的 box 文件和 qemu 可以起来的 windows.img 之间的关系    

![alt text](/assets/img/uploads/image-3.png)

通过 [文档](https://intellabs.github.io/kAFL/tutorials/windows/windows_template.html) 上给的 log      
```
==> vagrant-kafl-windows: Creating image (snapshot of base box volume).
==> vagrant-kafl-windows: Creating domain with the following settings...
==> vagrant-kafl-windows:  -- Name:              windows_x86_64_vagrant-kafl-windows
==> vagrant-kafl-windows:  -- Description:       Source: /home/user/kafl/kafl/examples/windows_x86_64/Vagrantfile
==> vagrant-kafl-windows:  -- Domain type:       kvm
==> vagrant-kafl-windows:  -- Cpus:              4
==> vagrant-kafl-windows:  -- Feature:           acpi
==> vagrant-kafl-windows:  -- Feature:           apic
==> vagrant-kafl-windows:  -- Feature:           pae
==> vagrant-kafl-windows:  -- Clock offset:      utc
==> vagrant-kafl-windows:  -- Memory:            4096M
==> vagrant-kafl-windows:  -- Base box:          kafl_windows
==> vagrant-kafl-windows:  -- Storage pool:      default
==> vagrant-kafl-windows:  -- Image(vda):        /home/user/.local/share/libvirt/images/windows_x86_64_vagrant-kafl-windows.img, virtio, 64G
==> vagrant-kafl-windows:  -- Disk driver opts:  cache='default'
==> vagrant-kafl-windows:  -- Graphics Type:     spice
==> vagrant-kafl-windows:  -- Graphics Websocket:
==> vagrant-kafl-windows:  -- Graphics Port:
==> vagrant-kafl-windows:  -- Graphics IP:
==> vagrant-kafl-windows:  -- Graphics Password: Not defined
==> vagrant-kafl-windows:  -- Video Type:        cirrus
==> vagrant-kafl-windows:  -- Video VRAM:        16384
==> vagrant-kafl-windows:  -- Video 3D accel:    false
==> vagrant-kafl-windows:  -- Keymap:            en-us
==> vagrant-kafl-windows:  -- TPM Backend:       passthrough
==> vagrant-kafl-windows:  -- INPUT:             type=mouse, bus=ps2
==> vagrant-kafl-windows:  -- CHANNEL:             type=spicevmc, mode=
==> vagrant-kafl-windows:  -- CHANNEL:             target_type=virtio, target_name=com.redhat.spice.0
```
可知 在 `vagrant snapshot save --force 'ready_provision' ` 一步中 save 下来了那个被 qemu 跑的 img     

问了 claude 得到类似回答（总之就是 保存下来的 snapshot 可以被 qemu 拿来当 image 跑）    

![alt text](/assets/img/uploads/image-4.png)

## 原版 kAFL - 函数签名如何确定
在 msFuzz 的 kafl-fuzzer 中，专门实现了 Irp 类，但是观察原版的 kAFL，只有 kafl.targets 不同（代表 Host OS 上的 Agent 是随 target 不同的），fuzzer 是一致的，而我们变异的时候，测例的生成全是在 fuzzer 中，也就是说，fuzzer 在 mutate 的时候，**完全不知道自己 fuzz 的接口的函数签名**    

那这是怎么保证准确度的呢？    

答案是 initial seed 和 harness 解析格式的一致性      

最重要的一个条件， kAFL 是 mutation-based fuzzer，代表一开始他的测例只有 initial seeds，是一大块数据，此时，host 通过 hypercall 把 initial seed 这一大块数据发给 Guest OS 里面的 Agent， Agent 把 seed 按照字段等规则解析为真正向接口传入的参数，调用该接口看执行到了哪些地方，然后再 mutate initial seed 得到后续输入，观察覆盖率等提升情况      

对于 Windows，Hypercall 对于每次 ioctl 调用，可以传入如下结构体   

```c
struct Entry{
    uint32_t function_code = IOCTL;
    uint32_t Ioctlcode;
    uint32_t InputBufferLength;
    uint32_t OutputBufferLength;
    uint32_t inbuffer[InputBufferLength];
}
```

这在 Host OS 中的所有部分看上去都是一大块连续的数据，然后 Agent 可以按以下方式解析   

```c
uint64_t* entry = (uint64_t*)payload_buffer;
function_code = entry[0];
IoControlCode = entry[1];
InBufferLength = entry[2];
OutBufferLength = entry[3];
inbuffer = entry + 4;

if(function_code == IOCTL){
        DeviceIoControl(kafl_vuln_handle,
        IoControlCode,
        (LPVOID)inbuffer,
        InBufferLength,
        outbuff,
        OutBufferLength,
        NULL,
        NULL
        );

}
```
从而可以保证传入多个参数    
我们把 Host OS 上 mutator 看到的一大块数据叫做 input    

至于变异，mutator 虽然不知道比如说 input 0x10 的地方对应的传参是 InBufferLength，但是通过 RedQueen 的求解，如果在调用接口时，发现在被测 binary 中执行到了以下形式的代码   

```c
if (InputBufferLength < 0x10){
    return 0xc0000013;
}
```

则 mutator 也会知道在被测 binary 中 input 0x10 offset 地方的那个 8 字节值需要大于等于 0x10，才能 explore 更深，从而按照该标准变异，从而也能达到预期效果      

## TODO
阅读 kAFL 源码，有机会再写写     
