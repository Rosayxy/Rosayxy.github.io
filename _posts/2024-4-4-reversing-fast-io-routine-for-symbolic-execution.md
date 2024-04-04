---
date: 2024-4-4 21:22:03
layout: post
title: Reversing FastIo Routine for Symbolic Execution Implementation
subtitle: Looking through ntoskrnl for FastIo calls for Windows drivers
description: >-
  FastIo ~
image: >-
  /assets/img/uploads/flower_tree.jpg
optimized_image: >-
  /assets/img/uploads/sky.jpg
category: hackedemic
tags:
  - reverse
  - windows driver
  - FastIo
author: 已经逆不动的 Rosayxy
paginate: true
---

# Reversing FastIoDeviceControl for Symbolic Execution Implementation
## 背景
- 在 Windows 对于驱动的调用中，存在 FastIoDeviceControl 和 DispatchDeviceControl 两个调用 routine, 在驱动层面，他们是靠驱动在 DriverEntry (即是驱动的调用入口) 处对 DriverObject 的特定字段的初始化来注册相应的handler,具体来说，其中DispatchDeviceControl是MajorFunction中秩为14的字段,而FastIo则是在MajorFunction前面的FastIoDispatch字段。在系统调用 driver 中，最经典也是比较常见的系统调用是NtDeviceIoControlFile，即是和DispatchDeviceControl和FastIoDeviceControl这两个routine相关。内核把控制交给驱动的时候，根据这些关于DriverObject的偏移来调用这样的handler，再由 handler 根据ioctlcode（还有别的参数）来调用很多实施具体功能的函数，调用完会回到handler,handler返回时控制流重回内核    
拿经典driver afd.sys 做例子
DriverEntry 中注册如下：
```c
    DriverObject->MajorFunction[14] = (PDRIVER_DISPATCH)&AfdDispatchDeviceControl;
    DriverObject->MajorFunction[15] = (PDRIVER_DISPATCH)&AfdWskDispatchInternalDeviceControl;
    DriverObject->MajorFunction[23] = (PDRIVER_DISPATCH)&AfdEtwDispatch;
    DriverObject->FastIoDispatch = (PFAST_IO_DISPATCH)&AfdFastIoDispatch;
```
FastIoDispatch中根据ioctlcode 进行function dispatch table 中函数调用的代码如下
![alt_text](/assets/img/uploads/afd_dispatch.png)  
没截全的那一行是这个`v48 = (__int64 (__fastcall *)(_FILE_OBJECT *, _QWORD, _QWORD, unsigned int *, unsigned int, unsigned __int64, int, __int64))AfdImmediateCallDispatch[v47];`   
- 当前没找到从逆向kernel层面分析这个 dispatch routine 的博客或者其他资源，而且官方文档提供信息有限，遂决定自己写一篇（叉手手.jpg），特别感谢各位fuzz组师傅们帮助

## 问题
组会上讨论，发现有两个问题需要研究
1. FastIo routine 的调用条件，即是我用户态调用 NtDeviceControl 接口时需要如何调用到 FastIo 的路径
2. FastIoDeviceControl 的函数签名~
## 研究环境
- 在Windows 11 22H2 上分析 ntoskrnl.exe 和afd.sys等驱动
- 用IDA Pro 8.3 进行逆向
## 调用条件
### tldr
如果由FastIo的注册函数，则先调用FastIo,如果调用返回值非0就返回，否则调用DispatchDeviceControl
### 稍微详细一点版  
- 调用 FastIo 的 routine 集中在`NtDeviceIoControlFile` 直接调用的 `IopXxxControlFile` 里面  
- 我们先跳过那些前面对传入 handler 的检查，（这个之后再细说一下），来看和 FastIo 比较相关的部分~
    - 逆向发现有4个 if 条件需要满足
    - 第一个是第11个参数需要非0（第390行左右），而上层 NtCreateFile 直接设置这个参数是1就比较开心
    - 还有反汇编420行左右的
      ```c
      if ( !IsSandboxedToken ){
      FastIoDispatch = v31->DriverObject->FastIoDispatch;
      if ( FastIoDispatch ){
        FastIoDeviceControl = FastIoDispatch->FastIoDeviceControl;
        if ( FastIoDeviceControl ){
            //some code...
        }
      }
      }
      ``` 
      循环内层两个参数比较好办，只要 driver 注册了 FastIo 的 routine 就可以  
    - IsSandboxedToken 则需要**不满足**这个条件 `(ioctlcode == 589988 && input_len >= 4 || ioctlcode == 590860 && input_len >= 0x24)` ，如果满足的话，内核会根据进程的信息进行赋值，就不是咱可以控的参数了（但是依然有概率可以满足 IsSandbboxedToken 是0）
    - 然后就可以快乐调用 FastIo 的 routine 了！
    - 调用完之后，内核会检查 driver 注册的 fastIo handler 的返回值是否为0，如果非0就直接设置 Status然后返回，否则就会去进行下一步 DispatchDeviceControl 的调用
    - 之前还想到一个问题，就是按这种情况，一个同时注册了 FastIoDeviceControl 和DispatchDeviceControl routine 的 driver 会不会出现把 DispatchDeviceControl 路径上的调用传到 FastIo 里面，接下来就以 afd.sys 来分析一下
      - 逆向可知，如果 DispatchDeviceControl 的调用号不在 FastIo 里面出现，或者因不满足其他情况而不被调用，则 FastIo handler 一定返回0
      - 但是 afd.sys 情况是用同一个 ioctltable 去调用不同 function dispatch table，所以可能会以不满足条件的 InputBuffer 去调用 FastIo 对应 dispatch table 里面的函数。而这时的措施**就由 driver 去自定义了**，本来预期是可能根据比如说 FsContext 里面的某个字段去当一个 is_fastio 的flag， 然后逆了一下一些FastIoDeviceControl 和DispatchDeviceControl的分发函数发现应该不是这样的（不知道会不会逆错了www）（所以直觉这里可能有洞？(但是不确定诶ww)）   

- 对handler的检查
  - 可能可以偷懒？的办法：https://securityintelligence.com/x-force/patch-tuesday-exploit-wednesday-pwning-windows-ancillary-function-driver-winsock/  按照这个cve-2023-21768 的exp 写（逃）
  - 有一处 `v19 = ObReferenceObjectByHandle(Handle, 0, (POBJECT_TYPE)IoFileObjectType, PreviousMode, &v88, &v104);` , 按 `ObpKernelHandleTable` 根据 Handle 去查找初始化file_object,即是FastIo handler 所需要的第一个参数，但是很遗憾，`ObpKernelHandleTable`是在运行时初始化的，找到了`ObWaitForMultipleObjects`一个Xref，看调用链发现应该是接受系统调用的传参来初始化（）
  - 接着调handler的参数使得**不满足**`file_object_->CompletionContext && (a3.QuadPart & 0xFFFFFFFFFFFFFFFEui64) != 0` 这个条件
  - 接着就感觉没啥检查了哈哈哈~

- 顺带说一下DispatchDeviceControl调用链吧
  - `NtDeviceIoControlFile`->`IopXxxControlFile`->`IopSynchronousServiceTail`->`IofCallDriver`就是这个

## 函数签名
```c
v35 = FastIoDeviceControl(
                  file_object_,
                  wait,  // 没啥用，之前被设置成1
                  InputBuffer,
                  InputBufferLength,
                  OutputBuffer,
                  OutputBufferLength,
                  ioctlcode,
                  (_IO_STATUS_BLOCK *)&io_status,// 这个传入时是0
                  device_object);// 这个没啥用，IDA Pro 反编译的时候多加了这个参数
```
是不是非常直接？（没错，这感觉就很REDQUEEN）
（是不是要稍微解释一下REDQUEEN呀hhh? REDQUEEN 是一个神仙 fuzzer, 一个主要的motivation是用户输入在进入内核的时候，值一般不会得到很大的变化，即使是进入比较深层次的地方也是这样子，所以REDQUEEN就采取了一些魔法手段来规避符号执行和污点分析的开销，当时看到的时候就震撼到了hhh）    
- file_object_： 
  - 首先根据handle初始化，具体看 `v19 = ObReferenceObjectByHandle(Handle, 0, (POBJECT_TYPE)IoFileObjectType, PreviousMode, &v88, &v104);`，将调用完后v88的值赋给了它,在我们可控的参数中，这个只由Handle控制，而具体字段的赋值则由`ObpKernelHandleTable`决定，但是这个我们应是无法静态分析来的  
  - 然后是DeviceObject的初始化，belike:  
  ```c
    if ( (file_object_->Flags & 0x800) != 0 )
    AttachedDevice = IoGetAttachedDevice(file_object_->DeviceObject);
    else
    AttachedDevice = IoGetRelatedDeviceObject(file_object_);
    ```
  - file_object 看微软官方文档长这样：
    ```c
    typedef struct _FILE_OBJECT {
    CSHORT                            Type;
    CSHORT                            Size;
    PDEVICE_OBJECT                    DeviceObject;
    PVPB                              Vpb;
    PVOID                             FsContext;
    PVOID                             FsContext2;
    PSECTION_OBJECT_POINTERS          SectionObjectPointer;
    PVOID                             PrivateCacheMap;
    NTSTATUS                          FinalStatus;
    struct _FILE_OBJECT               *RelatedFileObject;
    BOOLEAN                           LockOperation;
    BOOLEAN                           DeletePending;
    BOOLEAN                           ReadAccess;
    BOOLEAN                           WriteAccess;
    BOOLEAN                           DeleteAccess;
    BOOLEAN                           SharedRead;
    BOOLEAN                           SharedWrite;
    BOOLEAN                           SharedDelete;
    ULONG                             Flags;
    UNICODE_STRING                    FileName;
    LARGE_INTEGER                     CurrentByteOffset;
    __volatile ULONG                  Waiters;
    __volatile ULONG                  Busy;
    PVOID                             LastLock;
    KEVENT                            Lock;
    KEVENT                            Event;
    __volatile PIO_COMPLETION_CONTEXT CompletionContext;
    KSPIN_LOCK                        IrpListLock;
    LIST_ENTRY                        IrpList;
    __volatile PVOID                  FileObjectExtension;
    } FILE_OBJECT, *PFILE_OBJECT;
    ``` 

嗯 所以大概就是这样的 ~
## 一点小总结
- 逆向还是有点费脑子哈哈哈
- 但是说实话比想象中简单（逃）而且还是挺好玩的，之后就是一点todo,把fastio的信息移植到一些符号执行工具上啦！
- **如果有师傅发现写的有问题或者有地方需要交流，可以邮箱联系，谢谢啦！**
- 是春天啦，大家春天快乐：）
## reference
- https://learn.microsoft.com/en-us/previous-versions/windows/hardware/network/ff565048(v=vs.85)
- https://www.ndss-symposium.org/ndss-paper/redqueen-fuzzing-with-input-to-state-correspondence/
- https://en.wikipedia.org/wiki/Ntoskrnl.exe

## appendix

贴一段简单逆向过的伪代码吧hhh可以跟上文比对看看~ (苯人逆向不太行，在线求大佬带带www)

```cpp{.line-numbers}
// IopXxxControlFile(
//            FileHandle,
//            (IRP *)Event,
//            (_LARGE_INTEGER)ApcRoutine,
//            ApcContext,
//            IoStatusBlock,
//            IoControlCode,
//            (char *)InputBuffer,
//            InputBufferLength,
//            OutputBuffer,
//            OutputBufferLength,
//            1);
__int64 __fastcall IopXxxControlFile(
        HANDLE Handle,
        IRP *a2,
        _LARGE_INTEGER a3,
        void *a4,
        _IO_STATUS_BLOCK *a5,
        unsigned int ioctlcode,
        char *a7,
        int a8,
        volatile void *Address,
        int a10,
        char a11)
{
  char *v12; // r8
  PVOID v13; // r9
  LOCK_OPERATION v14; // r13d
  int v15; // edi
  char PreviousMode; // r12
  __int64 v17; // rcx
  unsigned int v18; // eax
  int v19; // ebx
  __int64 v20; // r8
  _FILE_OBJECT *file_object_; // rsi
  _DWORD *v22; // rax
  unsigned int input_len; // edi
  _KPROCESS *Process; // rcx
  __int16 v25; // ax
  __int64 Status; // rcx
  unsigned int OutputBufferLength; // ebx
  struct _DEVICE_OBJECT *AttachedDevice; // rax
  unsigned __int64 wait; // rdx
  __int64 v30; // rcx
  PDEVICE_OBJECT v31; // rdi
  _FAST_IO_DISPATCH *FastIoDispatch; // rcx
  unsigned __int8 (__fastcall *FastIoDeviceControl)(_FILE_OBJECT *, unsigned __int8, void *, unsigned int, void *, unsigned int, unsigned int, _IO_STATUS_BLOCK *, _DEVICE_OBJECT *); // r14
  _DWORD *v34; // rdi
  unsigned __int8 v35; // bl
  IRP *v36; // rax
  __int64 v37; // r9
  IRP *v38; // rbx
  _IO_STACK_LOCATION *CurrentStackLocation; // r14
  char v40; // r8
  ULONG v41; // ecx
  unsigned int v42; // edx
  int v43; // eax
  __int64 v44; // rcx
  _IRP *v45; // rax
  struct _MDL *Mdl; // rdi
  unsigned __int64 v48; // rcx
  unsigned __int64 v49; // rdx
  char *v50; // rcx
  int v51; // eax
  struct _KTHREAD *CurrentThread; // rax
  volatile __int32 *v53; // rbx
  __int64 v54; // rax
  unsigned int v55; // ebx
  __int64 v56; // rbx
  _IO_STATUS_BLOCK *v57; // rcx
  int v58; // r9d
  HANDLE v59; // r14
  PVOID v60; // r14
  unsigned int v61; // eax
  __int64 v62; // rcx
  _IRP *Pool2; // rax
  __int64 v64; // rcx
  int v65; // ecx
  __int64 v66; // rdx
  __int64 v67; // rsi
  char v68; // di
  char v69; // al
  char v70; // di
  __int64 *v71; // r8
  char IsProcessAppContainer; // al
  struct _KPROCESS *v73; // rax
  int v74; // eax
  _IRP *MasterIrp; // rax
  int Object; // [rsp+20h] [rbp-1C8h]
  int HandleInformation; // [rsp+28h] [rbp-1C0h]
  char v78; // [rsp+50h] [rbp-198h]
  char IsSandboxedToken; // [rsp+51h] [rbp-197h]
  unsigned int InputBufferLength; // [rsp+54h] [rbp-194h]
  unsigned int Size_4; // [rsp+58h] [rbp-190h]
  char v82; // [rsp+5Ch] [rbp-18Ch]
  unsigned int v83; // [rsp+60h] [rbp-188h] BYREF
  char v84; // [rsp+68h] [rbp-180h] BYREF
  char v85; // [rsp+69h] [rbp-17Fh]
  char v86; // [rsp+6Ah] [rbp-17Eh]
  SIZE_T Length; // [rsp+70h] [rbp-178h]
  PVOID v88; // [rsp+78h] [rbp-170h] BYREF
  int v89; // [rsp+80h] [rbp-168h]
  char v90; // [rsp+84h] [rbp-164h]
  PVOID v91; // [rsp+88h] [rbp-160h]
  void *InputBuffer; // [rsp+90h] [rbp-158h]
  int v93; // [rsp+98h] [rbp-150h]
  unsigned int v94; // [rsp+9Ch] [rbp-14Ch]
  PVOID OutputBuffer; // [rsp+A0h] [rbp-148h]
  __int128 io_status; // [rsp+A8h] [rbp-140h] BYREF
  _IO_STATUS_BLOCK *v97; // [rsp+B8h] [rbp-130h]
  PVOID P; // [rsp+C0h] [rbp-128h] BYREF
  struct _DEVICE_OBJECT *device_object; // [rsp+C8h] [rbp-120h]
  HANDLE Handlea; // [rsp+D0h] [rbp-118h]
  PIRP Irp; // [rsp+D8h] [rbp-110h]
  unsigned int v102; // [rsp+E0h] [rbp-108h] BYREF
  __int64 v103; // [rsp+E8h] [rbp-100h]
  struct _OBJECT_HANDLE_INFORMATION v104; // [rsp+F0h] [rbp-F8h] BYREF
  PVOID v105; // [rsp+F8h] [rbp-F0h] BYREF
  __int64 v106; // [rsp+100h] [rbp-E8h]
  PETHREAD Thread; // [rsp+108h] [rbp-E0h]
  __int64 v108; // [rsp+110h] [rbp-D8h] BYREF
  PDEVICE_OBJECT v109; // [rsp+118h] [rbp-D0h] BYREF
  struct _SECURITY_SUBJECT_CONTEXT SubjectContext; // [rsp+120h] [rbp-C8h] BYREF
  struct _KTHREAD *v111; // [rsp+140h] [rbp-A8h]
  char v112[32]; // [rsp+150h] [rbp-98h] BYREF
  __int64 *v113; // [rsp+170h] [rbp-78h]
  __int64 v114; // [rsp+178h] [rbp-70h]
  PDEVICE_OBJECT *v115; // [rsp+180h] [rbp-68h]
  __int64 v116; // [rsp+188h] [rbp-60h]
  unsigned int *v117; // [rsp+190h] [rbp-58h]
  __int64 v118; // [rsp+198h] [rbp-50h]

  Handlea = a2;
  v86 = a11;
  Irp = a2;
  v97 = a5;
  v12 = a7;
  InputBuffer = a7;
  v83 = a8;
  v13 = (PVOID)Address;
  OutputBuffer = (PVOID)Address;
  LODWORD(Length) = a10;
  v14 = IoReadAccess;
  v91 = 0i64;
  v104 = 0i64;
  io_status = 0i64;
  v15 = ioctlcode & 3;
  v89 = v15;
  v94 = v15;
  Thread = KeGetCurrentThread();
  PreviousMode = Thread->PreviousMode;
  if ( IoFsctlProcessMitigationEnabled )
  {
    if ( !PreviousMode )
      goto LABEL_152;
    if ( !a11 && !(unsigned __int8)IopIsStandardFsctlIoControlCode(ioctlcode) )
    {
      v67 = *(_QWORD *)(v66 + 184);
      v68 = *(_DWORD *)(v67 + 2928);
      v69 = v68 & 4;
      v70 = v68 & 2;
      if ( v70 || v69 )
      {
        if ( (*(_DWORD *)(v67 + 2928) & 4) != 0 )
        {
          v71 = MITIGATION_AUDIT_PROHIBIT_FSCTL_SYSTEM_CALLS;
          if ( v70 )
            v71 = MITIGATION_ENFORCE_PROHIBIT_FSCTL_SYSTEM_CALLS;
          EtwpTimLogMitigationForProcess(3i64, (unsigned int)(v70 != 0) + 1, v71, v67);
          _InterlockedAnd((volatile signed __int32 *)(v67 + 2928), 0xFFFFFFFB);
          v13 = OutputBuffer;
          v12 = (char *)InputBuffer;
        }
        if ( v70 )
          return 0xC0000022i64;
      }
      v15 = v89;
    }
  }
  if ( !PreviousMode )
  {
LABEL_152:
    InputBufferLength = v83;
    Size_4 = Length;
    goto LABEL_19;
  }
  v17 = (__int64)v97;
  if ( (unsigned __int64)v97 >= 0x7FFFFFFF0000i64 )
    v17 = 0x7FFFFFFF0000i64;
  *(_DWORD *)v17 = *(_DWORD *)v17;
  if ( v15 )
  {
    v18 = Length;
LABEL_7:
    Size_4 = v18;
    goto LABEL_8;
  }
  if ( !v13 )
  {
    v18 = 0;
    LODWORD(Length) = 0;
    goto LABEL_7;
  }
  Size_4 = Length;
  ProbeForWrite(v13, (unsigned int)Length, 1u);
  v12 = (char *)InputBuffer;
LABEL_8:
  if ( v15 == 3 )
  {
    InputBufferLength = v83;
  }
  else if ( v12 )
  {
    InputBufferLength = v83;
    if ( v83 && ((unsigned __int64)&v12[v83] > 0x7FFFFFFF0000i64 || &v12[v83] < v12) )
      MEMORY[0x7FFFFFFF0000] = 0;
  }
  else
  {
    InputBufferLength = 0;
    v83 = 0;
  }
LABEL_19:
  v88 = 0i64;
  v19 = ObReferenceObjectByHandle(Handle, 0, (POBJECT_TYPE)IoFileObjectType, PreviousMode, &v88, &v104);
  file_object_ = (_FILE_OBJECT *)v88;
  if ( v19 >= 0 && (v22 = (_DWORD *)*((_QWORD *)v88 + 26)) != 0i64 && (*v22 & 4) != 0 )
  {
    IsProcessAppContainer = PsIsProcessAppContainer(KeGetCurrentThread()->ApcState.Process);
    file_object_ = (_FILE_OBJECT *)v88;
    if ( IsProcessAppContainer )
    {
      ObfDereferenceObject(v88);
      v19 = 0xC0000910;
    }
    input_len = v83;
    InputBufferLength = v83;
    Size_4 = Length;
  }
  else
  {
    input_len = InputBufferLength;
  }
  if ( v19 < 0 )
    return (unsigned int)v19;
  if ( file_object_->CompletionContext && (a3.QuadPart & 0xFFFFFFFFFFFFFFFEui64) != 0 )
  {
    ObfDereferenceObject(file_object_);
    return 3221225485i64;
  }
  if ( PreviousMode
    && (unsigned __int16)ioctlcode >> 14
    && (((unsigned __int16)ioctlcode >> 14) & v104.GrantedAccess) != (unsigned __int16)ioctlcode >> 14 )
  {
    ObfDereferenceObject(file_object_);
    return 0xC0000022i64;
  }
  if ( ioctlcode == 0x94264 || ioctlcode == 0x98268 )
  {
    v19 = IopCopyOffloadCapable(file_object_, ioctlcode);
    if ( v19 < 0 )
      goto LABEL_192;
  }
  else if ( ioctlcode == 0x9042C )
  {
    LOBYTE(v20) = 1;
    v19 = IopSetFileObjectExtensionFlag(file_object_, 16i64, v20);
    if ( v19 < 0 )
    {
      ObfDereferenceObject(file_object_);
      return (unsigned int)v19;
    }
  }
  if ( Handlea )
  {
    v105 = 0i64;
    v19 = ObReferenceObjectByHandle(Handlea, 2u, (POBJECT_TYPE)ExEventObjectType, PreviousMode, &v105, 0i64);
    v91 = v105;
    if ( v19 >= 0 )
    {
      KeResetEvent((PRKEVENT)v105);
      goto LABEL_30;
    }
LABEL_192:
    ObfDereferenceObject(file_object_);
    return (unsigned int)v19;
  }
LABEL_30:
  P = 0i64;
  IsSandboxedToken = 0;
  v82 = 0;
  if ( PreviousMode && (ioctlcode == 589988 && input_len >= 4 || ioctlcode == 590860 && input_len >= 0x24) )
  {
    memset(&SubjectContext, 0, sizeof(SubjectContext));
    v73 = IoThreadToProcess(Thread);
    SeCaptureSubjectContextEx(Thread, v73, &SubjectContext);
    IsSandboxedToken = ((__int64 (__fastcall *)(PSECURITY_SUBJECT_CONTEXT))RtlIsSandboxedToken)(&SubjectContext);
    v90 = IsSandboxedToken;
    SeReleaseSubjectContext(&SubjectContext);
    if ( IsSandboxedToken )
    {
      v93 = 0;
      if ( ioctlcode == 0x9040C )
        v74 = *((_DWORD *)InputBuffer + 8);
      else
        v74 = *(_DWORD *)InputBuffer;
      v93 = v74;
      if ( v74 == 0xA0000003 )
      {
        v82 = 1;
        v19 = IopValidateJunctionTarget(ioctlcode, InputBuffer, InputBufferLength, Size_4, &P, &v83);
        InputBufferLength = v83;
      }
      if ( v19 < 0 )
      {
        if ( v91 )
          ObfDereferenceObject(v91);
        goto LABEL_192;
      }
    }
  }
  if ( (file_object_->Flags & 2) != 0 )
  {
    CurrentThread = KeGetCurrentThread();
    --CurrentThread->KernelApcDisable;
    v53 = (volatile __int32 *)v88;
    v54 = KeAbPreAcquire((char *)v88 + 128, 0i64, 0i64);
    v84 = 0;
    if ( _InterlockedExchange(v53 + 29, 1) )
    {
      file_object_ = (_FILE_OBJECT *)v88;
      v55 = IopWaitAndAcquireFileObjectLock(v88, (__int64)&v84);
    }
    else
    {
      if ( v54 )
        *(_BYTE *)(v54 + 18) = 1;
      file_object_ = (_FILE_OBJECT *)v88;
      ObfReferenceObject(v88);
      v55 = 0;
    }
    if ( v84 )
    {
      if ( v91 )
        ObfDereferenceObject(v91);
      if ( P )
        ExFreePoolWithTag(P, 0);
      ObfDereferenceObject(file_object_);
      return v55;
    }
    v78 = 1;
    InputBufferLength = v83;
    OutputBufferLength = Length;
    Size_4 = Length;
  }
  else
  {
    v78 = 0;
    if ( PreviousMode )
    {
      v111 = KeGetCurrentThread();
      Process = v111->ApcState.Process;
      if ( Process[1].Affinity.StaticBitmap[30] )
      {
        v25 = WORD2(Process[2].Affinity.StaticBitmap[20]);
        if ( v25 == 332 || v25 == 452 )
        {
          Status = (unsigned int)v97->Status;
          *(_DWORD *)Status = *(_DWORD *)Status;
          v97 = (_IO_STATUS_BLOCK *)Status;
          a3.QuadPart |= 1ui64;
        }
      }
      file_object_ = (_FILE_OBJECT *)v88;
      InputBufferLength = v83;
      OutputBufferLength = Length;
      Size_4 = Length;
    }
    else
    {
      OutputBufferLength = Size_4;
    }
  }
  if ( (file_object_->Flags & 0x800) != 0 )
    AttachedDevice = IoGetAttachedDevice(file_object_->DeviceObject);
  else
    AttachedDevice = IoGetRelatedDeviceObject(file_object_);
  v31 = AttachedDevice;
  device_object = AttachedDevice;
  if ( a11 )
  {
    if ( AstIsActive )
    {
      if ( dword_140C03878 )
      {
        if ( (BYTE2(AttachedDevice[-1].DeviceObjectExtension) & 2) != 0
          && !(unsigned __int8)AstTestBloomFilter(v30, AttachedDevice, ioctlcode) )
        {
          AstAddBloomFilter(v64, (__int64)v31, ioctlcode);
          if ( (unsigned int)dword_140C03878 > 5 )
          {
            if ( (unsigned __int8)tlgKeywordOn(&dword_140C03878, 0x200000000000i64) )
            {
              v108 = 0x80000000i64;
              v113 = &v108;
              v114 = 8i64;
              v109 = v31;
              v115 = &v109;
              v116 = 8i64;
              v102 = ioctlcode;
              v117 = &v102;
              v118 = 4i64;
              tlgWriteTransfer_EtwWriteTransfer(&dword_140C03878, &word_14002BFB6, 0i64, 0i64, 5, v112);
            }
          }
        }
      }
    }
    if ( !IsSandboxedToken )
    {
      FastIoDispatch = v31->DriverObject->FastIoDispatch;
      if ( FastIoDispatch )
      {
        FastIoDeviceControl = FastIoDispatch->FastIoDeviceControl;
        if ( FastIoDeviceControl )
        {
          if ( PreviousMode && OutputBuffer )
          {
            if ( v89 == 1 )
            {
              if ( OutputBufferLength )
              {
                v50 = (char *)OutputBuffer + OutputBufferLength;
                if ( (unsigned __int64)v50 > 0x7FFFFFFF0000i64 || v50 < OutputBuffer )
                  MEMORY[0x7FFFFFFF0000] = 0;
              }
            }
            else if ( v89 == 2 && OutputBufferLength )
            {
              v48 = (unsigned __int64)OutputBuffer;
              v49 = (unsigned __int64)OutputBuffer + OutputBufferLength - 1;
              if ( (unsigned __int64)OutputBuffer > v49 || v49 >= 0x7FFFFFFF0000i64 )
                ExRaiseAccessViolation();
              wait = (v49 & 0xFFFFFFFFFFFFF000ui64) + 4096;
              do
              {
                *(_BYTE *)v48 = *(_BYTE *)v48;
                v48 = (v48 & 0xFFFFFFFFFFFFF000ui64) + 4096;
              }
              while ( v48 != wait );
              file_object_ = (_FILE_OBJECT *)v88;
              InputBufferLength = v83;
              OutputBufferLength = Length;
              Size_4 = Length;
            }
          }
          if ( ioctlcode == 0x90020 )
          {
            _InterlockedIncrement((volatile signed __int32 *)(MmWriteableSharedUserData + 732));
            file_object_ = (_FILE_OBJECT *)v88;
            InputBufferLength = v83;
            OutputBufferLength = Length;
            Size_4 = Length;
          }
          if ( (MmVerifierData & 0x10) != 0 && MmIsDriverVerifying(v31->DriverObject) )
            v34 = (_DWORD *)VfFastIoSnapState();
          else
            v34 = 0i64;
          LOBYTE(wait) = 1;
          v35 = FastIoDeviceControl(
                  file_object_,
                  wait,
                  InputBuffer,
                  InputBufferLength,
                  OutputBuffer,
                  OutputBufferLength,
                  ioctlcode,
                  (_IO_STATUS_BLOCK *)&io_status,// 这个传入时是0
                  device_object);
          if ( v34 )
            VfFastIoCheckState(v34, (ULONG_PTR)FastIoDeviceControl);
          if ( v35 )
          {
            v56 = 0i64;
            v103 = 0i64;
            v106 = 0i64;
            v85 = 0;
            if ( (a3.LowPart & 1) != 0 )
            {
              v57 = v97;
              HIDWORD(v97->Pointer) = DWORD2(io_status);
              v57->Status = io_status;
            }
            else
            {
              *v97 = (_IO_STATUS_BLOCK)io_status;
            }
            v58 = io_status;
            v59 = Handlea;
            if ( file_object_->CompletionContext
              && ((file_object_->Flags & 0x2000000) == 0 || (io_status & 0xC0000000) == 0x80000000)
              && (io_status & 0xC0000000) != -1073741824 )
            {
              IopIncrementCompletionContextUsageCountAndReadData((ULONG_PTR)file_object_);
              v58 = io_status;
              v56 = v103;
            }
            if ( v59 )
            {
              if ( (file_object_->Flags & 0x8000000) == 0 || v56 && (v58 & 0xC0000000) == 0x80000000 )
              {
                v60 = v91;
                KeSetEvent((PRKEVENT)v91, 0, 0);
              }
              else
              {
                v60 = v91;
              }
              ObfDereferenceObject(v60);
              v58 = io_status;
            }
            if ( v78 )
            {
              IopReleaseFileObjectLock((PADAPTER_OBJECT)file_object_);
              v58 = io_status;
            }
            if ( v56 && a4 )
            {
              if ( (int)IoSetIoCompletionEx2(v56, v106, (int)a4, v58, *((__int64 *)&io_status + 1), 1, 0i64) < 0 )
              {
                v65 = -1073741670;
                LODWORD(io_status) = -1073741670;
              }
              else
              {
                v65 = io_status;
              }
              if ( (v65 & 0xC0000000) == 0x80000000 )
                LODWORD(io_status) = 259;
            }
            if ( v85 )
              IopDecrementCompletionContextUsageCount((ULONG_PTR)file_object_);
            ObfDereferenceObject(file_object_);
            return (unsigned int)io_status;
          }
          v31 = device_object;
        }
      }
    }
  }
  Handlea = &file_object_->Flags;
  if ( (file_object_->Flags & 0x4000000) == 0 )
    KeResetEvent(&file_object_->Event);
  v36 = (IRP *)IopAllocateIrpExReturn((__int64)v31, (unsigned __int8)v31->StackSize, (unsigned __int8)v78 ^ 1u);
  v38 = v36;
  Irp = v36;
  if ( v36 )
  {
    v36->Tail.Overlay.OriginalFileObject = file_object_;
    v36->Tail.Overlay.Thread = (_ETHREAD *)Thread;
    v36->Tail.Overlay.AuxiliaryBuffer = 0i64;
    v36->RequestorMode = PreviousMode;
    v36->PendingReturned = 0;
    v36->Cancel = 0;
    v36->CancelRoutine = 0i64;
    v36->UserEvent = (_KEVENT *)v91;
    v36->UserIosb = v97;
    v36->Overlay.AllocationSize = a3;
    v36->Overlay.AsynchronousParameters.UserApcContext = a4;
    CurrentStackLocation = v36->Tail.Overlay.CurrentStackLocation;
    v40 = v86;
    *(_DWORD *)&CurrentStackLocation[-1].MajorFunction = (v86 != 0) + 13;
    CurrentStackLocation[-1].FileObject = file_object_;
    v41 = Size_4;
    CurrentStackLocation[-1].Parameters.Read.Length = Size_4;
    v42 = InputBufferLength;
    CurrentStackLocation[-1].Parameters.Create.Options = InputBufferLength;
    CurrentStackLocation[-1].Parameters.Read.ByteOffset.LowPart = ioctlcode;
    v36->MdlAddress = 0i64;
    v36->AssociatedIrp.MasterIrp = 0i64;
    v43 = v89;
    if ( (v31->Flags & 0x80000) != 0 )
    {
      v37 = 3i64;
      if ( !IsSandboxedToken )
        v43 = 3;
      v89 = v43;
    }
    if ( v43 == 2 )
      goto LABEL_62;
    if ( !v43 )
    {
      CurrentStackLocation[-1].Parameters.CreatePipe.Parameters = 0i64;
      if ( InputBufferLength || Size_4 )
      {
        if ( P )
        {
          v38->AssociatedIrp.MasterIrp = (_IRP *)P;
        }
        else
        {
          v61 = Size_4;
          if ( InputBufferLength > Size_4 )
            v61 = InputBufferLength;
          v62 = 105i64;
          if ( !v40 )
            v62 = 97i64;
          Pool2 = (_IRP *)ExAllocatePool2(v62, v61, 1112764233i64);
          v38->AssociatedIrp.MasterIrp = Pool2;
          if ( InputBuffer )
            memmove(Pool2, InputBuffer, InputBufferLength);
          v42 = InputBufferLength;
          v41 = Size_4;
        }
        v38->Flags = 48;
        v38->UserBuffer = OutputBuffer;
        if ( v41 )
          v38->Flags = 112;
      }
      else
      {
        v38->Flags = 0;
        v38->UserBuffer = 0i64;
      }
      if ( v42 < v41 )
        memset((char *)v38->AssociatedIrp.MasterIrp + v42, 0, v41 - v42);
      goto LABEL_73;
    }
    v51 = v43 - 1;
    if ( !v51 )
    {
LABEL_62:
      v38->Flags = 0;
      CurrentStackLocation[-1].Parameters.CreatePipe.Parameters = 0i64;
      if ( InputBufferLength && InputBuffer )
      {
        v44 = 107i64;
        if ( !v40 )
          v44 = 99i64;
        v45 = (_IRP *)ExAllocatePool2(v44, InputBufferLength, 1112764233i64);
        v38->AssociatedIrp.MasterIrp = v45;
        memmove(v45, InputBuffer, InputBufferLength);
        v38->Flags = 48;
        v41 = Size_4;
      }
      if ( v41 )
      {
        Mdl = IoAllocateMdl(OutputBuffer, v41, 0, 1u, v38);
        v38->MdlAddress = Mdl;
        if ( !Mdl )
          RtlRaiseStatus(-1073741670);
        v94 = *(_DWORD *)&CurrentStackLocation[-1].MajorFunction;
        LOBYTE(v14) = v89 != 1;
        MmProbeAndLockPages(Mdl, PreviousMode, v14);
        if ( (MmTrackLockedPages & 1) != 0 )
          MmUpdateMdlTracker(Mdl, device_object->DriverObject->MajorFunction[v94]);
      }
      v31 = device_object;
    }
    else if ( v51 == 2 )
    {
      v38->Flags = 0;
      v38->UserBuffer = OutputBuffer;
      CurrentStackLocation[-1].Parameters.CreatePipe.Parameters = (_NAMED_PIPE_CREATE_PARAMETERS *)InputBuffer;
    }
LABEL_73:
    CurrentStackLocation[-1].Flags |= v104.GrantedAccess & 1 | (unsigned __int8)(2 * (v104.GrantedAccess & 2));
    if ( !a11 )
      v38->Flags |= 0x800u;
    if ( ioctlcode == 589856 )
    {
      _InterlockedIncrement((volatile signed __int32 *)(MmWriteableSharedUserData + 732));
      file_object_ = (_FILE_OBJECT *)v88;
    }
    if ( !IsSandboxedToken || v82 )
      goto LABEL_78;
    MasterIrp = v38->AssociatedIrp.MasterIrp;
    if ( ioctlcode == 590860 )
      MasterIrp = (_IRP *)((char *)MasterIrp + 32);
    if ( *(_DWORD *)&MasterIrp->Type != 0xA0000003 )
    {
LABEL_78:
      LOBYTE(v37) = v86 == 0;
      LOBYTE(HandleInformation) = v78;
      LOBYTE(Object) = PreviousMode;
      return IopSynchronousServiceTail(v31, v38, (__int64)file_object_, v37, Object, HandleInformation, 2u);
    }
    IopExceptionCleanupEx(file_object_, v38, v91, 0i64, (*(_DWORD *)Handlea & 2) != 0);
    return 3221225485i64;
  }
  IopAllocateIrpCleanup((PADAPTER_OBJECT)file_object_, (PADAPTER_OBJECT)v91);
  if ( P )
    ExFreePoolWithTag(P, 0);
  return 3221225626i64;
}

```