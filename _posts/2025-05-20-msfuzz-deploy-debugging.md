---
date: 2025-05-20 10:21:56
layout: post
title: Solving MsFuzz Deploying Problem of Not Able to Start Fuzzing
subtitle: 
description: >-
    Anyway, I personally think that the installation manual of MsFuzz should be clearer...
image: >-
  /assets/img/uploads/rainy_street.jpg
optimized_image: >-
  /assets/img/uploads/rainy_street.jpg
category: hackedemic
tags:
  - Windows fuzz
  - MsFuzz
author: rosayxy
paginate: true
---

Please refer to [this issue](https://github.com/0dayResearchLab/msFuzz/issues/7) for the details of the problem and solution.    
## vuln_test.c
The `vuln_test.c` after the modification should be as follows (using the `afd.sys` driver as an example to fuzz, the places to modify are marked with `// TODO`):    
```c
#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include "nyx_api.h"
#include <psapi.h>

#define LOG_UPDATE_FREQ      5000
#define MAX_ATTEMPT          200000
#define MAX_IRP_COUNT        500
#define ARRAY_SIZE 1024
#define BUF_SIZE 0x10000

#define INFO_SIZE                       (128 << 10)				/* 128KB info string */

#define PAYLOAD_MAX_SIZE (128*1024)

// TODO: change this to the driver name to fuzz
#define VULN_DRIVER_NAME "afd.sys"
// TODO: change this to the driver name to fuzz
#define VULN_DRIVER_NAME2 "afd.sys"
// TODO: change this to the driver name to fuzz
#define VULN_DRIVER_NAME3 "afd.sys"

#define IOCTL 0x4f494f49 // 'IOIO'
#define WRITE 0x52575257 // 'WRITE'
#define REVERT 0x45524552 // 'RERE'
typedef unsigned int uint32_t;


typedef struct __attribute__((__packed__)){
        uint32_t function_code;
        uint32_t IoControlCode;
        uint32_t InBufferLength;
        uint32_t OutBufferLength;
        uint8_t InBuffer[PAYLOAD_MAX_SIZE-sizeof(uint32_t)*4];
} kAFL_custom;


PCSTR ntoskrnl = "C:\\Windows\\System32\\ntoskrnl.exe";
PCSTR kernel_func1 = "KeBugCheck";
PCSTR kernel_func2 = "KeBugCheckEx";

FARPROC KernGetProcAddress(HMODULE kern_base, LPCSTR function){
    // error checking? bah...
    HMODULE kernel_base_in_user_mode = LoadLibraryA(ntoskrnl);
    return (FARPROC)((PUCHAR)GetProcAddress(kernel_base_in_user_mode, function) - (PUCHAR)kernel_base_in_user_mode + (PUCHAR)kern_base);
}   


UINT64 resolve_KeBugCheck(PCSTR kfunc){
    LPVOID drivers[ARRAY_SIZE];
    DWORD cbNeeded;
    FARPROC KeBugCheck = NULL;
    int cDrivers, i;

    if( EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers)){ 
        TCHAR szDriver[ARRAY_SIZE];
        cDrivers = cbNeeded / sizeof(drivers[0]);
        for (i=0; i < cDrivers; i++){
            if(GetDeviceDriverFileName(drivers[i], szDriver, sizeof(szDriver) / sizeof(szDriver[0]))){
            // assuming ntoskrnl.exe is first entry seems save (FIXME)
                if (i == 0){
                    KeBugCheck = KernGetProcAddress((HMODULE)drivers[i], kfunc);
                    if (!KeBugCheck){
                        printf("[-] w00t?");
                        ExitProcess(0);
                    }
                    break;
                }
            }
        }
    }
    else{
        printf("[-] EnumDeviceDrivers failed; array size needed is %d\n", (UINT32)(cbNeeded / sizeof(LPVOID)));
        ExitProcess(0);
    }

    return  (UINT64) KeBugCheck;
}


void init_agent_handshake() {

    hprintf("Initiate fuzzer handshake...\n");

    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

    // Submit our CR3
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    // Tell KAFL we're running in 64bit mode
    kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

    /* Request information on available (host) capabilites (not optional) */
    volatile host_config_t host_config;
    kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);
    if (host_config.host_magic != NYX_HOST_MAGIC ||
        host_config.host_version != NYX_HOST_VERSION) {
	hprintf("host_config magic/version mismatch!\n");
	habort("GET_HOST_CNOFIG magic/version mismatch!\n");
    }

    hprintf("\thost_config.bitmap_size: 0x%lx\n", host_config.bitmap_size);
    hprintf("\thost_config.ijon_bitmap_size: 0x%lx\n", host_config.ijon_bitmap_size);
    hprintf("\thost_config.payload_buffer_size: 0x%lx\n", host_config.payload_buffer_size);

    /* reserved guest memory must be at least as large as host SHM view */
    if (PAYLOAD_MAX_SIZE < host_config.payload_buffer_size) {
        habort("Insufficient guest payload buffer!\n");
    }

    /* submit agent configuration */
    volatile agent_config_t agent_config = {0};
    agent_config.agent_magic = NYX_AGENT_MAGIC;
    agent_config.agent_version = NYX_AGENT_VERSION;

    agent_config.agent_tracing = 0; // trace by host!
    agent_config.agent_ijon_tracing = 0; // no IJON
    agent_config.agent_non_reload_mode = 1; // allow persistent
    agent_config.coverage_bitmap_size = host_config.bitmap_size;

    kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

}

typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, *PRTL_PROCESS_MODULE_INFORMATION;
 
typedef struct _RTL_PROCESS_MODULES
{
    ULONG NumberOfModules;
    RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, *PRTL_PROCESS_MODULES;

void set_ip_range() {
    char* info_buffer = (char*)VirtualAlloc(0, INFO_SIZE, MEM_COMMIT, PAGE_READWRITE);
    memset(info_buffer, 0xff, INFO_SIZE);
    memset(info_buffer, 0x00, INFO_SIZE);
    int pos = 0;

   LPVOID drivers[ARRAY_SIZE];
   DWORD cbNeeded;
   int cDrivers, i;
   NTSTATUS status;
   int index =0;

   if( EnumDeviceDrivers(drivers, sizeof(drivers), &cbNeeded) && cbNeeded < sizeof(drivers))
   {
        cDrivers = cbNeeded / sizeof(drivers[0]);
        PRTL_PROCESS_MODULES ModuleInfo;
 
        ModuleInfo=(PRTL_PROCESS_MODULES)VirtualAlloc(NULL,1024*1024,MEM_COMMIT|MEM_RESERVE,PAGE_READWRITE);
     
        if(!ModuleInfo){
            habort("set_ip_range: VirtualAlloc failed\n");
            goto fail;
        }
     
        if(!NT_SUCCESS(status=NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)11,ModuleInfo,1024*1024,NULL))){
            VirtualFree(ModuleInfo,0,MEM_RELEASE);
            habort("set_ip_range: NtQuerySystemInformation failed\n");
            goto fail;
        }

        pos += sprintf(info_buffer + pos, "kAFL Windows x86-64 Kernel Addresses (%d Drivers)\n\n", cDrivers);
        //_tprintf(TEXT("kAFL Windows x86-64 Kernel Addresses (%d Drivers)\n\n"), cDrivers);      
        pos += sprintf(info_buffer + pos, "START-ADDRESS\t\tEND-ADDRESS\t\tDRIVER\n");
        //_tprintf(TEXT("START-ADDRESS\t\tEND-ADDRESS\t\tDRIVER\n"));      
        for (i=0; i < cDrivers; i++ ){
            pos += sprintf(info_buffer + pos, "0x%p\t0x%lld\t%s\n", drivers[i], ((UINT64)drivers[i]) + ModuleInfo->Modules[i].ImageSize, ModuleInfo->Modules[i].FullPathName+ModuleInfo->Modules[i].OffsetToFileName);
            // hprintf("%s: driver FullPathName: %s\n", __func__, ModuleInfo->Modules[i].FullPathName);
	    if(strstr((const char*)ModuleInfo->Modules[i].FullPathName, VULN_DRIVER_NAME) > 0 || 
		strstr((const char*)ModuleInfo->Modules[i].FullPathName, VULN_DRIVER_NAME2) > 0 ||
		strstr((const char*)ModuleInfo->Modules[i].FullPathName, VULN_DRIVER_NAME3) > 0
		) {
                uint64_t buffer[3];
                buffer[0] = (UINT64)drivers[i];
                buffer[1] = (UINT64)drivers[i] + ModuleInfo->Modules[i].ImageSize;
                buffer[2] = index++;
                kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (UINT64)buffer);
		hprintf("[+] msFuzz: SET_IP_RANGE to %s\n",ModuleInfo->Modules[i].FullPathName+ModuleInfo->Modules[i].OffsetToFileName);
            }
            hprintf("0x%p\t0x%p\t%s\n", drivers[i], drivers[i]+ModuleInfo->Modules[i].ImageSize, ModuleInfo->Modules[i].FullPathName+ModuleInfo->Modules[i].OffsetToFileName);
        }
   }
   else {
        hprintf("%s: EnumDeviceDrivers failed\n", __func__);
        goto fail;
   }
   if(index >=1)
	return;
    fail:
        habort("FAIL! NO MATCH!\n");
        exit(1);
}

void init_panic_handlers() {
    UINT64 panic_kebugcheck = 0x0;
    UINT64 panic_kebugcheck2 = 0x0;
    panic_kebugcheck = resolve_KeBugCheck(kernel_func1);
    panic_kebugcheck2 = resolve_KeBugCheck(kernel_func2);
    hprintf("Submitting bug check handlers\n");
    /* submit panic address */
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_kebugcheck);
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_PANIC, panic_kebugcheck2);
}

int main(int argc, char** argv)
{
    hprintf("[+] msFuzz: loader is executed\n");
    kAFL_custom* payload_buffer = (kAFL_custom*)VirtualAlloc(0, PAYLOAD_MAX_SIZE, MEM_COMMIT, PAGE_READWRITE);

    memset(payload_buffer, 0x0, PAYLOAD_MAX_SIZE);

    /* open vulnerable driver */

    HANDLE kafl_vuln_handle = NULL;
    int i;
    int count=0;
    while(1)
    {
        // TODO change the first parameter of this function call to the device corresponding to the driver
        kafl_vuln_handle = CreateFile((LPCSTR)"\\\\.\\GLOBALROOT\\Device\\Afd",
            GENERIC_READ | GENERIC_WRITE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
            NULL
        );

        count++;

        if (kafl_vuln_handle != INVALID_HANDLE_VALUE)
            break;

        if (count % LOG_UPDATE_FREQ == 0)
            hprintf("[-] CreateFile failed: Attempt #%d, Error code: 0x%X\n", count, GetLastError());

        if (count > MAX_ATTEMPT) {
            hprintf("[-] Too many retries. Aborting...\n");
            habort("Exceeded max retry count\n");
        }

    }

    if (kafl_vuln_handle == INVALID_HANDLE_VALUE) {
        hprintf("[-] KAFL test: Cannot get device handle: 0x%X\n", GetLastError());
        habort("Cannot get device handle\n");
    } else {
        hprintf("[+] msFuzz: Entering fuzzing loop\n");
    }


    init_agent_handshake();

    //init_panic_handlers();

    /* this hypercall submits the current CR3 value */ 
    kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);

    /* submit the guest virtual address of the payload buffer */
    kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (UINT64)payload_buffer);

    // Submit PT ranges
    set_ip_range();
    char* outbuff = (CHAR*)malloc(0x10000);
    DWORD dwRet = 0;

    uint32_t *header = payload_buffer;
    uint32_t function_code;
    uint32_t IoControlCode;
    uint32_t InBufferLength;
    uint32_t OutBufferLength;
    uint8_t *inbuffer;

    // Snapshot here
    kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);

    /* request new payload (*blocking*) */
    kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0); 


    for(i=0; i< MAX_IRP_COUNT; i++)
    {
        function_code = header[0];
        IoControlCode = header[1];
        InBufferLength = header[2];
        OutBufferLength = header[3];
        inbuffer = header+4;

	if(function_code != IOCTL)
	    break; // End of IRP sequence

        DeviceIoControl(kafl_vuln_handle,
            IoControlCode,
            (LPVOID)inbuffer,
            InBufferLength,
            outbuff,
            OutBufferLength,
            NULL,
            NULL
        );

	header = inbuffer + InBufferLength;

    }
    /* inform fuzzer about finished fuzzing iteration */
    // Will reset back to start of snapshot here
    kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);
    

    return 0;
}


```

## result.json
The `result.json` is output by the [angrPT](https://github.com/0dayResearchLab/angrPT), which is the symbolic execution implementation of MsFuzz.   
AngrPT's error handling implementation could be improved (and the ablity of interface analysis is restricted by this), and we might be able to find (or write, lol) better symbolic execution implementation for a static "frontend" for MsFuzz.   

Anyway, if we are to use another symbolic execution tool for analyzing the ioctl interfaces, the `result.json` format should be compatible with the angrPT's one. And it should look like this:   

```json
[
    {
        "IoControlCode": "0x12003",
        "InBufferLength": [
            "0-5"
        ],
        "OutBufferLength": [
            "0-inf"
        ]
    },
    {
        "IoControlCode": "0x1200b",
        "InBufferLength": [
            "0-11"
        ],
        "OutBufferLength": [
            "0-inf"
        ]
    },
    {
        "IoControlCode": "0x12010",
        "InBufferLength": [
            "0-inf"
        ],
        "OutBufferLength": [
            "0-inf"
        ]
    },
]
```