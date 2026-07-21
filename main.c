#include <ntddk.h>
#include <wdmsec.h>
#include "rtcore.h"

typedef struct _RTC_SECTION_MAPPING RTC_SECTION_MAPPING, *PRTC_SECTION_MAPPING;
typedef struct _RTC_MEMORY_MAPPING RTC_MEMORY_MAPPING, *PRTC_MEMORY_MAPPING;

extern NTSTATUS RtcMapMemoryViaSection(PRTC_SECTION_MAPPING MappingRequest, ULONG RequiredLength, ULONG RequiredAlignment);
extern NTSTATUS RtcMapMemory(PRTC_MEMORY_MAPPING MappingRequest);
extern BOOLEAN RtcValidatePciDataPortAccess(ULONG Port);
extern void RtcInitMappingTable(void);
extern PVOID RtcGetMapping(PVOID Handle, ULONG* OutLength);
extern BOOLEAN RtcRemoveMapping(PVOID Handle, ULONG Length);

// IOCTL 0x8000202C (GHIDRA: DAT_00013054)
ULONG g_RtcCounter = 0;

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD RtcUnload;
DRIVER_DISPATCH RtcDispatch;

// уник GUID для класса устройства (необходим для IoCreateDeviceSecure)
// {B4C8116E-7F8D-433A-8C37-A350EF4F17A2}
static const GUID GUID_DEVCLASS_RTCORE = 
{ 0xb4c8116e, 0x7f8d, 0x433a, { 0x8c, 0x37, 0xa3, 0x50, 0xef, 0x4f, 0x17, 0xa2 } };

// Функция: RtcUnload (GHIDRA: FUN_00011000)
VOID RtcUnload(_In_ PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symbolicLinkName;
    
    RtlInitUnicodeString(&symbolicLinkName, L"\\DosDevices\\RTCore64");
    IoDeleteSymbolicLink(&symbolicLinkName);
    
    if (DriverObject->DeviceObject != NULL) {
        IoDeleteDevice(DriverObject->DeviceObject);
    }
}

// RtcDispatch (GHIDRA: FUN_00011450)
NTSTATUS RtcDispatch(_In_ PDEVICE_OBJECT DeviceObject, _Inout_ PIRP Irp)
{
    PIO_STACK_LOCATION irpSp;
    PVOID systemBuffer;
    ULONG inputBufferLength;
    ULONG outputBufferLength;
    NTSTATUS status = STATUS_SUCCESS;
    ULONG_PTR information = 0;
    PULONG buffer32;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpSp = IoGetCurrentIrpStackLocation(Irp);

    // FIX CVE-2024-3745: Строгая проверка пространства имен (Namespace ACL Bypass).
    // Если пользователь запрашивает путь с суффиксом (например, \Device\RTCore64\ или \Device\RTCore64\abc),
    // мы жестко блокируем этот запрос на этапе IRP_MJ_CREATE.
    if (irpSp->MajorFunction == IRP_MJ_CREATE) {
        if (irpSp->FileObject != NULL && irpSp->FileObject->FileName.Length > 0) {
            Irp->IoStatus.Status = STATUS_OBJECT_NAME_NOT_FOUND;
            Irp->IoStatus.Information = 0;
            IoCompleteRequest(Irp, IO_NO_INCREMENT);
            return STATUS_OBJECT_NAME_NOT_FOUND;
        }
    }

    systemBuffer = Irp->AssociatedIrp.SystemBuffer;
    buffer32 = (PULONG)systemBuffer;

    inputBufferLength = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outputBufferLength = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    // если это не IRP_MJ_DEVICE_CONTROL сразу завершаем
    if (irpSp->MajorFunction != IRP_MJ_DEVICE_CONTROL) {
        Irp->IoStatus.Status = STATUS_SUCCESS;
        Irp->IoStatus.Information = 0;
        IoCompleteRequest(Irp, IO_NO_INCREMENT);
        return STATUS_SUCCESS;
    }

    // обработка IOCTL кодов
    switch (irpSp->Parameters.DeviceIoControl.IoControlCode)
    {
        case 0x80002000: // маппинг памяти через секцию PhysicalMemory
            // Предварительная проверка длины входящего буфера и наличия самого буфера
            if (inputBufferLength < 0x20 || systemBuffer == NULL) {
                status = STATUS_INVALID_PARAMETER;
                break;
            }

            status = RtcMapMemoryViaSection((PRTC_SECTION_MAPPING)systemBuffer, inputBufferLength, outputBufferLength);
            if (NT_SUCCESS(status)) {
                information = 8;
            } else {
                status = STATUS_INVALID_PARAMETER; // 0xc000000d
            }
            break;

        case 0x80002004: // анмап секции
            if (inputBufferLength < 8) {
                status = STATUS_UNSUCCESSFUL; // 0xc0000001
            } else {
                status = ZwUnmapViewOfSection(NtCurrentProcess(), *(PVOID*)systemBuffer);
            }
            break;

        case 0x80002008: // чтение из порта (BYTE)
            if (inputBufferLength == 8) {
                buffer32[1] = READ_PORT_UCHAR((PUCHAR)(ULONG_PTR)buffer32[0]);
                information = 8;
            } else status = STATUS_INVALID_PARAMETER;
            break;

        case 0x8000200C: // чтение из порта (WORD)
            if (inputBufferLength == 8) {
                buffer32[1] = READ_PORT_USHORT((PUSHORT)(ULONG_PTR)buffer32[0]);
                information = 8;
            } else status = STATUS_INVALID_PARAMETER;
            break;

        case 0x80002010: // чтение из порта (DWORD)
            if (inputBufferLength == 8) {
                buffer32[1] = READ_PORT_ULONG((PULONG)(ULONG_PTR)buffer32[0]);
                information = 8;
            } else status = STATUS_INVALID_PARAMETER;
            break;

        case 0x80002014: // запись в порт (BYTE) с валидацией PCI
            if (inputBufferLength == 8) {
                if (RtcValidatePciDataPortAccess(buffer32[0])) {
                    WRITE_PORT_UCHAR((PUCHAR)(ULONG_PTR)buffer32[0], (UCHAR)buffer32[1]);
                    information = 8;
                } else status = STATUS_INVALID_PARAMETER;
            } else status = STATUS_INVALID_PARAMETER;
            break;

        case 0x80002018: // запись в порт (WORD) с валидацией PCI
            if (inputBufferLength == 8) {
                if (RtcValidatePciDataPortAccess(buffer32[0])) {
                    WRITE_PORT_USHORT((PUSHORT)(ULONG_PTR)buffer32[0], (USHORT)buffer32[1]);
                    information = 8;
                } else status = STATUS_INVALID_PARAMETER;
            } else status = STATUS_INVALID_PARAMETER;
            break;

        case 0x8000201C: // запись в порт (DWORD) с валидацией PCI
            if (inputBufferLength == 8) {
                if (RtcValidatePciDataPortAccess(buffer32[0])) {
                    WRITE_PORT_ULONG((PULONG)(ULONG_PTR)buffer32[0], buffer32[1]);
                    information = 8;
                } else status = STATUS_INVALID_PARAMETER;
            } else status = STATUS_INVALID_PARAMETER;
            break;

        case 0x80002028: // получить версию драйвера
            if (inputBufferLength == 8) {
                buffer32[0] = 1;
                buffer32[1] = 8; // Версия 1.8
                information = 8;
            } else status = STATUS_INVALID_PARAMETER;
            break;

        case 0x8000202C: // обновление счетчика/переменной состояния
            if (inputBufferLength == 8) {
                if (buffer32[0] != 0x80000000) {
                    g_RtcCounter = buffer32[0];
                }
                g_RtcCounter += buffer32[1];
                buffer32[0] = g_RtcCounter;
                information = 8;
            } else status = STATUS_INVALID_PARAMETER;
            break;

        case 0x80002030: // чтение регистра MSR
            if (inputBufferLength == 12) {
                ULONG64 msrValue = __readmsr(buffer32[0]);
                buffer32[1] = (ULONG)(msrValue >> 32);     // High
                buffer32[2] = (ULONG)(msrValue & 0xFFFFFFFF); // Low
                information = 12;
            } else status = STATUS_INVALID_PARAMETER;
            break;

        case 0x80002034: // запись в регистр MSR
            if (inputBufferLength == 12) {
                ULONG64 msrValue = ((ULONG64)buffer32[1] << 32) | buffer32[2];
                __writemsr(buffer32[0], msrValue);
                information = 12;
            } else status = STATUS_INVALID_PARAMETER;
            break;

        case 0x80002040: // маппинг физической памяти (MmMapIoSpace)
            if (inputBufferLength == 0x30) {
                status = RtcMapMemory((PRTC_MEMORY_MAPPING)systemBuffer);
                if (NT_SUCCESS(status)) {
                    information = 0x30;
                } else {
                    status = STATUS_INSUFFICIENT_RESOURCES; // 0xc000009a
                }
            } else status = STATUS_INVALID_PARAMETER;
            break;

        case 0x80002044: // анмап физической памяти (через Handle)
            if (inputBufferLength == 0x30) {
                PVOID handle = (PVOID)(*(PULONG64)(&buffer32[2]));
                ULONG length = buffer32[4];
                if (handle == NULL) {
                    status = STATUS_INVALID_PARAMETER;
                } else {
                    if (!RtcRemoveMapping(handle, length)) {
                        status = STATUS_INVALID_PARAMETER;
                    }
                }
            } else status = STATUS_INVALID_PARAMETER;
            break;

        case 0x80002048: // чтение из замапленной памяти (через Handle)
            if (inputBufferLength == 0x30) {
                PVOID handle = (PVOID)(*(PULONG64)(&buffer32[2]));
                ULONG mapLength = 0;
                PVOID mappedAddress = RtcGetMapping(handle, &mapLength);

                if (mappedAddress == NULL) {
                    status = STATUS_INVALID_PARAMETER;
                } else {
                    ULONG accessSize = buffer32[6];
                    ULONG offset = buffer32[5]; // buffer32[5] теперь выступает как смещение внутри блока

                    // FIX: cтрого проверяем выход за границы выделенного участка
                    if (offset + accessSize > mapLength || offset + accessSize < offset) {
                        status = STATUS_ACCESS_VIOLATION;
                    } else {
                        ULONG_PTR targetAddress = (ULONG_PTR)mappedAddress + offset;

                        if (accessSize == 1) buffer32[7] = *(PUCHAR)targetAddress;
                        else if (accessSize == 2) buffer32[7] = *(PUSHORT)targetAddress;
                        else if (accessSize == 4) buffer32[7] = *(PULONG)targetAddress;

                        information = 0x30;
                    }
                }
            } else status = STATUS_INVALID_PARAMETER;
            break;

        case 0x8000204C: // запись в замапленную память (через Handle)
            if (inputBufferLength == 0x30) {
                PVOID handle = (PVOID)(*(PULONG64)(&buffer32[2]));
                ULONG mapLength = 0;
                PVOID mappedAddress = RtcGetMapping(handle, &mapLength);

                if (mappedAddress == NULL) {
                    status = STATUS_INVALID_PARAMETER;
                } else {
                    ULONG accessSize = buffer32[6];
                    ULONG offset = buffer32[5];

                    // FIX: cтрого проверяем выход за границы выделенного участка
                    if (offset + accessSize > mapLength || offset + accessSize < offset) {
                        status = STATUS_ACCESS_VIOLATION;
                    } else {
                        ULONG_PTR targetAddress = (ULONG_PTR)mappedAddress + offset;

                        if (accessSize == 1) *(PUCHAR)targetAddress = (UCHAR)buffer32[7];
                        else if (accessSize == 2) *(PUSHORT)targetAddress = (USHORT)buffer32[7];
                        else if (accessSize == 4) *(PULONG)targetAddress = buffer32[7];

                        information = 0x30;
                    }
                }
            } else status = STATUS_INVALID_PARAMETER;
            break;

        case 0x80002050: // чтение PCI конфигурации
            if (inputBufferLength == 0x18) {
                ULONG size = buffer32[4];
                if (size == 0 || size > 4) {
                    status = STATUS_INVALID_PARAMETER;
                } else {
                    ULONG slotNumber = ((buffer32[2] & 7) << 5) | (buffer32[1] & 0x1F);
                    HalGetBusDataByOffset(PCIConfiguration, buffer32[0], slotNumber, &buffer32[5], buffer32[3], size);
                    information = 0x18;
                }
            } else status = STATUS_INVALID_PARAMETER;
            break;

        case 0x80002054: // запись в PCI конфигурацию (с защитой BAR)
            if (inputBufferLength == 0x18) {
                ULONG size = buffer32[4];
                if (size == 0 || size > 4) {
                    status = STATUS_INVALID_PARAMETER;
                } else {
                    ULONG offset = buffer32[3];
                    // блокируем перезапись BAR регистров
                    if (offset < 0x10 || offset > 0x27) {
                        ULONG slotNumber = ((buffer32[2] & 7) << 5) | (buffer32[1] & 0x1F);
                        HalSetBusDataByOffset(PCIConfiguration, buffer32[0], slotNumber, &buffer32[5], offset, size);
                        information = 0x18;
                    } else {
                        status = STATUS_INVALID_PARAMETER;
                    }
                }
            } else status = STATUS_INVALID_PARAMETER;
            break;

        default:
            status = STATUS_INVALID_PARAMETER;
            break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = information;

    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

NTSTATUS DriverEntry(_In_ PDRIVER_OBJECT DriverObject, _In_ PUNICODE_STRING RegistryPath)
{
    UNREFERENCED_PARAMETER(RegistryPath);

    NTSTATUS status;
    PDEVICE_OBJECT deviceObject = NULL;
    UNICODE_STRING deviceName;
    UNICODE_STRING symbolicLinkName;

    RtcInitMappingTable();

    // SDDL Строка защиты:
    // D:P         -> Защищенный DACL (DACL Protected)
    // (A;;GA;;;SY)-> Разрешить (A) полный доступ (GA) локальной Системе (SY)
    // (A;;GA;;;BA)-> Разрешить (A) полный доступ (GA) Встроенным Администраторам (BA)

    // Любые другие пользователи (включая обычных пользователей и гостей) не смогут получить Handle
    DECLARE_CONST_UNICODE_STRING(sddlSecureString, L"D:P(A;;GA;;;SY)(A;;GA;;;BA)");

    RtlInitUnicodeString(&deviceName, L"\\Device\\RTCore64");
    RtlInitUnicodeString(&symbolicLinkName, L"\\DosDevices\\RTCore64");

    status = IoCreateDeviceSecure(
        DriverObject,
        0,
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN, // обязать требовать проверку безопасности при открытии дескрипторов
        FALSE,
        &sddlSecureString,
        &GUID_DEVCLASS_RTCORE,
        &deviceObject
    );

    if (NT_SUCCESS(status))
    {
        status = IoCreateSymbolicLink(&symbolicLinkName, &deviceName);

        if (NT_SUCCESS(status))
        {
            DriverObject->MajorFunction[IRP_MJ_CREATE]         = RtcDispatch;
            DriverObject->MajorFunction[IRP_MJ_CLOSE]          = RtcDispatch;
            DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RtcDispatch;
            DriverObject->DriverUnload                         = RtcUnload;

            return STATUS_SUCCESS;
        }
        else
        {
            // fixed IoDevice leak if create symbolic link failed (OpenRTCore64 feature)
            IoDeleteDevice(deviceObject);
        }
    }

    return status;
}
