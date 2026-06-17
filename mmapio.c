#include "rtcore.h"

#define RTC_MAX_MAPPINGS 256
#define RTC_HANDLE_BASE ((PVOID)0x10000000)

typedef struct _RTC_MAPPING_ENTRY {
    BOOLEAN InUse;
    PVOID KernelAddress;
    ULONG Length;
} RTC_MAPPING_ENTRY;

RTC_MAPPING_ENTRY g_Mappings[RTC_MAX_MAPPINGS];
KSPIN_LOCK g_MappingLock;

void RtcInitMappingTable(void) {
    KeInitializeSpinLock(&g_MappingLock);
    RtlZeroMemory(g_Mappings, sizeof(g_Mappings));
}

PVOID RtcAddMapping(PVOID KernelAddress, ULONG Length) {
    KIRQL irql;
    PVOID handle = NULL;
    KeAcquireSpinLock(&g_MappingLock, &irql);
    for (ULONG i = 0; i < RTC_MAX_MAPPINGS; i++) {
        if (!g_Mappings[i].InUse) {
            g_Mappings[i].KernelAddress = KernelAddress;
            g_Mappings[i].Length = Length;
            g_Mappings[i].InUse = TRUE;
            handle = (PVOID)((ULONG_PTR)RTC_HANDLE_BASE + i);
            break;
        }
    }
    KeReleaseSpinLock(&g_MappingLock, irql);
    return handle;
}

PVOID RtcGetMapping(PVOID Handle, ULONG* OutLength) {
    ULONG_PTR index = (ULONG_PTR)Handle - (ULONG_PTR)RTC_HANDLE_BASE;
    if (index >= RTC_MAX_MAPPINGS) return NULL;

    KIRQL irql;
    PVOID kernelAddress = NULL;
    KeAcquireSpinLock(&g_MappingLock, &irql);
    if (g_Mappings[index].InUse) {
        kernelAddress = g_Mappings[index].KernelAddress;
        if (OutLength) *OutLength = g_Mappings[index].Length;
    }
    KeReleaseSpinLock(&g_MappingLock, irql);
    return kernelAddress;
}

BOOLEAN RtcRemoveMapping(PVOID Handle, ULONG Length) {
    ULONG_PTR index = (ULONG_PTR)Handle - (ULONG_PTR)RTC_HANDLE_BASE;
    if (index >= RTC_MAX_MAPPINGS) return FALSE;

    KIRQL irql;
    BOOLEAN result = FALSE;
    KeAcquireSpinLock(&g_MappingLock, &irql);
    if (g_Mappings[index].InUse && g_Mappings[index].Length == Length) {
        MmUnmapIoSpace(g_Mappings[index].KernelAddress, g_Mappings[index].Length);
        g_Mappings[index].InUse = FALSE;
        result = TRUE;
    }
    KeReleaseSpinLock(&g_MappingLock, irql);
    return result;
}

// структура запроса на маппинг памяти
typedef struct _RTC_MEMORY_MAPPING {
    PHYSICAL_ADDRESS PhysicalAddress; // +0x00: Целевой физический адрес
    PVOID MappedAddress;              // +0x08: Возвращаемый виртуальный адрес
    ULONG Length;                     // +0x10: Размер региона
    ULONG Padding1;                   // +0x14: Выравнивание
    ULONG AddressSpace;               // +0x18: Пространство
    ULONG Padding2;                   // +0x1C: Выравнивание
    RTC_PCI_BAR_CONTEXT PciContext;   // +0x20: Вложенный контекст PCI
} RTC_MEMORY_MAPPING, *PRTC_MEMORY_MAPPING;

BOOLEAN RtcCheckMemoryIntersection(
    _In_ ULONG64 RequestedAddress,
    _In_ ULONG RequestedLength,
    _In_ ULONG64 AllowedBase,
    _In_ ULONG AllowedSize
)
{
    ULONG64 requestedEnd;
    ULONG64 allowedEnd;

    if (RequestedAddress >= AllowedBase) {
        requestedEnd = RequestedAddress + RequestedLength;
        allowedEnd = AllowedBase + AllowedSize;
        if (requestedEnd <= allowedEnd) {
            return TRUE;
        }
    }
    return FALSE;
}

BOOLEAN RtcValidatePhysicalAddress(
    _In_ PHYSICAL_ADDRESS PhysicalAddress,
    _In_ ULONG Length,
    _In_ PRTC_PCI_BAR_CONTEXT PciContext,
    _In_ ULONG_PTR UnknownArg 
)
{
    ULONG pciSlot;
    ULONG barOffset;
    ULONG barValue = 0;
    PHYSICAL_ADDRESS allowedBase;

    UNREFERENCED_PARAMETER(UnknownArg);

    allowedBase.QuadPart = 0xC0000; 
    if (RtcCheckMemoryIntersection(PhysicalAddress.QuadPart, Length, allowedBase.QuadPart, 0x20000)) {
        return TRUE;
    }

    if (PciContext->BarIndex < 6) {
        pciSlot = ((PciContext->FunctionNumber & 7) << 5) | (PciContext->DeviceNumber & 0x1F);
        barOffset = 0x10 + (PciContext->BarIndex * 4);

        HalGetBusDataByOffset(PCIConfiguration, PciContext->BusNumber, pciSlot, &barValue, barOffset, sizeof(ULONG));

        if (barValue != 0xFFFFFFFF && barValue != 0) {
            if ((barValue & 1) == 0) {
                allowedBase.QuadPart = barValue & 0xFFFFFF00;
                return RtcCheckMemoryIntersection(PhysicalAddress.QuadPart, Length, allowedBase.QuadPart, 0x1000000);
            }
        }
    }
    return FALSE; 
}

NTSTATUS RtcMapMemory(_In_ PRTC_MEMORY_MAPPING MappingRequest)
{
    PHYSICAL_ADDRESS translatedAddress;
    ULONG addressSpace = 0; 
    PVOID mappedAddress;

    // адрес структуры PciContext и адрес переменной addressSpace с кастом ULONG_PTR
    if (!RtcValidatePhysicalAddress(
            MappingRequest->PhysicalAddress, 
            MappingRequest->Length, 
            &MappingRequest->PciContext,
            (ULONG_PTR)&addressSpace)) 
    {
        return STATUS_UNSUCCESSFUL;
    }

    if (HalTranslateBusAddress(Isa, 0, MappingRequest->PhysicalAddress, &addressSpace, &translatedAddress)) 
    {
        mappedAddress = MmMapIoSpace(translatedAddress, MappingRequest->Length, MmNonCached);
        if (mappedAddress != NULL) {
            PVOID handle = RtcAddMapping(mappedAddress, MappingRequest->Length);
            if (handle != NULL) {
                MappingRequest->MappedAddress = handle;
                return STATUS_SUCCESS;
            } else {
                MmUnmapIoSpace(mappedAddress, MappingRequest->Length);
                return STATUS_INSUFFICIENT_RESOURCES;
            }
        }
    }
    return STATUS_INSUFFICIENT_RESOURCES;
}
