#include "rtcore.h"

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
            MappingRequest->MappedAddress = mappedAddress;
            return STATUS_SUCCESS;
        }
    }
    return STATUS_INSUFFICIENT_RESOURCES;
}
