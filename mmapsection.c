#include "rtcore.h"

typedef struct _RTC_SECTION_MAPPING {
    PHYSICAL_ADDRESS PhysicalAddress; // +0x00: Запрашиваемый физический адрес
    ULONG Length;                     // +0x08: Размер маппинга
    RTC_PCI_BAR_CONTEXT PciContext;   // +0x0C: Контекст для валидации (PCI BAR)
} RTC_SECTION_MAPPING, *PRTC_SECTION_MAPPING;


NTSTATUS RtcMapMemoryViaSection(
    _Inout_ PRTC_SECTION_MAPPING MappingRequest, 
    _In_ ULONG RequiredLength, 
    _In_ ULONG RequiredAlignment
)
{
    NTSTATUS status;
    HANDLE sectionHandle = NULL;
    PVOID sectionObject = NULL;
    UNICODE_STRING physicalMemoryString;
    OBJECT_ATTRIBUTES objectAttributes;
    
    PHYSICAL_ADDRESS startBusAddress;
    PHYSICAL_ADDRESS endBusAddress;
    PHYSICAL_ADDRESS startTranslatedAddress;
    PHYSICAL_ADDRESS endTranslatedAddress;
    
    ULONG addressSpaceStart = 0;
    ULONG addressSpaceEnd = 0;
    
    PVOID mappedBaseAddress = NULL;
    LARGE_INTEGER sectionOffset;
    SIZE_T viewSize;
    ULONG_PTR pageOffset;

    if (!RtcValidatePhysicalAddress(
            MappingRequest->PhysicalAddress, 
            MappingRequest->Length, 
            &MappingRequest->PciContext, 
            (ULONG_PTR)RequiredAlignment)) // Каст к ULONG_PTR
    {
        return STATUS_UNSUCCESSFUL;
    }

    if (RequiredLength < 0x20 || RequiredAlignment < 8) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    RtlInitUnicodeString(&physicalMemoryString, L"\\Device\\PhysicalMemory");

    InitializeObjectAttributes(&objectAttributes, &physicalMemoryString, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

    status = ZwOpenSection(&sectionHandle, SECTION_ALL_ACCESS, &objectAttributes);
    if (!NT_SUCCESS(status)) return status;

    status = ObReferenceObjectByHandle(sectionHandle, SECTION_ALL_ACCESS, NULL, KernelMode, &sectionObject, NULL);
    if (!NT_SUCCESS(status)) {
        ZwClose(sectionHandle);
        return status;
    }

    startBusAddress = MappingRequest->PhysicalAddress;
    endBusAddress.QuadPart = MappingRequest->PhysicalAddress.QuadPart + MappingRequest->Length;

    if (!HalTranslateBusAddress(Isa, 0, startBusAddress, &addressSpaceStart, &startTranslatedAddress) ||
        !HalTranslateBusAddress(Isa, 0, endBusAddress, &addressSpaceEnd, &endTranslatedAddress)) 
    {
        ObDereferenceObject(sectionObject);
        ZwClose(sectionHandle);
        return STATUS_UNSUCCESSFUL;
    }

    viewSize = (SIZE_T)(endTranslatedAddress.QuadPart - startTranslatedAddress.QuadPart);
    if (viewSize == 0) {
        ObDereferenceObject(sectionObject);
        ZwClose(sectionHandle);
        return STATUS_UNSUCCESSFUL;
    }

    pageOffset = startTranslatedAddress.LowPart & (PAGE_SIZE - 1); 
    sectionOffset.QuadPart = startTranslatedAddress.QuadPart - pageOffset; 
    
    status = ZwMapViewOfSection(
        sectionHandle, 
        NtCurrentProcess(), 
        &mappedBaseAddress, 
        0, 0, 
        &sectionOffset, 
        &viewSize, 
        ViewShare, // Используем ViewShare (значение 1, как в Ghidra)
        0, 
        PAGE_READWRITE | PAGE_NOCACHE
    );

    if (NT_SUCCESS(status)) {
        MappingRequest->PhysicalAddress.QuadPart = (ULONG_PTR)mappedBaseAddress + pageOffset;
    }

    ObDereferenceObject(sectionObject);
    ZwClose(sectionHandle);

    return status;
}
