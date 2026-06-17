#pragma once
#include <ntddk.h>

// Контекст PCI-устройства
typedef struct _RTC_PCI_BAR_CONTEXT {
    ULONG BusNumber;      // +0x00: Номер шины
    ULONG DeviceNumber;   // +0x04: Номер устройства
    ULONG FunctionNumber; // +0x08: Номер функции
    ULONG BarIndex;       // +0x0C: Индекс BAR регистра
} RTC_PCI_BAR_CONTEXT, *PRTC_PCI_BAR_CONTEXT;

// Прототип общей функции валидации физического адреса
BOOLEAN RtcValidatePhysicalAddress(
    _In_ PHYSICAL_ADDRESS PhysicalAddress,
    _In_ ULONG Length,
    _In_ PRTC_PCI_BAR_CONTEXT PciContext,
    _In_ ULONG_PTR UnknownArg // ULONG_PTR для совместимости с mmapsection и mmapio
);
