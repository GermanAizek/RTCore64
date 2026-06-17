#include <ntddk.h>

#define PCI_CONFIG_ADDRESS_PORT 0xCF8
#define PCI_CONFIG_DATA_PORT    0xCFC
#define PCI_ENABLE_BIT          0x80000000 // бит 31 (Enable Configuration Space Mapping)
#define PCI_REGISTER_MASK       0xFC       // маска для битов 2-7 (смещение регистра)

// fcn_00011420 Валидация доступа к порту конфигурации PCI данных (0xCFC)
BOOLEAN RtcValidatePciDataPortAccess(_In_ ULONG Port)
{
    ULONG configAddress;
    ULONG registerOffset;

    // чекаем идет ли обращение именно к порту данных PCI (0xCFC)
    if (Port == PCI_CONFIG_DATA_PORT) 
    {
        // парсим текущее значение из порта адреса (0xCF8), чтобы узнать какой регистр PCI выбран в данный момент
        // аналог ассемблер: (dx = 0xcf8; in eax, dx;)
        configAddress = READ_PORT_ULONG((PULONG)(ULONG_PTR)PCI_CONFIG_ADDRESS_PORT);

        // сверяем бит включения (31 бит). Если он не установлен, механизм конфигурации PCI неактивен
        if ((configAddress & PCI_ENABLE_BIT) != 0) 
        {
            // извлекаем смещение регистра внутри конфигурационного пространства
            // маска 0xFC (11111100b) отбрасывает лишние биты, оставляя только номер регистра
            registerOffset = configAddress & PCI_REGISTER_MASK;

            // разрешаем доступ только если смещение находится в диапазоне 0x10 - 0x27
            // в стандарте PCI это пространство Base Address Registers (BAR0 - BAR5) и Cardbus CIS Pointer.
            if (registerOffset >= 0x10 && registerOffset <= 0x27) 
            {
                return FALSE; // 0: условие соблюдено (доступ разрешен)
            }
        }
    }

    // 1: Порт не 0xCFC, бит Enable снят или регистр вне диапазона BAR (доступ запрещен)
    return TRUE; 
}
