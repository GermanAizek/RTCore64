#include <ntddk.h>

#define PCI_CONFIG_ADDRESS_PORT 0xCF8
#define PCI_CONFIG_DATA_PORT    0xCFC
#define PCI_ENABLE_BIT          0x80000000 // бит 31 (Enable Configuration Space Mapping)
#define PCI_REGISTER_MASK       0xFC       // маска для битов 2-7 (смещение регистра)

// Функция валидации доступа к любым портам ввода-вывода (I/O)
BOOLEAN RtcValidateIOPortAccess(_In_ ULONG Port, _In_ BOOLEAN IsWrite)
{
    ULONG configAddress;
    ULONG registerOffset;

    // разрешаем доступ к порту адреса конфигурации PCI (0xCF8)
    if (Port == PCI_CONFIG_ADDRESS_PORT)
    {
        return TRUE;
    }

    // проверка при доступе к порту данных PCI (0xCFC)
    if (Port == PCI_CONFIG_DATA_PORT)
    {
        // при записи дополнительно защищаем критически важные регистры BAR
        if (IsWrite)
        {
            configAddress = READ_PORT_ULONG((PULONG)(ULONG_PTR)PCI_CONFIG_ADDRESS_PORT);
            if ((configAddress & PCI_ENABLE_BIT) != 0)
            {
                registerOffset = configAddress & PCI_REGISTER_MASK;

                // если попытка перезаписать Base Address Registers (BAR0 - BAR5) или CIS Pointer (0x10 - 0x27)
                // блокаем эту операцию (защита от краша и эксплойтов)
                if (registerOffset >= 0x10 && registerOffset <= 0x27)
                {
                    return FALSE;
                }
            }
        }
        // одобряем безопасную запись или любое чтение из порта данных 0xCFC
        return TRUE;
    }

    // белый список стандартных VGA портов (0x3B0 - 0x3DF)
    // Необходимы для работы программ мониторинга GPU
    if (Port >= 0x3B0 && Port <= 0x3DF)
    {
        return TRUE;
    }

    return FALSE;
}