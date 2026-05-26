#pragma once
#include <cstdint>
#include <windows.h>

namespace MemoryEx
{
    // =================================================================================
    // ОПЕРАЦИИ ЗАПИСИ (WRITE OPERATIONS)
    // =================================================================================

    /// <summary>Пишет массив байт по указанному адресу в памяти с автоматическим обходом защиты страниц (VirtualProtect).</summary>
    void WriteMemoryBYTES(uintptr_t address, const void* bytes, size_t size);

    /// <summary>Пишет вариативный список байт по указанному адресу.</summary>
    void WriteMemoryBYTES(uintptr_t address, size_t size, ...);

    /// <summary>Парсит HEX-строку (например, "90 90 90") и записывает эти байты в память.</summary>
    void WriteMemoryBYTES(uintptr_t address, const char* hexString);

    /// <summary>Записывает 8-байтовое значение (QWORD) в память.</summary>
    void WriteMemoryQWORD(uintptr_t address, uint64_t value);

    /// <summary>Записывает 4-байтовое значение (DWORD) в память.</summary>
    void WriteMemoryDWORD(uintptr_t address, uint32_t value);

    /// <summary>Записывает 2-байтовое значение (WORD) в память.</summary>
    void WriteMemoryWORD(uintptr_t address, uint16_t value);

    /// <summary>Записывает 1-байтовое значение (BYTE) в память.</summary>
    void WriteMemoryBYTE(uintptr_t address, uint8_t value);

    /// <summary>Заполняет область памяти инструкциями NOP (0x90) указанной длины.</summary>
    void NOPMemory(uintptr_t address, size_t size);

    /// <summary>Заполняет область памяти нулевыми байтами (0x00) указанной длины.</summary>
    void NULLMemory(uintptr_t address, size_t size);

    // =================================================================================
    // ЗАПИСЬ ИНСТРУКЦИЙ (INSTRUCTION PATCHING)
    // =================================================================================

    /// <summary>Записывает базовую ассемблерную инструкцию перехода по относительному смещению.</summary>
    void WriteInstruction(uintptr_t address, uintptr_t destination, uint8_t opcode);

    /// <summary>Записывает инструкцию перехода с опциональным заполнением NOP-ами оставшегося пространства (NopZone).</summary>
    void WriteInstruction(uintptr_t address, uintptr_t destination, size_t nopSize, uint8_t opcode);

    /// <summary>Записывает сложную инструкцию вызова CALL JMP EAX.</summary>
    void WriteInstructionCallJmpEax(uintptr_t address, uintptr_t destination, uintptr_t nopEnd = 0);

    /// <summary>Записывает инструкцию относительного вызова CALL (0xE8) по адресу.</summary>
    void WriteInstructionCall(uintptr_t address, uintptr_t destination, uintptr_t nopEnd = 0);

    /// <summary>Записывает инструкцию относительного перехода JMP (0xE9) по адресу.</summary>
    void WriteInstructionJmp(uintptr_t address, uintptr_t destination, uintptr_t nopEnd = 0);

    /// <summary>Записывает ассемблерную инструкцию MOV EAX, [moffs32].</summary>
    void WriteInstructionMov32_eax_moffs32(uintptr_t address, uintptr_t valueAddress);

    /// <summary>Записывает ассемблерную инструкцию MOV AL, [moffs8].</summary>
    void WriteInstructionMov_al_moffs8(uintptr_t address, uintptr_t valueAddress);

    /// <summary>Записывает ассемблерную инструкцию MOVZX R32, RM8.</summary>
    void WriteInstructionMovzx_r32_rm8(uintptr_t address, uintptr_t valueAddress);

    /// <summary>Записывает ассемблерную инструкцию сравнения CMP RM8, R8.</summary>
    void WriteInstructionCmp_rm8_r8(uintptr_t address, uintptr_t valueAddress, uint8_t param2);

    // =================================================================================
    // ОПЕРАЦИИ ЧТЕНИЯ (READ OPERATIONS)
    // =================================================================================

    /// <summary>Безопасно копирует байты из памяти процесса в буфер клиента.</summary>
    void ReadMemoryBYTES(uintptr_t address, void* buffer, size_t size);

    /// <summary>Безопасно читает 8-байтовое значение из памяти.</summary>
    void ReadMemoryQWORD(uintptr_t address, uint64_t* value);

    /// <summary>Безопасно читает 4-байтовое значение из памяти.</summary>
    void ReadMemoryDWORD(uintptr_t address, uint32_t* value);

    /// <summary>Безопасно читает 2-байтовое значение из памяти.</summary>
    void ReadMemoryWORD(uintptr_t address, uint16_t* value);

    /// <summary>Безопасно читает 1-байтовое значение из памяти.</summary>
    void ReadMemoryBYTE(uintptr_t address, uint8_t* value);

    /// <summary>Возвращает 8-байтовое значение по адресу.</summary>
    uint64_t ReadMemoryQWORD(uintptr_t address);

    /// <summary>Возвращает 4-байтовое значение по адресу.</summary>
    uint32_t ReadMemoryDWORD(uintptr_t address);

    /// <summary>Возвращает 2-байтовое значение по адресу.</summary>
    uint16_t ReadMemoryWORD(uintptr_t address);

    /// <summary>Возвращает 1-байтовое значение по адресу.</summary>
    uint8_t ReadMemoryBYTE(uintptr_t address);

    // =================================================================================
    // МОДИФИКАЦИЯ ЧИСЕЛ (ARITHMETIC MEMORY MODIFICATION)
    // =================================================================================

    /// <summary>Добавляет (или вычитает) значение к 8-байтовому числу в памяти.</summary>
    void ChangeMemoryQWORD(uintptr_t address, int64_t value);

    /// <summary>Добавляет (или вычитает) значение к 4-байтовому числу в памяти.</summary>
    void ChangeMemoryDWORD(uintptr_t address, int32_t value);

    /// <summary>Добавляет (или вычитает) значение к 2-байтовому числу в памяти.</summary>
    void ChangeMemoryWORD(uintptr_t address, int16_t value);

    /// <summary>Добавляет (или вычитает) значение к 1-байтовому числу в памяти.</summary>
    void ChangeMemoryBYTE(uintptr_t address, int8_t value);

    // =================================================================================
    // АНАЛИЗ ИНСТРУКЦИЙ (INSTRUCTION ANALYSIS)
    // =================================================================================

    /// <summary>Рассчитывает смещение RIP/EIP-относительного указателя в ассемблерной инструкции.</summary>
    uintptr_t ReadRIPPointer(uintptr_t address, size_t instructionSize, size_t addrPosition);

    /// <summary>Вычисляет адрес перехода по указанной инструкции относительного прыжка (JMP).</summary>
    uintptr_t ReadJumpAddress(uintptr_t address);

    /// <summary>Записывает прямой безусловный переход JMP на функцию назначения.</summary>
    uintptr_t WriteDirectJMP(uintptr_t address, uintptr_t destination);

    // =================================================================================
    // ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ И ВИРТУАЛЬНЫЕ ТАБЛИЦЫ (VTABLE & HELPERS)
    // =================================================================================

    /// <summary>Проверяет, доступен ли указанный адрес памяти для чтения (предотвращает краши процесса).</summary>
    bool IsBadReadPtr(const void* pointer);

    /// <summary>Выполняет подмену метода в таблице виртуальных функций конкретного экземпляра объекта (VTable Patching).</summary>
    void* VtableHook(void* instance, void* hook, size_t methodIndex);

    /// <summary>Выполняет подмену метода непосредственно в глобальном массиве таблицы виртуальных функций по ее адресу.</summary>
    void* VtableHook(uintptr_t vtableAddress, void* hook, size_t methodIndex);
}