// ==========================================
// FILE: src\Utils.cpp
// ==========================================

#include "stdafx.h"
#include "../include/Utils.h"
#include <cstdio>
#include <string>
#include <cstdarg>

namespace Utils
{
    int Message(const char* format, ...)
    {
        va_list args, args_copy;
        va_start(args, format);
        va_copy(args_copy, args);

        // 1. Двухпроходное форматирование. 
        // Передавая nullptr, мы заставляем vsnprintf не писать текст, а только ВЫЧИСЛИТЬ
        // точное количество байт, которое потребуется для итоговой строки.
        int len = vsnprintf(nullptr, 0, format, args_copy);
        va_end(args_copy);

        // Если произошла ошибка парсинга или строка пустая — прерываемся.
        if (len <= 0)
        {
            va_end(args);
            return 0;
        }

        // 2. Безопасное выделение памяти (Heap Allocation).
        // Мы НЕ используем массивы на стеке (char szMsg[20480]), так как при вызове
        // хука из глубокого вызова внутри игры стек потока может быть почти исчерпан.
        // Выделение в куче страхует нас от краша Stack Overflow при огромных дампах xrefs.
        std::string buffer(len + 1, '\0');

        // 3. Финальное форматирование в точно отмеренный буфер.
        vsnprintf(&buffer[0], buffer.size(), format, args);
        va_end(args);

        // Используем MessageBoxA для явной работы с ANSI-строками (UTF-8 совместимо).
        return MessageBoxA(nullptr, buffer.c_str(), "XXXXXReverse Mod", MB_OK | MB_ICONINFORMATION);
    }

    void ODS(const char* format, ...)
    {
        va_list args, args_copy;
        va_start(args, format);
        va_copy(args_copy, args);

        // 1. Вычисляем точный размер строки (актуально для огромных логов из SymbolResolver).
        int len = vsnprintf(nullptr, 0, format, args_copy);
        va_end(args_copy);

        if (len <= 0)
        {
            va_end(args);
            return;
        }

        // 2. Выделяем память в куче с небольшим запасом:
        // len + 2 байта: (len под сам текст) + (1 байт под '\n') + (1 байт под нулевой терминатор '\0').
        std::string buffer(len + 2, '\0');

        // 3. Записываем текст в начало буфера (он займет ровно len байт).
        vsnprintf(&buffer[0], len + 1, format, args);

        // 4. Решаем проблему многопоточности (Thread-safety).
        // Если делать вызов OutputDebugString дважды (текст, затем "\n"), другой поток игры
        // может вклиниться между ними со своим логом, и строки в отладчике "разорвутся".
        // Мы склеиваем текст и перенос строки в памяти, чтобы отправить их ОДНИМ вызовом API.
        buffer[len] = '\n';
        // Символ '\0' уже находится на позиции [len + 1], так как строка заполнена нулями при создании.

        // 5. Отправляем в ядро системы монолитный блок данных.
        OutputDebugStringA(buffer.c_str());

        va_end(args);
    }
}