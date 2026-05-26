#pragma once
#include <string>
#include <map>
#include <cstdio>
#include <fstream>
#include <sstream>
#include <vector>
#include "Utils.h"

/// <summary>
/// Класс для сопоставления адресов памяти с именами функций из IDA Pro (Symbolic Resolver).
/// Реализован на основе паттерна Синглтон (Singleton), предоставляя общую карту символов для всей DLL.
/// </summary>
class SymbolResolver
{
public:
    /// <summary>
    /// Возвращает единственный глобальный экземпляр класса SymbolResolver.
    /// </summary>
    /// <returns>Ссылка на единственный экземпляр SymbolResolver.</returns>
    static SymbolResolver& Instance()
    {
        static SymbolResolver instance;
        return instance;
    }

    /// <summary>
    /// Структура, содержащая метаданные об импортированной функции.
    /// </summary>
    struct SymbolInfo {
        /// <summary>Размер функции в байтах.</summary>
        size_t size;
        /// <summary>Символьное имя функции.</summary>
        std::string name;
    };

    /// <summary>
    /// Добавляет информацию о функции в локальную базу символов.
    /// </summary>
    /// <param name="start_addr">Начальный виртуальный адрес функции (RVA или абсолютный).</param>
    /// <param name="size">Размер функции в байтах.</param>
    /// <param name="name">Символьное имя функции.</param>
    void AddSymbol(uintptr_t start_addr, size_t size, std::string name)
    {
        m_symbols[start_addr] = { size, std::move(name) };
    }

    /// <summary>
    /// Определяет имя функции по любому адресу внутри ее границ.
    /// Если адрес находится внутри тела функции, возвращает строку в формате "FunctionName+0xOffset".
    /// Если символ не найден, возвращает шестнадцатеричное строковое представление адреса.
    /// </summary>
    /// <param name="address">Виртуальный адрес для сопоставления.</param>
    /// <returns>Строка с именем функции и смещением, либо шестнадцатеричный адрес.</returns>
    std::string Resolve(uintptr_t address) const
    {
        if (m_symbols.empty()) {
            return FormatHex(address);
        }

        // upper_bound ищет первый элемент, ключ которого строго больше address
        auto it = m_symbols.upper_bound(address);

        // Если это не самый первый элемент, мы можем сделать шаг назад
        if (it != m_symbols.begin())
        {
            --it;
            uintptr_t func_start = it->first;
            const SymbolInfo& info = it->second;

            // Проверяем, попадает ли переданный адрес в диапазон размера функции
            if (address >= func_start && address < func_start + info.size)
            {
                size_t offset = address - func_start;
                if (offset == 0) {
                    return info.name; // Прямое попадание на точку входа
                }
                else {
                    // Форматируем в стиле "MethodName+0xOffset"
                    char buf[256];
                    snprintf(buf, sizeof(buf), "%s+0x%X", info.name.c_str(), (unsigned int)offset);
                    return std::string(buf);
                }
            }
        }

        // Если адрес не попал ни в один зарегистрированный диапазон функций
        return FormatHex(address);
    }

    /// <summary>
    /// Загружает и парсит список функций (карту символов) из текстового файла экспорта IDA Pro.
    /// Ожидает формат экспорта текстовой таблицы IDA с разделением табуляцией (\t).
    /// </summary>
    /// <param name="filepath">Путь к файлу экспорта символов (например, "ida_exports.txt").</param>
    /// <returns>True, если файл успешно прочитан и обработан; иначе False.</returns>
    bool LoadFromFile(const std::string& filepath)
    {
        std::ifstream file(filepath);
        if (!file.is_open()) {
            Utils::Message("[SymbolResolver] Не удалось открыть файл символов: %s\n", filepath.c_str());
            return false;
        }

        std::string line;
        size_t loaded_count = 0;

        while (std::getline(file, line)) {
            // Пропускаем пустые строки и заголовок таблицы функций IDA
            if (line.empty() || line.find("Function name") != std::string::npos) {
                continue;
            }

            std::istringstream iss(line);
            std::string name, segment, start_str, length_str;

            // IDA экспортирует данные таблицы через табуляцию (\t). 
            // Читаем первые 4 колонки: 1. Имя, 2. Сегмент, 3. Начало, 4. Длина
            if (std::getline(iss, name, '\t') &&
                std::getline(iss, segment, '\t') &&
                std::getline(iss, start_str, '\t') &&
                std::getline(iss, length_str, '\t'))
            {
                if (start_str.empty() || length_str.empty()) continue;

                try {
                    // Конвертируем HEX-строки из таблицы IDA в числа
                    uintptr_t start_addr = std::stoull(start_str, nullptr, 16);
                    size_t length = std::stoull(length_str, nullptr, 16);

                    AddSymbol(start_addr, length, name);
                    loaded_count++;
                }
                catch (...) {
                    // Игнорируем ошибки парсинга невалидных строк
                    continue;
                }
            }
        }

        Utils::ODS("[SymbolResolver] Успешно загружено %zu символов из %s\n", loaded_count, filepath.c_str());
        return true;
    }

private:
    /// <summary>
    /// Закрытый конструктор синглтона.
    /// </summary>
    SymbolResolver() = default;

    /// <summary>
    /// База данных символов, сопоставляющая адрес начала функции с метаданными.
    /// </summary>
    std::map<uintptr_t, SymbolInfo> m_symbols;

    /// <summary>
    /// Вспомогательный метод для форматирования адреса в шестнадцатеричный вид.
    /// </summary>
    /// <param name="addr">Адрес для форматирования.</param>
    /// <returns>Форматированная строка адреса.</returns>
    std::string FormatHex(uintptr_t addr) const {
        char buf[32];
        snprintf(buf, sizeof(buf), "0x%08X", addr);
        return std::string(buf);
    }
};