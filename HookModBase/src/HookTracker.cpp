#include "stdafx.h"
#include "../include/MemoryEx.h"
#include "../include/Utils.h"
#include "../include/SymbolResolver.h"

static constexpr size_t NOP_TRAP_SIZE = 5;

/// <summary>Сообщает о входе в затёртый диапазон и останавливает отладчик.</summary>
static void __cdecl NopError()
{
	Utils::Message("Execution entered a NOP range. Check the call stack at the breakpoint.");
	__debugbreak();
}

/// <summary>Проверяет дальность перехода или опкод и разрядность PUSH.</summary>
static void ValidateHookTarget(uintptr_t nAddress, uintptr_t nMethodAddress, HookType eType)
{
	if (eType == HookType::Call || eType == HookType::Jmp) {
		uint32_t dwDisplacement = 0;
		if (!MemoryEx::TryGetRel32(nAddress, nMethodAddress, dwDisplacement)) {
			throw std::invalid_argument("Hook target is outside rel32 reach");
		}
		return;
	}
	if (eType != HookType::Push) {
		return;
	}
	if (sizeof(uintptr_t) != sizeof(uint32_t)) {
		throw std::invalid_argument("HookType::Push requires an x86 process");
	}

	uint8_t byOpcode = 0;
	MemoryEx::ReadMemoryBYTES(nAddress, &byOpcode, sizeof(byOpcode));
	if (byOpcode != 0x68) {
		throw std::invalid_argument("HookType::Push requires an existing PUSH imm32");
	}
}

/// <summary>Проверяет границы и достижимость обработчика до записи патчей.</summary>
static void ValidateNopRanges(const std::vector<HijackedFunction>& vecFunctions, NopMode eNopMode)
{
	for (const auto& func : vecFunctions) {
		const bool bValid = func.end_address > func.start_address &&
			func.size == func.end_address - func.start_address;
		assert(bValid && "Invalid NOP range");
		if (!bValid) {
			throw std::invalid_argument("Invalid NOP range");
		}

		if (eNopMode == NopMode::BreakOnEntry && func.size >= NOP_TRAP_SIZE) {
			uint32_t dwDisplacement = 0;
			const uintptr_t nHandlerAddress = reinterpret_cast<uintptr_t>(&NopError);
			if (!MemoryEx::TryGetRel32(func.start_address, nHandlerAddress, dwDisplacement)) {
				throw std::invalid_argument("NOP trap handler is outside CALL rel32 reach");
			}
		}
	}
}

/// <summary>Заполняет диапазон NOP и при необходимости ставит ловушку на входе.</summary>
static void WriteNopRange(const HijackedFunction& stFunction, NopMode eNopMode)
{
	if (eNopMode == NopMode::BreakOnEntry && stFunction.size >= NOP_TRAP_SIZE) {
		MemoryEx::WriteInstructionCall(stFunction.start_address, reinterpret_cast<uintptr_t>(&NopError),
			stFunction.end_address);
	}
	else {
		MemoryEx::NOPMemory(stFunction.start_address, stFunction.size);
	}
}

/// <summary>
/// Вспомогательная локальная функция для простого объединения вектора строк через разделитель.
/// </summary>
static std::string join_strings(const std::vector<std::string>& vec, const std::string& separator)
{
    if (vec.empty()) return "";

    return std::accumulate(std::next(vec.begin()), vec.end(), vec[0],
        [&separator](const std::string& a, const std::string& b) {
            return a + separator + b;
        });
}

/// <summary>
/// Вспомогательная локальная функция форматирования списка адресов (callers) в структурированный 
/// многострочный древовидный вид с автоматическим разрешением символов через SymbolResolver.
/// </summary>
static std::string join_resolved_multiline(const std::vector<uintptr_t>& vec, const std::string& linePrefix, size_t perLine = 3)
{
    if (vec.empty()) return "";

    std::string result;
    // Сдвиг вправо, чтобы выровнять адреса под заголовок "(Called from: "
    std::string indent = "\n       " + linePrefix + "               ";

    for (size_t i = 0; i < vec.size(); ++i) {
        std::string name = SymbolResolver::Instance().Resolve(vec[i]);

        // Используем выравнивание по левому краю шириной в 64 символа для поддержки длинных имен из IDA
        char buf[64];
        snprintf(buf, sizeof(buf), "%-64s", name.c_str());
        result += buf;

        if (i < vec.size() - 1) {
            result += ", ";

            // Перенос строки при достижении лимита колонок (perLine)
            if ((i + 1) % perLine == 0) {
                result += indent;
            }
        }
    }
    return result;
}

void HookTracker::InstallHook(uintptr_t nAddress, HookType eType, uintptr_t nMethodAddress,
	const std::string& strName, const std::vector<HijackedFunction>& vecFunctions, NopMode eNopMode)
{
	ValidateHookTarget(nAddress, nMethodAddress, eType);
	ValidateNopRanges(vecFunctions, eNopMode);

	HookRecord stRecord;
	stRecord.address = nAddress;
	stRecord.type = eType;
	stRecord.name = strName;
	stRecord.totalBytesIntercepted = 0;

	// 1. Вычисляем размер изменяемой области для базовой установки хука.
	// VTable хранит адрес нативной ширины. Инструкции занимают пять байт.
	const size_t nHookSize = (eType == HookType::VTable) ? sizeof(uintptr_t) : 5;
	size_t nHijackedBytes = 0;

	for (const auto& stFunction : vecFunctions) {
		nHijackedBytes += stFunction.size;
	}
	stRecord.totalBytesIntercepted = nHookSize + nHijackedBytes;

	// 2. Читаем и сохраняем оригинальные байты хука для отката в будущем
	stRecord.originalHookBytes.resize(nHookSize);
	MemoryEx::ReadMemoryBYTES(nAddress, stRecord.originalHookBytes.data(), nHookSize);

	// 3. Записываем команду перехода (устанавливаем хук)
	switch (eType) {
	case HookType::Call:
		MemoryEx::WriteInstructionCall(nAddress, nMethodAddress, 0);
		break;
	case HookType::Jmp:
		MemoryEx::WriteInstructionJmp(nAddress, nMethodAddress, 0);
		break;
	case HookType::VTable:
		MemoryEx::WriteMemoryBYTES(nAddress, &nMethodAddress, sizeof(nMethodAddress));
		break;
	case HookType::Push:
		MemoryEx::WriteInstructionPushImm32(nAddress, static_cast<uint32_t>(nMethodAddress));
		break;
	}

	// Логируем установку основной точки входа
	Utils::ODS("- [HOOK] %s @ 0x%08X (Total hijacked: %zu bytes)", strName.c_str(), nAddress, stRecord.totalBytesIntercepted);

	// 4. Обрабатываем и затираем (NOP) оригинальные вызовы функций, которые теперь не нужны
	for (const auto& stFunction : vecFunctions) {
		// Выводим древовидную схему NOP-регионов
		Utils::ODS("  %s- [NOP] %s @ 0x%08X-0x%08X (%zu bytes)",
			&stFunction == &vecFunctions.back() ? "\\_" : "|-",
			stFunction.name.c_str(),
			stFunction.start_address,
			stFunction.end_address,
			stFunction.size);

		SavedNop stSavedNop;
		stSavedNop.address = stFunction.start_address;
		stSavedNop.name = stFunction.name;
		stSavedNop.originalBytes.resize(stFunction.size);

		// Безопасно сохраняем затираемые байты оригинального кода
		MemoryEx::ReadMemoryBYTES(stFunction.start_address, stSavedNop.originalBytes.data(), stFunction.size);

		// Заполняем диапазон в выбранном режиме.
		WriteNopRange(stFunction, eNopMode);

		stRecord.savedNops.push_back(std::move(stSavedNop));
	}

	m_totalBytes += stRecord.totalBytesIntercepted;
	m_records.push_back(std::move(stRecord));

	Utils::ODS("[hooked 0x%08X: %zu байт] %s", nAddress, stRecord.totalBytesIntercepted, strName.c_str());
}

void HookTracker::InstallHook(const std::vector<HookTarget>& vecTargets, uintptr_t nDefaultMethodAddress,
	const std::string& strName, const std::vector<HijackedFunction>& vecFunctions, NopMode eNopMode)
{
	if (vecTargets.empty()) {
		return;
	}

	for (const auto& stTarget : vecTargets) {
		const uintptr_t nMethodAddress = stTarget.custom_method ? stTarget.custom_method : nDefaultMethodAddress;
		ValidateHookTarget(stTarget.address, nMethodAddress, stTarget.type);
	}
	ValidateNopRanges(vecFunctions, eNopMode);

	std::vector<SavedNop> vecSavedNops;
	size_t nHijackedBytes = 0;

	// --- 1. Обработка и логирование NOP-регионов (единожды на всю группу хуков) ---
	for (const auto& stFunction : vecFunctions) {
		nHijackedBytes += stFunction.size;

		Utils::ODS("  %s- [NOP] %s @ 0x%08X-0x%08X (%zu bytes)",
			&stFunction == &vecFunctions.back() ? "\\_" : "|-",
			stFunction.name.c_str(),
			stFunction.start_address,
			stFunction.end_address,
			stFunction.size);

		SavedNop stSavedNop;
		stSavedNop.address = stFunction.start_address;
		stSavedNop.name = stFunction.name;
		stSavedNop.originalBytes.resize(stFunction.size);

		// Сохраняем исходные байты перед заполнением диапазона.
		MemoryEx::ReadMemoryBYTES(stFunction.start_address, stSavedNop.originalBytes.data(), stFunction.size);
		WriteNopRange(stFunction, eNopMode);

		vecSavedNops.push_back(std::move(stSavedNop));

		// Вычисляем графические символы ветвей для вывода дерева вызовов
		bool bLastFunction = (&stFunction == &vecFunctions.back());
		std::string strBranch = bLastFunction ? " " : "|";

		// Определяем список адресов вызова (callers)
		std::vector<uintptr_t> vecCallerAddresses = stFunction.callers;
		if (vecCallerAddresses.empty()) {
			for (const auto& stCaller : vecTargets) {
				vecCallerAddresses.push_back(stCaller.address);
			}
		}

		if (!vecCallerAddresses.empty()) {
			// Выводим отформатированное дерево вызовов (по 4 имени на строку)
			std::string strCallers = join_resolved_multiline(vecCallerAddresses, strBranch, 4);
			Utils::ODS("  %s      (Called from: %s)", strBranch.c_str(), strCallers.c_str());
		}
	}

	// --- 2. Циклическая установка хуков по списку целей ---
	bool bFirstRecord = true;

	for (const auto& stTarget : vecTargets) {
		HookRecord stRecord;
		stRecord.address = stTarget.address;
		stRecord.type = stTarget.type;
		stRecord.name = strName;

		// Определяем адрес метода-замены (кастомный для цели или глобальный по умолчанию)
		uintptr_t nMethodAddress = (stTarget.custom_method != 0) ? stTarget.custom_method : nDefaultMethodAddress;
		const size_t nHookSize = (stTarget.type == HookType::VTable) ? sizeof(uintptr_t) : 5;

		// NOP-регионы привязываем только к ПЕРВОЙ записи группы, чтобы RestoreAll не восстанавливал их повторно
		if (bFirstRecord) {
			stRecord.totalBytesIntercepted = nHookSize + nHijackedBytes;
			stRecord.savedNops = std::move(vecSavedNops);
			bFirstRecord = false;
		}
		else {
			stRecord.totalBytesIntercepted = nHookSize;
		}

		// Читаем оригинальные байты кода перед изменением
		stRecord.originalHookBytes.resize(nHookSize);
		MemoryEx::ReadMemoryBYTES(stTarget.address, stRecord.originalHookBytes.data(), nHookSize);

		// Записываем ассемблерную команду перехода в память процесса
		switch (stTarget.type) {
		case HookType::Call:
			MemoryEx::WriteInstructionCall(stTarget.address, nMethodAddress, 0);
			break;
		case HookType::Jmp:
			MemoryEx::WriteInstructionJmp(stTarget.address, nMethodAddress, 0);
			break;
		case HookType::VTable:
			MemoryEx::WriteMemoryBYTES(stTarget.address, &nMethodAddress, sizeof(nMethodAddress));
			break;
		case HookType::Push:
			MemoryEx::WriteInstructionPushImm32(stTarget.address, static_cast<uint32_t>(nMethodAddress));
			break;
		}

		m_totalBytes += stRecord.totalBytesIntercepted;
		m_records.push_back(std::move(stRecord));
	}
}

void HookTracker::RestoreAll()
{
    // Восстанавливаем оригинальное состояние памяти в обратном порядке (LIFO)
    for (auto it = m_records.rbegin(); it != m_records.rend(); ++it)
    {
        // 1. Восстанавливаем за-NOP-ленные ранее участки функций (обратный порядок внутри хука)
        for (auto nopIt = it->savedNops.rbegin(); nopIt != it->savedNops.rend(); ++nopIt)
        {
            MemoryEx::WriteMemoryBYTES(nopIt->address, nopIt->originalBytes.data(), nopIt->originalBytes.size());
        }

        // 2. Восстанавливаем байты самой инструкции перехода хука
        MemoryEx::WriteMemoryBYTES(it->address, it->originalHookBytes.data(), it->originalHookBytes.size());

        Utils::ODS("[unhooked 0x%08X] %s", it->address, it->name.c_str());
    }

    m_records.clear();
    m_totalBytes = 0;
}

void HookTracker::CollectMemoryRanges(std::vector<MemoryRange>& ranges) const
{
    for (const auto& record : m_records)
    {
        ranges.push_back({ record.address, record.originalHookBytes.size(), record.type, false, record.name });

        for (const auto& nop : record.savedNops)
            ranges.push_back({ nop.address, nop.originalBytes.size(), HookType::Jmp, true, nop.name });
    }
}
void HookTracker::PrintSummary() const
{
    if (m_records.empty()) return;

    size_t total_hijacked_funcs = 0;
    // Суммируем количество всех задействованных NOP-регионов
    for (const auto& record : m_records) {
        total_hijacked_funcs += record.savedNops.size();
    }

    Utils::ODS("==================== Hook Module Summary ====================");
    Utils::ODS("  - Основных точек входа (хуков) установлено: %zu", m_records.size());
    Utils::ODS("  - Дополнительно взято под контроль (NOP) функций: %zu", total_hijacked_funcs);
    Utils::ODS("  - Общий объем перезаписанного кода в клиенте: %zu байт", m_totalBytes);
    Utils::ODS("=============================================================");
}
