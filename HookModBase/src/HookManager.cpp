#include "stdafx.h"
#include "../include/Utils.h"
#include <algorithm>
#include <fstream>
#include <sstream>

namespace
{
	/// <summary>
	/// Структура для хранения информации о границах секции исполняемого файла (PE) в памяти.
	/// </summary>
	struct CodeSectionInfo
	{
		/// <summary>Начальный виртуальный адрес секции.</summary>
		uintptr_t start;
		/// <summary>Конечный виртуальный адрес секции.</summary>
		uintptr_t end;
		/// <summary>Размер секции в байтах (VirtualSize).</summary>
		size_t size;
	};

	/// <summary>
	/// Записывает 16-битное беззнаковое целое число (WORD) в файловый поток в формате Little-Endian.
	/// Необходимо для корректной генерации заголовков бинарных форматов (например, BMP).
	/// </summary>
	/// <param name="file">Открытый файловый поток вывода.</param>
	/// <param name="value">16-битное значение для записи.</param>
	static void WriteLE16(std::ofstream& file, unsigned short value)
	{
		file.put(static_cast<char>(value & 0xFF));
		file.put(static_cast<char>((value >> 8) & 0xFF));
	}

	/// <summary>
	/// Записывает 32-битное беззнаковое целое число (DWORD) в файловый поток в формате Little-Endian.
	/// </summary>
	/// <param name="file">Открытый файловый поток вывода.</param>
	/// <param name="value">32-битное значение для записи.</param>
	static void WriteLE32(std::ofstream& file, unsigned int value)
	{
		file.put(static_cast<char>(value & 0xFF));
		file.put(static_cast<char>((value >> 8) & 0xFF));
		file.put(static_cast<char>((value >> 16) & 0xFF));
		file.put(static_cast<char>((value >> 24) & 0xFF));
	}

	/// <summary>
	/// Динамически парсит PE-заголовок текущего процесса и возвращает границы секции, содержащей исполняемый код (.text).
	/// </summary>
	/// <returns>Структура CodeSectionInfo с границами исполняемого кода.</returns>
	static CodeSectionInfo GetExeCodeSectionInfo()
	{
		CodeSectionInfo info = {};
		HMODULE hModule = GetModuleHandle(NULL);
		if (!hModule)
			return info;

		PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
		if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
			return info;

		PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(reinterpret_cast<BYTE*>(hModule) + pDosHeader->e_lfanew);
		if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE)
			return info;

		PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
		for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; ++i, ++pSection)
		{
			if ((pSection->Characteristics & IMAGE_SCN_CNT_CODE) == 0)
				continue;

			uintptr_t sectionStart = reinterpret_cast<uintptr_t>(hModule) + pSection->VirtualAddress;
			uintptr_t sectionEnd = sectionStart + pSection->Misc.VirtualSize;

			if (info.start == 0 || sectionStart < info.start)
				info.start = sectionStart;
			if (sectionEnd > info.end)
				info.end = sectionEnd;
		}

		if (info.start != 0 && info.end > info.start)
			info.size = info.end - info.start;

		return info;
	}

	/// <summary>
	/// Получает абсолютный путь к директории, в которой находится исполняемый файл процесса (без имени самого EXE).
	/// </summary>
	/// <returns>Строка с путем к директории.</returns>
	static std::string GetExeDirectory()
	{
		char path[MAX_PATH] = {};
		DWORD length = GetModuleFileNameA(NULL, path, MAX_PATH);
		if (length == 0 || length >= MAX_PATH)
			return ".";

		char* slash = strrchr(path, '\\');
		if (!slash)
			return ".";

		*slash = '\0';
		return path;
	}

	/// <summary>
	/// Закрашивает горизонтальную линию пикселей на холсте изображения (RGB) заданным цветом.
	/// </summary>
	/// <param name="image">Вектор, представляющий сырые данные пикселей изображения (RGB).</param>
	/// <param name="width">Ширина изображения в пикселях.</param>
	/// <param name="height">Высота изображения в пикселях.</param>
	/// <param name="firstPixel">Индекс начального пикселя для закраски.</param>
	/// <param name="lastPixel">Индекс конечного пикселя для закраски.</param>
	/// <param name="r">Интенсивность красного канала (0-255).</param>
	/// <param name="g">Интенсивность зеленого канала (0-255).</param>
	/// <param name="b">Интенсивность синего канала (0-255).</param>
	static void PaintRange(std::vector<unsigned char>& image, int width, int height, size_t firstPixel, size_t lastPixel, unsigned char r, unsigned char g, unsigned char b)
	{
		const size_t pixelCount = static_cast<size_t>(width) * static_cast<size_t>(height);
		if (firstPixel >= pixelCount)
			return;

		if (lastPixel >= pixelCount)
			lastPixel = pixelCount - 1;

		for (size_t pixel = firstPixel; pixel <= lastPixel; ++pixel)
		{
			size_t offset = pixel * 3;
			image[offset + 0] = b;
			image[offset + 1] = g;
			image[offset + 2] = r;
		}
	}

	/// <summary>
	/// Сохраняет массив пикселей в файл изображения формата BMP (24-bit TrueColor) без сжатия.
	/// Автоматически вычисляет необходимые отступы (padding) для строк пикселей.
	/// </summary>
	/// <param name="path">Путь к сохраняемому файлу (например, "map.bmp").</param>
	/// <param name="image">Вектор сырых данных изображения (в формате BGR).</param>
	/// <param name="width">Ширина изображения в пикселях.</param>
	/// <param name="height">Высота изображения в пикселях.</param>
	/// <returns>True, если файл успешно записан; иначе False.</returns>
	static bool WriteBmp24(const std::string& path, const std::vector<unsigned char>& image, int width, int height)
	{
		std::ofstream file(path.c_str(), std::ios::binary);
		if (!file)
			return false;

		const unsigned int rowSize = static_cast<unsigned int>((width * 3 + 3) & ~3);
		const unsigned int pixelDataSize = rowSize * static_cast<unsigned int>(height);
		const unsigned int fileHeaderSize = 14;
		const unsigned int dibHeaderSize = 40;
		const unsigned int pixelDataOffset = fileHeaderSize + dibHeaderSize;

		file.put('B');
		file.put('M');
		WriteLE32(file, pixelDataOffset + pixelDataSize);
		WriteLE16(file, 0);
		WriteLE16(file, 0);
		WriteLE32(file, pixelDataOffset);

		WriteLE32(file, dibHeaderSize);
		WriteLE32(file, static_cast<unsigned int>(width));
		WriteLE32(file, static_cast<unsigned int>(height));
		WriteLE16(file, 1);
		WriteLE16(file, 24);
		WriteLE32(file, 0);
		WriteLE32(file, pixelDataSize);
		WriteLE32(file, 0);
		WriteLE32(file, 0);
		WriteLE32(file, 0);
		WriteLE32(file, 0);

		std::vector<unsigned char> padding(rowSize - width * 3, 0);
		for (int y = height - 1; y >= 0; --y)
		{
			const unsigned char* row = &image[static_cast<size_t>(y) * static_cast<size_t>(width) * 3];
			file.write(reinterpret_cast<const char*>(row), width * 3);
			if (!padding.empty())
				file.write(reinterpret_cast<const char*>(padding.data()), padding.size());
		}

		return true;
	}

	/// <summary>
	/// Преобразует строго типизированное перечисление типа хука (HookType) в его текстовое представление.
	/// </summary>
	/// <param name="type">Значение перечисления HookType.</param>
	/// <returns>Строковое имя типа хука (например, "call", "jmp", "vtable").</returns>
	static const char* HookTypeToString(HookType type)
	{
		switch (type)
		{
		case HookType::Call: return "call";
		case HookType::Jmp: return "jmp";
		case HookType::VTable: return "vtable";
		default: return "unknown";
		}
	}

	/// <summary>
	/// Экранирует специальные управляющие символы в строке для безопасной сериализации и вставки в JSON-документ.
	/// </summary>
	/// <param name="value">Исходная неэкранированная строка.</param>
	/// <returns>Строка, готовая для использования в качестве значения в JSON.</returns>
	static std::string EscapeJsonString(const std::string& value)
	{
		std::string result;
		result.reserve(value.size() + 8);

		for (size_t i = 0; i < value.size(); ++i)
		{
			const unsigned char ch = static_cast<unsigned char>(value[i]);
			switch (ch)
			{
			case '\\': result += "\\\\"; break;
			case '"': result += "\\\""; break;
			case '\b': result += "\\b"; break;
			case '\f': result += "\\f"; break;
			case '\n': result += "\\n"; break;
			case '\r': result += "\\r"; break;
			case '\t': result += "\\t"; break;
			default:
				if (ch < 0x20)
				{
					char buffer[8];
					snprintf(buffer, sizeof(buffer), "\\u%04X", static_cast<unsigned int>(ch));
					result += buffer;
				}
				else
				{
					result += static_cast<char>(ch);
				}
				break;
			}
		}

		return result;
	}

	/// <summary>
	/// Форматирует целочисленный адрес памяти в стандартную 32-битную шестнадцатеричную строку (с префиксом 0x).
	/// </summary>
	/// <param name="value">Адрес в памяти для форматирования.</param>
	/// <returns>Отформатированная строка (например, "0x00AABBCC").</returns>
	static std::string HexAddress(uintptr_t value)
	{
		char buffer[32];
		snprintf(buffer, sizeof(buffer), "0x%08X", static_cast<unsigned int>(value));
		return buffer;
	}

	/// <summary>
	/// Генерирует JSON-файл с детальной метаинформацией обо всех установленных хуках, NOP-регионах и параметрах карты памяти.
	/// Позволяет сторонним инструментам анализировать масштаб вмешательства в процесс.
	/// </summary>
	/// <param name="path">Путь для сохранения .json файла.</param>
	/// <param name="ranges">Вектор диапазонов памяти, захваченных менеджером хуков.</param>
	/// <param name="code">Информация о границах сканируемой памяти (.text / .rdata).</param>
	/// <param name="width">Ширина сгенерированной BMP карты.</param>
	/// <param name="height">Высота сгенерированной BMP карты.</param>
	/// <param name="totalBytes">Общее количество байт, измененных модулем.</param>
	/// <returns>True при успешной генерации, иначе False.</returns>
	static bool WriteHookMemoryJson(
		const std::string& path,
		const std::vector<HookTracker::MemoryRange>& ranges,
		const CodeSectionInfo& code,
		int width,
		int height,
		size_t totalBytes)
	{
		std::ofstream file(path.c_str(), std::ios::out | std::ios::trunc);
		if (!file)
			return false;

		const size_t pixelCount = static_cast<size_t>(width) * static_cast<size_t>(height);
		const double bytesPerPixel = pixelCount > 0 ? static_cast<double>(code.size) / static_cast<double>(pixelCount) : 0.0;

		file << "{\n";
		file << "  \"version\": 1,\n";
		file << "  \"image\": {\n";
		file << "    \"width\": " << width << ",\n";
		file << "    \"height\": " << height << ",\n";
		file << "    \"bytes_per_pixel\": " << bytesPerPixel << "\n";
		file << "  },\n";
		file << "  \"code\": {\n";
		file << "    \"start\": \"" << HexAddress(code.start) << "\",\n";
		file << "    \"end\": \"" << HexAddress(code.end) << "\",\n";
		file << "    \"size\": " << code.size << "\n";
		file << "  },\n";
		file << "  \"summary\": {\n";
		file << "    \"tracked_bytes\": " << totalBytes << ",\n";
		file << "    \"range_count\": " << ranges.size() << "\n";
		file << "  },\n";
		file << "  \"ranges\": [\n";

		for (size_t i = 0; i < ranges.size(); ++i)
		{
			const HookTracker::MemoryRange& range = ranges[i];
			const uintptr_t endAddress = range.address + range.size;
			const bool intersectsText = range.size > 0 && range.address < code.end && endAddress > code.start;

			size_t pixelStart = 0;
			size_t pixelEnd = 0;
			if (intersectsText)
			{
				const uintptr_t clippedStart = range.address > code.start ? range.address : code.start;
				const uintptr_t clippedEnd = endAddress < code.end ? endAddress : code.end;
				pixelStart = static_cast<size_t>((static_cast<double>(clippedStart - code.start) / static_cast<double>(code.size)) * static_cast<double>(pixelCount));
				pixelEnd = static_cast<size_t>((static_cast<double>(clippedEnd - 1 - code.start) / static_cast<double>(code.size)) * static_cast<double>(pixelCount));
				if (pixelStart >= pixelCount) pixelStart = pixelCount - 1;
				if (pixelEnd >= pixelCount) pixelEnd = pixelCount - 1;
			}

			file << "    {\n";
			file << "      \"name\": \"" << EscapeJsonString(range.name) << "\",\n";
			file << "      \"kind\": \"" << (range.isNop ? "nop" : "hook") << "\",\n";
			file << "      \"hook_type\": \"" << HookTypeToString(range.type) << "\",\n";
			file << "      \"address\": \"" << HexAddress(range.address) << "\",\n";
			file << "      \"end\": \"" << HexAddress(endAddress) << "\",\n";
			file << "      \"size\": " << range.size << ",\n";
			file << "      \"intersects_text\": " << (intersectsText ? "true" : "false") << ",\n";
			file << "      \"pixel_start\": " << pixelStart << ",\n";
			file << "      \"pixel_end\": " << pixelEnd << "\n";
			file << "    }" << (i + 1 < ranges.size() ? "," : "") << "\n";
		}

		file << "  ]\n";
		file << "}\n";
		return true;
	}

	/// <summary>
	/// Генерирует интерактивный HTML-отчет (карту памяти) с просмотрщиком (вьювером) установленных хуков.
	/// Встраивает JSON-данные напрямую в HTML для автономной работы в браузере (без локального сервера).
	/// </summary>
	/// <param name="path">Путь для сохранения .html файла.</param>
	/// <param name="bmpFileName">Имя файла BMP-изображения для отображения на фоне холста.</param>
	/// <param name="ranges">Вектор диапазонов памяти, захваченных менеджером хуков.</param>
	/// <param name="code">Информация о границах сканируемой памяти.</param>
	/// <param name="width">Ширина сгенерированной BMP карты.</param>
	/// <param name="height">Высота сгенерированной BMP карты.</param>
	/// <param name="totalBytes">Общее количество перехваченных байт.</param>
	/// <returns>True при успешной генерации, иначе False.</returns>
	static bool WriteHookMemoryHtml(
		const std::string& path,
		const std::string& bmpFileName,
		const std::vector<HookTracker::MemoryRange>& ranges,
		const CodeSectionInfo& code,
		int width,
		int height,
		size_t totalBytes)
	{
		std::ostringstream json;
		const size_t pixelCount = static_cast<size_t>(width) * static_cast<size_t>(height);
		const double bytesPerPixel = pixelCount > 0 ? static_cast<double>(code.size) / static_cast<double>(pixelCount) : 0.0;

		json << "{\n";
		json << "  \"version\": 1,\n";
		json << "  \"image\": {\n";
		json << "    \"width\": " << width << ",\n";
		json << "    \"height\": " << height << ",\n";
		json << "    \"bytes_per_pixel\": " << bytesPerPixel << ",\n";
		json << "    \"bmp\": \"" << EscapeJsonString(bmpFileName) << "\"\n";
		json << "  },\n";
		json << "  \"code\": {\n";
		json << "    \"start\": \"" << HexAddress(code.start) << "\",\n";
		json << "    \"end\": \"" << HexAddress(code.end) << "\",\n";
		json << "    \"size\": " << code.size << "\n";
		json << "  },\n";
		json << "  \"summary\": {\n";
		json << "    \"tracked_bytes\": " << totalBytes << ",\n";
		json << "    \"range_count\": " << ranges.size() << "\n";
		json << "  },\n";
		json << "  \"ranges\": [\n";

		for (size_t i = 0; i < ranges.size(); ++i)
		{
			const HookTracker::MemoryRange& range = ranges[i];
			const uintptr_t endAddress = range.address + range.size;
			const bool intersectsText = range.size > 0 && range.address < code.end && endAddress > code.start;

			size_t pixelStart = 0;
			size_t pixelEnd = 0;
			if (intersectsText)
			{
				const uintptr_t clippedStart = range.address > code.start ? range.address : code.start;
				const uintptr_t clippedEnd = endAddress < code.end ? endAddress : code.end;
				pixelStart = static_cast<size_t>((static_cast<double>(clippedStart - code.start) / static_cast<double>(code.size)) * static_cast<double>(pixelCount));
				pixelEnd = static_cast<size_t>((static_cast<double>(clippedEnd - 1 - code.start) / static_cast<double>(code.size)) * static_cast<double>(pixelCount));
				if (pixelStart >= pixelCount) pixelStart = pixelCount - 1;
				if (pixelEnd >= pixelCount) pixelEnd = pixelCount - 1;
			}

			json << "    {\n";
			json << "      \"name\": \"" << EscapeJsonString(range.name) << "\",\n";
			json << "      \"kind\": \"" << (range.isNop ? "nop" : "hook") << "\",\n";
			json << "      \"hook_type\": \"" << HookTypeToString(range.type) << "\",\n";
			json << "      \"address\": \"" << HexAddress(range.address) << "\",\n";
			json << "      \"end\": \"" << HexAddress(endAddress) << "\",\n";
			json << "      \"size\": " << range.size << ",\n";
			json << "      \"intersects_text\": " << (intersectsText ? "true" : "false") << ",\n";
			json << "      \"pixel_start\": " << pixelStart << ",\n";
			json << "      \"pixel_end\": " << pixelEnd << "\n";
			json << "    }" << (i + 1 < ranges.size() ? "," : "") << "\n";
		}

		json << "  ]\n";
		json << "}";

		std::ofstream file(path.c_str(), std::ios::out | std::ios::trunc);
		if (!file)
			return false;

		file << R"HTML(<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Hook Memory Map</title>
<style>
:root { color-scheme: dark; --bg:#0f1115; --panel:#171a21; --panel2:#1f2430; --text:#e7edf7; --muted:#98a5b8; --line:#2a3140; --accent:#f09a2a; --accent2:#3ad975; }
* { box-sizing:border-box; }
body { margin:0; font:14px/1.4 Consolas, 'Courier New', monospace; background:radial-gradient(circle at top, #1c2230 0, #0f1115 45%, #090b10 100%); color:var(--text); }
button, input { font:inherit; }
.app { display:grid; grid-template-columns:360px 1fr; min-height:100vh; }
.sidebar { border-right:1px solid var(--line); background:rgba(20,23,30,.94); padding:16px; overflow:auto; }
.main { padding:16px; overflow:auto; }
.h1 { font-size:20px; margin:0 0 8px; }
.meta { color:var(--muted); margin-bottom:16px; }
.search { width:100%; padding:10px 12px; background:#0f131a; color:var(--text); border:1px solid var(--line); border-radius:10px; margin-bottom:12px; }
.stats { display:grid; grid-template-columns:1fr 1fr; gap:8px; margin-bottom:16px; }
.stat { padding:10px; border:1px solid var(--line); border-radius:10px; background:var(--panel); }
.stat .k { color:var(--muted); font-size:12px; }
.stat .v { font-size:16px; margin-top:4px; }
.legend { display:flex; gap:10px; flex-wrap:wrap; margin-bottom:16px; color:var(--muted); }
.legend span::before { content:''; display:inline-block; width:10px; height:10px; border-radius:2px; margin-right:6px; vertical-align:middle; }
.legend .l-vanilla::before { background:#181818; border:1px solid #2d2d2d; }
.legend .l-hook::before { background:#f09a2a; }
.legend .l-nop::before { background:#3ad975; }
.legend .l-vtable::before { background:#00ffff; }
.list { display:flex; flex-direction:column; gap:8px; }
.item { padding:10px; border:1px solid var(--line); border-radius:10px; background:var(--panel); cursor:pointer; }
.item:hover, .item.active { border-color:#5b6a82; background:var(--panel2); }
.item .name { font-weight:700; margin-bottom:3px; word-break:break-word; }
.item .sub { color:var(--muted); font-size:12px; }
.viewer-shell { border:1px solid var(--line); border-radius:14px; overflow:hidden; background:#111; box-shadow:0 20px 60px rgba(0,0,0,.35); }
.viewer-toolbar { display:flex; align-items:center; gap:8px; padding:10px 12px; background:#131722; border-bottom:1px solid var(--line); }
.viewer-toolbar button { padding:6px 10px; background:var(--panel2); color:var(--text); border:1px solid var(--line); border-radius:8px; cursor:pointer; }
.viewer-toolbar button:hover { border-color:#6d7b92; }
.viewer-toolbar .grow { flex:1; color:var(--muted); }
.viewer-viewport { position:relative; overflow:hidden; background:#0c0d11; cursor:grab; width:min(100%, 1920px); height:min(calc(100vh - 220px), 1080px); }
.viewer-viewport.dragging { cursor:grabbing; }
.viewer-stage { position:absolute; inset:0 auto auto 0; transform-origin:0 0; will-change:transform; }
.viewer-stage img, .viewer-stage canvas { display:block; width:1920px; height:1080px; }
.viewer-stage canvas { position:absolute; inset:0; }
.details { margin-top:14px; padding:12px; border:1px solid var(--line); border-radius:12px; background:var(--panel); min-height:96px; }
.details .title { font-weight:700; margin-bottom:8px; }
.details .row { color:var(--muted); margin:2px 0; word-break:break-word; }
.hint { color:var(--muted); margin-top:10px; }
@media (max-width:1100px) { .app { grid-template-columns:1fr; } .sidebar { border-right:0; border-bottom:1px solid var(--line); } .viewer-viewport { height:62vh; } }
</style>
</head>
<body>
<div class="app">
  <aside class="sidebar">
	<h1 class="h1">Hook Memory Map</h1>
	<div class="meta" id="meta"></div>
	<input class="search" id="search" placeholder="Filter by hook or function name">
	<div class="stats">
	  <div class="stat"><div class="k">Ranges</div><div class="v" id="statRanges"></div></div>
	  <div class="stat"><div class="k">Tracked Bytes</div><div class="v" id="statBytes"></div></div>
	  <div class="stat"><div class="k">Canvas</div><div class="v" id="statCanvas"></div></div>
	  <div class="stat"><div class="k">Hovered</div><div class="v" id="statHovered">0</div></div>
	</div>
	<div class="legend">
	  <span class="l-vanilla">vanilla</span>
	  <span class="l-hook">hook entry</span>
	  <span class="l-nop">nop owned</span>
	  <span class="l-vtable">vtable</span>
	</div>
	<div class="list" id="list"></div>
  </aside>
  <main class="main">
	<div class="viewer-shell">
	  <div class="viewer-toolbar">
		<button id="zoomOut" type="button">-</button>
		<button id="zoomIn" type="button">+</button>
		<button id="zoomReset" type="button">Reset</button>
		<div class="grow" id="zoomLabel"></div>
	  </div>
	  <div class="viewer-viewport" id="viewport">
		<div class="viewer-stage" id="stage">
		  <img id="mapImage" alt="Hook memory map">
		  <canvas id="overlay"></canvas>
		</div>
	  </div>
	</div>
	<div class="details" id="details">
	  <div class="title">Selection</div>
	  <div class="row">Click a range in the list or on the map.</div>
	</div>
	<div class="hint">Wheel to zoom. Drag to pan. Orange means entry hooks in code. Green means the code region is fully ours via NOP replacement.</div>
  </main>
</div>
<script id="hook-data" type="application/json">)HTML";
		file << json.str();
		file << R"HTML(</script>
<script>
const embeddedData = JSON.parse(document.getElementById('hook-data').textContent);
const image = document.getElementById('mapImage');
const canvas = document.getElementById('overlay');
const ctx = canvas.getContext('2d');
const list = document.getElementById('list');
const details = document.getElementById('details');
const search = document.getElementById('search');
const statHovered = document.getElementById('statHovered');
const meta = document.getElementById('meta');
const viewport = document.getElementById('viewport');
const stage = document.getElementById('stage');
const zoomLabel = document.getElementById('zoomLabel');
const zoomInButton = document.getElementById('zoomIn');
const zoomOutButton = document.getElementById('zoomOut');
const zoomResetButton = document.getElementById('zoomReset');

let data = embeddedData;
let filtered = [];
let activeIndex = -1;
let hoveredRanges = [];
let zoom = 1;
let panX = 0;
let panY = 0;
let isDragging = false;
let dragMoved = false;
let dragStartX = 0;
let dragStartY = 0;

function clamp(value, min, max) {
  return Math.min(Math.max(value, min), max);
}

async function loadData() {
  try {
	const response = await fetch('hook_memory_map.json', { cache: 'no-store' });
	if (!response.ok) throw new Error('fetch failed');
	data = await response.json();
  } catch (error) {
	data = embeddedData;
  }
}

function decorateData() {
  data.ranges.forEach((range, index) => {
	range.index = index;
	if (range.hook_type === 'vtable') {
	  range.color = 'rgba(0,255,255,0.40)';
	  range.stroke = '#00ffff';
	} else if (range.kind === 'nop') {
	  range.color = 'rgba(58,217,117,0.28)';
	  range.stroke = '#3ad975';
	} else {
	  range.color = 'rgba(240,154,42,0.30)';
	  range.stroke = '#f09a2a';
	}
  });
  filtered = data.ranges.slice();
}

function pixelToRect(start, end) {
  const width = data.image.width;
  const x1 = start % width;
  const y1 = Math.floor(start / width);
  const x2 = end % width;
  const y2 = Math.floor(end / width);
  return { x1, y1, x2, y2 };
}

function resizeCanvas() {
  canvas.width = data.image.width;
  canvas.height = data.image.height;
}

function applyTransform() {
  stage.style.transform = `translate(${panX}px, ${panY}px) scale(${zoom})`;
  zoomLabel.textContent = `${Math.round(zoom * 100)}% zoom`;
}

function centerView() {
  const fitScale = Math.min(viewport.clientWidth / data.image.width, viewport.clientHeight / data.image.height);
  zoom = Math.max(0.25, fitScale);
  panX = (viewport.clientWidth - data.image.width * zoom) * 0.5;
  panY = (viewport.clientHeight - data.image.height * zoom) * 0.5;
  applyTransform();
}

function focusRange(range) {
  if (!range.intersects_text) return;
  const rect = pixelToRect(range.pixel_start, range.pixel_end);
  const cx = (rect.x1 + rect.x2) * 0.5;
  const cy = (rect.y1 + rect.y2) * 0.5;
  panX = viewport.clientWidth * 0.5 - cx * zoom;
  panY = viewport.clientHeight * 0.5 - cy * zoom;
  applyTransform();
}

function drawRange(range, alphaBoost) {
  if (!range.intersects_text) return;
  const rect = pixelToRect(range.pixel_start, range.pixel_end);
  ctx.fillStyle = range.color.replace(/0\.\d+\)/, `${alphaBoost})`);
  if (rect.y1 === rect.y2) {
	ctx.fillRect(rect.x1, rect.y1, Math.max(1, rect.x2 - rect.x1 + 1), 1);
  } else {
	ctx.fillRect(rect.x1, rect.y1, data.image.width - rect.x1, 1);
	for (let y = rect.y1 + 1; y < rect.y2; y++) ctx.fillRect(0, y, data.image.width, 1);
	ctx.fillRect(0, rect.y2, rect.x2 + 1, 1);
  }
}

function renderOverlay(extraHovered = []) {
  ctx.clearRect(0, 0, canvas.width, canvas.height);
  filtered.forEach(range => drawRange(range, range.index === activeIndex ? 0.55 : 0.18));
  extraHovered.forEach(range => drawRange(range, 0.85));
}

function renderList() {
  list.innerHTML = '';
  filtered.slice(0, 500).forEach(range => {
	const el = document.createElement('div');
	el.className = 'item' + (range.index === activeIndex ? ' active' : '');
	el.innerHTML = `<div class="name">${range.name || '(unnamed)'}</div><div class="sub">${range.kind} | ${range.hook_type} | ${range.address} | ${range.size} bytes</div>`;
	el.onclick = () => {
	  activeIndex = range.index;
	  updateDetails([range]);
	  renderList();
	  renderOverlay();
	  focusRange(range);
	};
	list.appendChild(el);
  });
}

function updateStats() {
  meta.textContent = `${data.code.start} - ${data.code.end} | ${data.code.size} bytes mapped`;
  document.getElementById('statRanges').textContent = String(data.summary.range_count);
  document.getElementById('statBytes').textContent = String(data.summary.tracked_bytes);
  document.getElementById('statCanvas').textContent = `${data.image.width} x ${data.image.height}`;
}

function updateDetails(ranges) {
  if (!ranges.length) {
	details.innerHTML = '<div class="title">Selection</div><div class="row">Click a range in the list or on the map.</div>';
	return;
  }
  const primary = ranges[0];
  let html = `<div class="title">${primary.name || '(unnamed)'}</div>` +
	`<div class="row">kind: ${primary.kind}</div>` +
	`<div class="row">hook_type: ${primary.hook_type}</div>` +
	`<div class="row">address: ${primary.address} .. ${primary.end}</div>` +
	`<div class="row">size: ${primary.size} bytes</div>` +
	`<div class="row">pixel: ${primary.pixel_start} .. ${primary.pixel_end}</div>`;
  if (ranges.length > 1) {
	html += `<div class="row">overlaps here: ${ranges.length}</div>`;
	html += ranges.slice(1, 8).map(range => `<div class="row">also: ${range.name || '(unnamed)'} | ${range.address}</div>`).join('');
  }
  details.innerHTML = html;
}

function filterRanges(query) {
  const q = query.trim().toLowerCase();
  filtered = !q ? data.ranges.slice() : data.ranges.filter(range =>
	(range.name || '').toLowerCase().includes(q) ||
	range.address.toLowerCase().includes(q) ||
	range.kind.includes(q) ||
	range.hook_type.includes(q)
  );
  renderList();
  renderOverlay(hoveredRanges);
}

function eventToImagePixel(event) {
  const rect = viewport.getBoundingClientRect();
  const x = (event.clientX - rect.left - panX) / zoom;
  const y = (event.clientY - rect.top - panY) / zoom;
  return {
	x: Math.floor(x),
	y: Math.floor(y),
	inside: x >= 0 && y >= 0 && x < data.image.width && y < data.image.height
  };
}

function findRangesAtEvent(event) {
  const point = eventToImagePixel(event);
  if (!point.inside) return [];
  const pixel = point.y * data.image.width + point.x;
  return filtered.filter(range => range.intersects_text && pixel >= range.pixel_start && pixel <= range.pixel_end);
}

viewport.addEventListener('mousemove', event => {
  if (isDragging) {
	const nextPanX = event.clientX - dragStartX;
	const nextPanY = event.clientY - dragStartY;
	dragMoved = dragMoved || Math.abs(nextPanX - panX) > 1 || Math.abs(nextPanY - panY) > 1;
	panX = nextPanX;
	panY = nextPanY;
	applyTransform();
	return;
  }
  hoveredRanges = findRangesAtEvent(event);
  statHovered.textContent = String(hoveredRanges.length);
  renderOverlay(hoveredRanges);
  updateDetails(hoveredRanges.length ? hoveredRanges : (activeIndex >= 0 ? data.ranges.filter(r => r.index === activeIndex) : []));
});

viewport.addEventListener('mouseleave', () => {
  if (isDragging) return;
  hoveredRanges = [];
  statHovered.textContent = '0';
  renderOverlay();
  updateDetails(activeIndex >= 0 ? data.ranges.filter(r => r.index === activeIndex) : []);
});

viewport.addEventListener('mousedown', event => {
  isDragging = true;
  dragMoved = false;
  viewport.classList.add('dragging');
  dragStartX = event.clientX - panX;
  dragStartY = event.clientY - panY;
});

window.addEventListener('mouseup', () => {
  isDragging = false;
  viewport.classList.remove('dragging');
});

viewport.addEventListener('click', event => {
  if (dragMoved) return;
  const clicked = findRangesAtEvent(event);
  if (!clicked.length) return;
  activeIndex = clicked[0].index;
  updateDetails(clicked);
  renderList();
  renderOverlay(clicked);
});

viewport.addEventListener('wheel', event => {
  event.preventDefault();
  const rect = viewport.getBoundingClientRect();
  const beforeX = (event.clientX - rect.left - panX) / zoom;
  const beforeY = (event.clientY - rect.top - panY) / zoom;
  const factor = event.deltaY < 0 ? 1.15 : 1 / 1.15;
  const nextZoom = clamp(zoom * factor, 0.2, 24);
  panX = event.clientX - rect.left - beforeX * nextZoom;
  panY = event.clientY - rect.top - beforeY * nextZoom;
  zoom = nextZoom;
  applyTransform();
}, { passive: false });

zoomInButton.addEventListener('click', () => {
  zoom = clamp(zoom * 1.2, 0.2, 24);
  applyTransform();
});
zoomOutButton.addEventListener('click', () => {
  zoom = clamp(zoom / 1.2, 0.2, 24);
  applyTransform();
});
zoomResetButton.addEventListener('click', centerView);
search.addEventListener('input', event => filterRanges(event.target.value));
window.addEventListener('resize', () => { if (zoom <= 1.01) centerView(); else applyTransform(); });

async function init() {
  await loadData();
  decorateData();
  updateStats();
  image.src = data.image.bmp;
  image.addEventListener('load', () => {
	resizeCanvas();
	centerView();
	renderList();
	renderOverlay();
  }, { once: true });
}

init();
</script>
</body>
</html>
)HTML";
		return true;
	}

	/// <summary>
	/// Создает Python-скрипт (IDAPython) для IDA Pro. При выполнении в IDA скрипт автоматически 
	/// синхронизирует базу данных с DLL: раскрашивает адреса хуков, ставит комментарии и патчит NOP-пещеры.
	/// </summary>
	/// <param name="path">Путь сохранения Python скрипта (.py).</param>
	/// <param name="ranges">Вектор диапазонов памяти с установленными изменениями.</param>
	/// <returns>True при успешной записи файла.</returns>
	static bool WriteIdaSyncScript(const std::string& path, const std::vector<HookTracker::MemoryRange>& ranges)
	{
		std::ofstream fs(path);
		if (!fs.is_open()) return false;

		fs << "import idc\n";
		fs << "import ida_bytes\n\n";

		fs << "# Цвета в формате 0xBBGGRR (IDA использует BGR)\n";
		fs << "COLOR_NOP = 0x75D93A   # Зеленый\n";
		fs << "COLOR_HOOK = 0x2A9AF0  # Оранжевый\n\n";

		fs << "def apply_sync(addr, size, name, is_nop):\n";
		fs << "    # Красим область\n";
		fs << "    for i in range(size):\n";
		fs << "        idc.set_color(addr + i, idc.CIC_ITEM, COLOR_NOP if is_nop else COLOR_HOOK)\n";
		fs << "    \n";
		fs << "    # Если это NOP-область, затираем байты\n";
		fs << "    if is_nop:\n";
		fs << "        for i in range(size):\n";
		fs << "            ida_bytes.patch_byte(addr + i, 0x90)\n";
		fs << "    \n";
		fs << "    # Ставим комментарий в начале\n";
		fs << "    current_cmt = idc.get_cmt(addr, 0)\n";
		fs << "    new_cmt = f'[Reverse] {name}'\n";
		fs << "    if not current_cmt or new_cmt not in current_cmt:\n";
		fs << "        idc.set_cmt(addr, f'{current_cmt} | {new_cmt}' if current_cmt else new_cmt, 0)\n\n";

		fs << "print('--- XXXXXReverse: Synchronizing memory map ---')\n";

		for (const auto& range : ranges)
		{
			// Экранируем кавычки в именах на всякий случай
			std::string safeName = range.name;
			size_t pos = 0;
			while ((pos = safeName.find('\"', pos)) != std::string::npos) {
				safeName.replace(pos, 1, "\\\"");
				pos += 2;
			}

			fs << "apply_sync("
				<< std::hex << "0x" << range.address << ", "
				<< std::dec << range.size << ", "
				<< "\"" << safeName << "\", "
				<< (range.isNop ? "True" : "False") << ")\n";
		}

		fs << "print('--- XXXXXReverse: Sync Complete. Check your NOP caves! ---')\n";

		return true;
	}

	/// <summary>
	/// Создает IDC-скрипт (стандартный макрос IDA Pro) для синхронизации карты памяти и хуков.
	/// Дополнительно включает алгоритм поиска "сирот" (orphans) — функций, на которые больше нет ссылок (xref).
	/// </summary>
	/// <param name="path">Путь сохранения IDC скрипта (.idc).</param>
	/// <param name="ranges">Вектор диапазонов памяти с установленными изменениями.</param>
	/// <returns>True при успешной записи файла.</returns>
	static bool WriteIdaSyncScriptIDC(const std::string& path, const std::vector<HookTracker::MemoryRange>& ranges)
	{
		std::ofstream fs(path);
		if (!fs.is_open()) return false;

		fs << "#include <idc.idc>\n\n";

		// --- ФУНКЦИЯ 1: СИНХРОНИЗАЦИЯ С DLL ---
		fs << "// Применяет изменения из DLL (Хуки, NOP-кейвы, VTable)\n";
		fs << "static apply_sync(addr, size, name, is_nop, h_type) {\n";
		fs << "    auto i, color, current_cmt, prefix;\n";
		fs << "    if (h_type == 2) { // HookType::VTable\n";
		fs << "        color = 0xFFFF00; // Cyan\n";
		fs << "        prefix = \"[VTABLE_DLL] \";\n";
		fs << "        //patch_byte(addr + 0, 0); patch_byte(addr + 1, 0);\n";
		fs << "        //patch_byte(addr + 2, 0); patch_byte(addr + 3, 0);\n";
		fs << "    } else {\n";
		fs << "        color = is_nop ? 0x00FF00 : 0xFF00FF; // Lime / Magenta\n";
		fs << "        prefix = is_nop ? \"[NOP_CAVE] \" : \"[REVERSE] \";\n";
		fs << "        if (is_nop) {\n";
		fs << "            for (i = 0; i < size; i++) patch_byte(addr + i, 0x90);\n";
		fs << "        }\n";
		fs << "    }\n";
		fs << "    for (i = 0; i < size; i++) set_color(addr + i, CIC_ITEM, color);\n";
		fs << "    current_cmt = get_cmt(addr, 0);\n";
		fs << "    if (current_cmt == 0 || current_cmt == \"\") {\n";
		fs << "        set_cmt(addr, prefix + name, 0);\n";
		fs << "    } else if (strstr(current_cmt, name) == -1) {\n";
		fs << "        set_cmt(addr, current_cmt + \" | \" + prefix + name, 0);\n";
		fs << "    }\n";
		fs << "}\n\n";

		// --- ФУНКЦИЯ 2: ПОИСК СИРОТ (ОРФАНОВ) ---
		fs << "static find_orphans() {\n";
		fs << "    auto addr, start, end, size, name, dref;\n";
		fs << "    auto h_count, h_size, v_count, v_size;\n";
		fs << "    h_count = 0; h_size = 0; v_count = 0; v_size = 0;\n\n";
		fs << "    msg(\"\\n--- Running Orphan Discovery --- (Hard vs Virtual)\\n\");\n";
		fs << "    for (addr = NextFunction(0); addr != BADADDR; addr = NextFunction(addr)) {\n";
		fs << "        if (get_func_attr(addr, FUNCATTR_FLAGS) & FUNC_LIB) continue;\n";
		fs << "        if (get_first_cref_to(addr) == BADADDR) {\n";
		fs << "            start = get_func_attr(addr, FUNCATTR_START);\n";
		fs << "            end = get_func_attr(addr, FUNCATTR_END);\n";
		fs << "            size = end - start;\n";
		fs << "            name = get_func_name(addr);\n";
		fs << "            dref = get_first_dref_to(addr);\n";
		fs << "            if (dref == BADADDR) {\n";
		fs << "                msg(\"  [HARD]   0x%08X | %d bytes | %s\\n\", addr, size, name);\n";
		fs << "                h_count = h_count + 1;\n";       // Поправил инкремент
		fs << "                h_size = h_size + size;\n";      // Поправил сложение
		fs << "            } else {\n";
		fs << "                msg(\"  [VIRTUAL] 0x%08X | %d bytes | %s (DRef: 0x%08X)\\n\", addr, size, name, dref);\n";
		fs << "                v_count = v_count + 1;\n";       // Поправил инкремент
		fs << "                v_size = v_size + size;\n";      // Поправил сложение
		fs << "            }\n";
		fs << "        }\n";
		fs << "    }\n";
		fs << "    msg(\"\\n--- ORPHAN SUMMARY ---\\n\");\n";
		fs << "    msg(\"  HARD ORPHANS:    %d funcs, %d bytes (%.2f KB)\\n\", h_count, h_size, h_size/1024.0);\n";
		fs << "    msg(\"  VIRTUAL ORPHANS: %d funcs, %d bytes (%.2f KB)\\n\", v_count, v_size, v_size/1024.0);\n";
		fs << "    msg(\"  TOTAL RECLAIM:   %d bytes (%.2f KB)\\n\", h_size + v_size, (h_size + v_size)/1024.0);\n";
		fs << "}\n";

		// --- MAIN ---
		fs << "static main() {\n";
		fs << "    msg(\"\\n=================== XXXXXReverse Sync Engine ===================\\n\");\n";

		// Генерация вызовов для каждого диапазона
		for (const auto& range : ranges)
		{
			std::string safeName = range.name;
			size_t pos = 0;
			while ((pos = safeName.find('\"', pos)) != std::string::npos) {
				safeName.replace(pos, 1, "'");
				pos += 1;
			}

			fs << "    apply_sync("
				<< std::hex << "0x" << range.address << ", "
				<< std::dec << (range.size == 0 ? 5 : range.size) << ", "
				<< "\"" << safeName << "\", "
				<< (range.isNop ? "1" : "0") << ", "
				<< (int)range.type << ");\n";
		}

		fs << "\n    msg(\"--- Sync complete. Reanalyzing... ---\\n\");\n";
		fs << "    find_orphans();\n";
		fs << "    msg(\"================================================================\\n\");\n";
		fs << "}\n";

		return true;
	}

	/// <summary>
	/// Динамически парсит PE-заголовок текущего процесса и возвращает границы указанной секции по её имени.
	/// </summary>
	/// <param name="name">Имя секции (например, ".rdata").</param>
	/// <returns>Структура CodeSectionInfo с границами найденной секции.</returns>
	CodeSectionInfo GetSectionInfo(const char* name) {
		CodeSectionInfo info = { 0, 0, 0 };
		HMODULE hModule = GetModuleHandle(NULL);
		if (!hModule) return info;

		PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
		PIMAGE_NT_HEADERS pNtHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + pDosHeader->e_lfanew);
		PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);

		for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++) {
			if (strncmp((char*)pSection->Name, name, 8) == 0) {
				info.start = (uintptr_t)hModule + pSection->VirtualAddress;
				info.size = pSection->Misc.VirtualSize;
				info.end = info.start + info.size;
				return info;
			}
		}
		return info;
	}

	/// <summary>
	/// Главная координирующая функция генерации отчетов. Определяет границы кода/данных,
	/// вычисляет пиксельные координаты, отрисовывает BMP-карту и вызывает запись HTML, JSON и скриптов для IDA.
	/// </summary>
	/// <param name="ranges">Полный список всех регионов памяти, модифицированных менеджером хуков.</param>
	/// <param name="totalBytes">Суммарное количество измененных байт для статистики.</param>
	static void WriteHookMemoryMap(const std::vector<HookTracker::MemoryRange>& ranges, size_t totalBytes)
	{
		// 1. Получаем информацию о границах исполняемого кода и данных
		CodeSectionInfo textSec = GetExeCodeSectionInfo(); // Секция .text
		CodeSectionInfo rdataSec = GetSectionInfo(".rdata"); // Секция .rdata (нужно реализовать поиск секции)

		if (textSec.size == 0)
		{
			Utils::ODS("[HookManager] Memory map aborted: .text section not found");
			return;
		}

		// Определяем общий рабочий диапазон (от начала кода до конца данных)
		uintptr_t mapStart = textSec.start;
		uintptr_t mapEnd = (rdataSec.end > textSec.end) ? rdataSec.end : textSec.end;
		size_t fullMapSize = mapEnd - mapStart;

		// Параметры холста
		const int width = 1920;
		const int height = 1080;
		const size_t pixelCount = static_cast<size_t>(width) * static_cast<size_t>(height);
		const double bytesPerPixel = static_cast<double>(fullMapSize) / static_cast<double>(pixelCount);

		// Инициализация изображения (цвет 0x181818 - темно-серый фон)
		std::vector<unsigned char> image(pixelCount * 3, 0x18);

		size_t bytesOwned = 0;
		size_t rangesOutside = 0;

		// 2. Отрисовка всех затреканных диапазонов
		for (const auto& range : ranges)
		{
			// Пропускаем, если диапазон пустой или лежит вне границ нашего "радара"
			if (range.size == 0 || range.address >= mapEnd || range.address + range.size <= mapStart)
			{
				++rangesOutside;
				continue;
			}

			// Обрезаем диапазон под границы карты (на случай, если залезли в другие секции)
			uintptr_t clippedStart = range.address > mapStart ? range.address : mapStart;
			uintptr_t clippedEnd = range.address + range.size < mapEnd ? range.address + range.size : mapEnd;

			// Вычисляем индексы пикселей на холсте
			size_t firstPixel = static_cast<size_t>((static_cast<double>(clippedStart - mapStart) / fullMapSize) * pixelCount);
			size_t lastPixel = static_cast<size_t>((static_cast<double>(clippedEnd - 1 - mapStart) / fullMapSize) * pixelCount);

			if (range.type == HookType::VTable)
			{
				// Специфический цвет для VTable (Циановый / Aqua)
				// BGR: 0xFF, 0xFF, 0x00
				PaintRange(image, width, height, firstPixel, lastPixel, 0x00, 0xFF, 0xFF);
			}
			else if (range.isNop)
			{
				// Цвет для NOP-пещер (Зеленый / Lime)
				// BGR: 0x3A, 0xD9, 0x75
				PaintRange(image, width, height, firstPixel, lastPixel, 0x3A, 0xD9, 0x75);
			}
			else
			{
				// Цвет для точек входа хуков (Оранжевый)
				// BGR: 0xF0, 0x9A, 0x2A
				PaintRange(image, width, height, firstPixel, lastPixel, 0xF0, 0x9A, 0x2A);
			}

			bytesOwned += (clippedEnd - clippedStart);
		}

		// 3. Формирование путей к файлам отчетов
		const std::string baseDir = GetExeDirectory() + "\\";
		const std::string bmpPath = baseDir + "hook_memory_map.bmp";
		const std::string jsonPath = baseDir + "hook_memory_map.json";
		const std::string htmlPath = baseDir + "hook_memory_map.html";
		const std::string idaPath = baseDir + "ida_sync_map.py";
		const std::string idcPath = baseDir + "ida_sync_map.idc";

		// Создаем единую секцию для правильного расчета пикселей в JSON/HTML
		CodeSectionInfo mapSec = { mapStart, mapEnd, fullMapSize };

		// 4. Сохранение всех артефактов
		if (WriteBmp24(bmpPath, image, width, height))
		{
			double ownedPercent = (static_cast<double>(bytesOwned) / static_cast<double>(fullMapSize)) * 100.0;

			Utils::ODS("[HookManager] --- Memory Map Sync Successful ---");
			Utils::ODS("[HookManager] Map range: 0x%08X - 0x%08X (%zu bytes)", mapStart, mapEnd, fullMapSize);
			Utils::ODS("[HookManager] Total owned: %zu bytes (%.3f%% of mapped area)", bytesOwned, ownedPercent);

			// JSON для внешних парсеров
			WriteHookMemoryJson(jsonPath, ranges, mapSec, width, height, totalBytes);

			// Интерактивный HTML с тултипами (именами функций при наведении на пиксель)
			WriteHookMemoryHtml(htmlPath, "hook_memory_map.bmp", ranges, mapSec, width, height, totalBytes);

			// Скрипты синхронизации для IDA Pro
			if (WriteIdaSyncScript(idaPath, ranges))
				Utils::ODS("[HookManager] IDA Python script: %s", idaPath.c_str());

			if (WriteIdaSyncScriptIDC(idcPath, ranges))
				Utils::ODS("[HookManager] IDA IDC script: %s", idcPath.c_str());

			Utils::ODS("[HookManager] Image saved: %s (%.2f bytes/pixel)", bmpPath.c_str(), bytesPerPixel);
		}
		else
		{
			Utils::ODS("[HookManager] FAILED to write BMP memory map to %s", bmpPath.c_str());
		}
	}
}

//===========

/// <summary>
/// Находит размер секций кода (.text) основного исполняемого файла процесса в памяти.
/// Помогает динамически вычислить точный процент замещенного кода без жестких констант.
/// </summary>
/// <returns>Суммарный размер исполняемого кода в байтах или 0 в случае ошибки чтения PE-заголовка.</returns>
static size_t GetExeCodeSize()
{
	// Получаем базовый адрес (HMODULE) текущего процесса (нашего EXE)
	HMODULE hModule = GetModuleHandle(nullptr);
	if (!hModule) return 0;

	// Читаем и проверяем заголовок DOS
	PIMAGE_DOS_HEADER pDosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(hModule);
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE) return 0;

	// Читаем и проверяем заголовок NT (PE)
	PIMAGE_NT_HEADERS pNtHeaders = reinterpret_cast<PIMAGE_NT_HEADERS>(
		reinterpret_cast<uint8_t*>(hModule) + pDosHeader->e_lfanew
		);
	if (pNtHeaders->Signature != IMAGE_NT_SIGNATURE) return 0;

	// Переходим к первой секции таблицы секций
	PIMAGE_SECTION_HEADER pSection = IMAGE_FIRST_SECTION(pNtHeaders);
	size_t totalCodeSize = 0;

	// Проходим по всем секциям PE-файла (.text, .rdata, .data и т.д.)
	for (WORD i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++, pSection++)
	{
		// Суммируем размеры только тех секций, которые содержат исполняемый код (IMAGE_SCN_CNT_CODE)
		if (pSection->Characteristics & IMAGE_SCN_CNT_CODE)
		{
			// VirtualSize указывает на реальный размер кода секции, развернутой в памяти
			totalCodeSize += pSection->Misc.VirtualSize;
		}
	}

	return totalCodeSize;
}

void HookManager::RegisterModule(std::unique_ptr<IHookModule> module)
{
	m_modules.push_back(std::move(module));
}


void HookManager::InitAll()
{
	// 1. Проходим по всем модулям и инициализируем их
	for (const auto& mod : m_modules)
	{
		if (!mod->Init())
		{
			Utils::ODS("[HookManager] FAILED to initialize module '%s'.\n", mod->GetName());
		}
	}

	// 2. Получаем размер исполняемого кода игры программно
	size_t exeCodeSize = GetExeCodeSize();

	// Если по какой-то причине программно получить не вышло, можно подставить хардкод из IDA
	if (exeCodeSize == 0) {
		exeCodeSize = 1024 * 1024 * 5; // Например, 5 МБ
	}

	// 3. Собираем статистику
	size_t total_replaced_bytes = 0;
	std::vector<HookTracker::MemoryRange> memoryRanges;

	Utils::ODS("=================== ГЛОБАЛЬНАЯ СТАТИСТИКА ЗАМЕЩЕНИЯ ===================");

	// Проходимся вторым циклом
	for (const auto& mod : m_modules)
	{
		size_t mod_bytes = mod->GetReplacedBytes();
		total_replaced_bytes += mod_bytes;
		mod->CollectHookMemoryRanges(memoryRanges);

		Utils::ODS("[HookManager] Модуль `%-15s`\tЗаменено байт в EXE: %zu", mod->GetName(), mod_bytes);
	}

	// 4. Считаем процент "захвата"
	// Защита от деления на ноль на всякий случай
	double percentage = (exeCodeSize > 0) ? (static_cast<double>(total_replaced_bytes) / exeCodeSize) * 100.0 : 0.0;

	Utils::ODS("-----------------------------------------------------------------------");
	Utils::ODS("[HookManager] Суммарно заменено байт в EXE: %zu = (%.3f%%)", total_replaced_bytes, percentage);
	WriteHookMemoryMap(memoryRanges, total_replaced_bytes);
	Utils::ODS("=======================================================================\n");
}

void HookManager::ShutdownAll()
{
	// Выгружаем модули строго в ОБРАТНОМ порядке (LIFO), чтобы избежать проблем 
	// с перекрестными зависимостями модулей во время деинициализации
	for (auto it = m_modules.rbegin(); it != m_modules.rend(); ++it)
	{
		Utils::ODS("[HookManager] Shutting down module '%s'...\n", (*it)->GetName());
		(*it)->Shutdown();
	}
	m_modules.clear();
}