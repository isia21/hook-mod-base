#include "stdafx.h"

#include "../include/utils.h"
namespace Utils {
	int Message(const char* str, ...)
	{
		char szMsg[20480];

		va_list va;
		va_start(va, str);
		vsprintf_s(szMsg, str, va);
		va_end(va);

		return MessageBox(nullptr, szMsg, __PRETTY_FUNCTION__, MB_OK);
	}
	void ODS(const char* str, ...)
	{
		char szMsg[20480];

		va_list va;
		va_start(va, str);
		vsprintf_s(szMsg, str, va);
		va_end(va);
		OutputDebugString(szMsg);
		OutputDebugString("\n");
	}
}

