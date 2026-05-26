#include "stdafx.h"
#include "../include/MemoryEx.h"

namespace MemoryEx
{
	void WriteMemoryBYTES(uintptr_t uAddress, const void* bytes, unsigned int len)
	{
		DWORD flOldProtect;
		VirtualProtect((LPVOID)uAddress, len, PAGE_WRITECOPY, &flOldProtect);
		memcpy((LPVOID)uAddress, bytes, len);
		VirtualProtect((LPVOID)uAddress, len, flOldProtect, &flOldProtect);
	}

	void WriteMemoryBYTES(uintptr_t addr, size_t len, ...)
	{
		if (len <= 0)
			return;

		BYTE* bytes = (BYTE*)alloca(len);
		va_list ap;
		va_start(ap, len);

		for (size_t i = 0; i < len; i++) { bytes[i] = va_arg(ap, BYTE); }
		va_end(ap);

		WriteMemoryBYTES(addr, bytes, len);
	}

	void WriteMemoryBYTES(uintptr_t uAddress, const char* textBytes)
	{
		std::basic_string<unsigned char> buf;
		char* end = 0;

		for (;; textBytes = end)
		{
			unsigned long value = strtoul(textBytes, &end, 16);
			if (textBytes == end)
				break;
			buf.push_back((unsigned char)value);
		}

		if (buf.size() > 0) { WriteMemoryBYTES(uAddress, buf.c_str(), buf.size()); }
	}

	void WriteMemoryQWORD(uintptr_t uAddress, unsigned __int64 value)
	{
		WriteMemoryBYTES(uAddress, &value, sizeof(unsigned __int64));
	}

	void WriteMemoryDWORD(uintptr_t uAddress, unsigned int value)
	{
		WriteMemoryBYTES(uAddress, &value, sizeof(unsigned int));
	}

	void WriteMemoryWORD(uintptr_t uAddress, unsigned short value)
	{
		WriteMemoryBYTES(uAddress, &value, sizeof(unsigned short));
	}

	void WriteMemoryBYTE(uintptr_t uAddress, unsigned char value)
	{
		WriteMemoryBYTES(uAddress, &value, sizeof(unsigned char));
	}

	void NOPMemory(uintptr_t uAddress, unsigned int len)
	{
		unsigned int dword_count = (len / 4), byte_count = (len % 4);
		unsigned char Byte = 0x90;
		unsigned int Dword = 0x90666666;

		DWORD flOldProtect;
		VirtualProtect((LPVOID)uAddress, len, PAGE_WRITECOPY, &flOldProtect);
		while (dword_count != NULL)
		{
			memcpy((LPVOID)uAddress, &Dword, sizeof(unsigned int));
			uAddress += sizeof(unsigned int);
			dword_count--;
		}
		while (byte_count != NULL)
		{
			memcpy((LPVOID)uAddress, &Byte, sizeof(unsigned char));
			uAddress += sizeof(unsigned char);
			byte_count--;
		}

		VirtualProtect((LPVOID)uAddress, len, flOldProtect, &flOldProtect);
	}

	void NULLMemory(uintptr_t uAddress, unsigned int len)
	{
		unsigned int dword_count = (len / 4), byte_count = (len % 4);
		unsigned char Byte = 0x00;
		unsigned int Dword = 0x00000000;

		DWORD flOldProtect;

		if (len)
		{
			VirtualProtect((LPVOID)uAddress, len, PAGE_WRITECOPY, &flOldProtect);
			while (dword_count != NULL)
			{
				memcpy((LPVOID)uAddress, &Dword, sizeof(unsigned int));
				uAddress += sizeof(unsigned int);
				dword_count--;
			}
			while (byte_count != NULL)
			{
				memcpy((LPVOID)uAddress, &Byte, sizeof(unsigned char));
				uAddress += sizeof(unsigned char);
				byte_count--;
			}
			VirtualProtect((LPVOID)uAddress, len, flOldProtect, &flOldProtect);
		}
	}

	void WriteInstruction(uintptr_t uAddress, uintptr_t uDestination, unsigned char uFirstByte)
	{
		unsigned char ExecLine[5];
		ExecLine[0] = uFirstByte;
		*((int*)(ExecLine + 1)) = (((int)uDestination) - (((int)uAddress) + 5));
		WriteMemoryBYTES(uAddress, ExecLine, 5);
	}

	void WriteInstruction(INT32 Address, INT32 NewAddress, INT32 NopZone, INT8 Instruction)
	{
		DWORD OLDPROTECT;
		CHAR* MyAddress = (CHAR*)Address;
		INT32 JAddress = NewAddress - (Address + 5);

		HANDLE Server = OpenProcess(PROCESS_ALL_ACCESS | PROCESS_VM_READ | PROCESS_VM_WRITE, false, GetCurrentProcessId());

		if (Server)
		{
			// Unlocking the current address space in order to create the new jump.
			VirtualProtect((VOID*)Address, 5 + NopZone, PAGE_WRITECOPY, &OLDPROTECT);

			memcpy((LPVOID)MyAddress, (CHAR*)&Instruction, 1);
			memcpy((LPVOID)(MyAddress + 1), (CHAR*)&JAddress, 4);
			// COPYING THE ADDRESS TO THE ADDRESS SPACE.
			NOPMemory((INT32)MyAddress + 5, (INT32)MyAddress + 5 + NopZone);
			VirtualProtect((VOID*)Address, 5 + NopZone, OLDPROTECT, &OLDPROTECT);
		}

		CloseHandle(Server);
	}

	void WriteInstructionCallJmpEax(uintptr_t uAddress, uintptr_t uDestination, uintptr_t uNopEnd)
	{
		unsigned char ExecLine[7];
		ExecLine[0] = 0xE8;
		*((int*)(ExecLine + 1)) = (((int)uDestination) - (((int)uAddress) + 5));
		*((unsigned short*)(ExecLine + 5)) = 0xE0FF;
		WriteMemoryBYTES(uAddress, ExecLine, 7);
		if (uNopEnd && uNopEnd > (uAddress + 7))
			NOPMemory((uAddress + 7), (uNopEnd - (uAddress + 7)));
	}

	//(mnemonic:'CALL';opcode1:eo_cd;paramtype1:par_rel32;bytes:1;bt1:$e8),
	void WriteInstructionCall(uintptr_t uAddress, uintptr_t uDestination, uintptr_t uNopEnd)
	{
		unsigned char ExecLine[5];
		ExecLine[0] = 0xE8;
		*((int*)(ExecLine + 1)) = (((int)uDestination) - (((int)uAddress) + 5));
		WriteMemoryBYTES(uAddress, ExecLine, 5);
		if (uNopEnd && uNopEnd > (uAddress + 5))
			NOPMemory((uAddress + 5), (uNopEnd - (uAddress + 5)));
	}

	//(mnemonic:'MOV';opcode1:eo_id;paramtype1:par_eax;paramtype2:par_moffs32;bytes:1;bt1:$a1),
	void WriteInstructionMov32_eax_moffs32(uintptr_t uAddress, uintptr_t uAddres)
	{
		unsigned char ExecLine[5];
		ExecLine[0] = 0xA1;
		*reinterpret_cast<int*>(ExecLine + 1) = uAddres;
		WriteMemoryBYTES(uAddress, ExecLine, 5);
	}

	// (mnemonic:'MOV';opcode1:eo_id;paramtype1:par_al;paramtype2:par_moffs8;bytes:1;bt1:$a0),
	void WriteInstructionMov_al_moffs8(uintptr_t uAddress, uintptr_t uAddres)
	{
		unsigned char ExecLine[5];
		ExecLine[0] = 0xA0;
		*reinterpret_cast<int*>(ExecLine + 1) = uAddres;
		WriteMemoryBYTES(uAddress, ExecLine, 5);
	}

	//(mnemonic:'MOVZX';opcode1:eo_reg;paramtype1:par_r32;paramtype2:par_rm8;bytes:2;bt1:$0f;bt2:$b6),
	void WriteInstructionMovzx_r32_rm8(uintptr_t uAddress, uintptr_t uAddres)
	{
		unsigned char ExecLine[7];
		ExecLine[0] = 0x0F;
		ExecLine[1] = 0xB6;
		ExecLine[2] = 0x05;
		*reinterpret_cast<int*>(ExecLine + 3) = uAddres;
		WriteMemoryBYTES(uAddress, ExecLine, 7);
	}

	//(mnemonic:'CMP';opcode1:eo_reg;paramtype1:par_rm8;paramtype2:par_r8;bytes:1;bt1:$38),
	void WriteInstructionCmp_rm8_r8(uintptr_t uAddress, uintptr_t uAddres, BYTE param2)
	{
		unsigned char ExecLine[5];
		ExecLine[0] = 0x38;
		ExecLine[1] = param2;
		*reinterpret_cast<int*>(ExecLine + 2) = uAddres;
		WriteMemoryBYTES(uAddress, ExecLine, 6);
	}

	void ReadMemoryBYTES(INT32 uAddress, void* bytes, INT32 len)
	{
		/*unsigned long protect[2];
		VirtualProtect(reinterpret_cast<LPVOID>(uAddress), len, PAGE_EXECUTE_READWRITE, &protect[0]);*/
		memcpy(bytes, reinterpret_cast<LPVOID>(uAddress), len);
		/*VirtualProtect(reinterpret_cast<LPVOID>(uAddress), len, protect[0], &protect[1]);*/

		//DWORD flOldProtect;
		//VirtualProtect((LPVOID)uAddress, len, PAGE_WRITECOPY, &flOldProtect);

		//memcpy(bytes, (LPVOID)uAddress, len);

		//VirtualProtect((LPVOID)uAddress, len, flOldProtect, &flOldProtect);
	}

	void ReadMemoryQWORD(INT32 Address, INT64* Value) { ReadMemoryBYTES(Address, Value, 8); }
	void ReadMemoryDWORD(INT32 Address, INT32* Value) { ReadMemoryBYTES(Address, Value, 4); }
	void ReadMemoryWORD(INT32 Address, INT16* Value) { ReadMemoryBYTES(Address, Value, 2); }
	void ReadMemoryBYTE(INT32 Address, INT8* Value) { ReadMemoryBYTES(Address, Value, 1); }
	INT64 ReadMemoryQWORD(INT32 Address)
	{
		INT64 result = 0;
		ReadMemoryQWORD(Address, &result);
		return result;
	}
	INT32 ReadMemoryDWORD(INT32 Address)
	{
		INT32 result = 0;
		ReadMemoryDWORD(Address, &result);
		return result;
	}
	INT16 ReadMemoryWORD(INT32 Address)
	{
		INT16 result = 0;
		ReadMemoryWORD(Address, &result);
		return result;
	}
	INT8 ReadMemoryBYTE(INT32 Address)
	{
		INT8 result = 0;
		ReadMemoryBYTE(Address, &result);
		return result;
	}

	void ChangeMemoryQWORD(INT32 Address, INT64 value)
	{
		INT64 old;
		ReadMemoryQWORD(Address, &old);
		WriteMemoryQWORD(Address, old + value);
	}

	void ChangeMemoryDWORD(INT32 Address, INT32 value)
	{
		INT32 old;
		ReadMemoryDWORD(Address, &old);
		WriteMemoryDWORD(Address, old + value);
	}

	void ChangeMemoryWORD(INT32 Address, INT16 value)
	{
		INT16 old;
		ReadMemoryWORD(Address, &old);
		WriteMemoryWORD(Address, old + value);
	}

	void ChangeMemoryBYTE(INT32 Address, INT8 value)
	{
		INT8 old;
		ReadMemoryBYTE(Address, &old);
		WriteMemoryBYTE(Address, old + value);
	}

	INT32 ReadRIPPointer(INT32 address, int instructionSize, int addrPosition)
	{
		INT32 RIPPointer;
		INT32 result;
		INT8 instruction;

		ReadMemoryBYTE(address, &instruction);
		if (instruction == 0xE9)
		{
			ReadMemoryDWORD(address + addrPosition, &RIPPointer);
			result = RIPPointer + address + instructionSize;
		}
		else
		{
			result = address;
		}

		return result;
	}

	INT32 ReadJumpAddress(INT32 address)
	{
		return ReadRIPPointer(address, 5, 1);
	}

	INT32 WriteDirectJMP(INT32 address, INT32 newFunc)
	{
		LONG_PTR realNewFunc = ReadJumpAddress(newFunc);

		WriteInstruction(address, (INT32)realNewFunc, 0, (INT8)0xE9);
		return (INT32)realNewFunc;
	}

	void WriteInstructionJmp(uintptr_t uAddress, uintptr_t uDestination, uintptr_t uNopEnd)
	{
		unsigned char ExecLine[5];
		ExecLine[0] = 0xE9;
		*reinterpret_cast<int*>(ExecLine + 1) = (static_cast<int>(uDestination) - (static_cast<int>(uAddress) + 5));
		WriteMemoryBYTES(uAddress, ExecLine, 5);
		if (uNopEnd && uNopEnd > (uAddress + 5))
			NOPMemory((uAddress + 5), (uNopEnd - (uAddress + 5)));
	}

	/* Return False If Read Ptr Error */
	bool IsBadReadPtr(PVOID pPointer)
	{
		MEMORY_BASIC_INFORMATION mbi = { 0 };

		if (VirtualQuery(pPointer, &mbi, sizeof(mbi)))
		{
			DWORD mask = (PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY);

			bool ret = !(mbi.Protect & mask);

			if (mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS))
				ret = true;

			return ret;
		}

		return true;
	}

	void* VtableHook(void* instance, void* hook, int lMethodIndex) {
		intptr_t vtable = *static_cast<intptr_t*>(instance);
		return VtableHook(vtable, hook, lMethodIndex);
	}
	void* VtableHook(intptr_t addres, void* hook, int lMethodIndex) {
		intptr_t vtable = addres;
		intptr_t entry = vtable + sizeof(int) * (lMethodIndex - 1);
		intptr_t original = *reinterpret_cast<intptr_t*>(entry);

		*reinterpret_cast<intptr_t*>(entry) = reinterpret_cast<intptr_t>(hook);

		return reinterpret_cast<void*>(original);
	}
}

