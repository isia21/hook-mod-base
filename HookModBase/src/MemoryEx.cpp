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

	void WriteInstruction(uintptr_t Address, uintptr_t NewAddress, size_t NopZone, uint8_t Instruction)
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

	void ReadMemoryBYTES(uintptr_t uAddress, void* bytes, size_t  len)
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

	void ReadMemoryQWORD(uintptr_t Address, uint64_t* Value) { ReadMemoryBYTES(Address, Value, 8); }
	void ReadMemoryDWORD(uintptr_t Address, uint32_t* Value) { ReadMemoryBYTES(Address, Value, 4); }
	void ReadMemoryWORD(uintptr_t Address, uint16_t* Value) { ReadMemoryBYTES(Address, Value, 2); }
	void ReadMemoryBYTE(uintptr_t Address, uint8_t* Value) { ReadMemoryBYTES(Address, Value, 1); }
	uint64_t ReadMemoryQWORD(uintptr_t Address)
	{
		uint64_t result = 0;
		ReadMemoryQWORD(Address, &result);
		return result;
	}
	uint32_t ReadMemoryDWORD(uintptr_t Address)
	{
		uint32_t result = 0;
		ReadMemoryDWORD(Address, &result);
		return result;
	}
	uint16_t ReadMemoryWORD(uintptr_t Address)
	{
		uint16_t result = 0;
		ReadMemoryWORD(Address, &result);
		return result;
	}
	uint8_t ReadMemoryBYTE(uintptr_t Address)
	{
		uint8_t result = 0;
		ReadMemoryBYTE(Address, &result);
		return result;
	}

	void ChangeMemoryQWORD(uintptr_t Address, uint64_t value)
	{
		uint64_t old;
		ReadMemoryQWORD(Address, &old);
		WriteMemoryQWORD(Address, old + value);
	}

	void ChangeMemoryDWORD(uintptr_t Address, uint32_t value)
	{
		uint32_t old;
		ReadMemoryDWORD(Address, &old);
		WriteMemoryDWORD(Address, old + value);
	}

	void ChangeMemoryWORD(uintptr_t Address, uint16_t value)
	{
		uint16_t old;
		ReadMemoryWORD(Address, &old);
		WriteMemoryWORD(Address, old + value);
	}

	void ChangeMemoryBYTE(uintptr_t Address, uint8_t value)
	{
		uint8_t old;
		ReadMemoryBYTE(Address, &old);
		WriteMemoryBYTE(Address, old + value);
	}

	uintptr_t ReadRIPPointer(uintptr_t address, int instructionSize, int addrPosition)
	{
		uintptr_t RIPPointer;
		uintptr_t result;
		uint8_t instruction;

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

	uintptr_t ReadJumpAddress(uintptr_t address)
	{
		return ReadRIPPointer(address, 5, 1);
	}

	INT32 WriteDirectJMP(uintptr_t address, INT32 newFunc)
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

	void* VtableHook(void* instance, void* hook, size_t lMethodIndex) {
		uintptr_t vtable = *static_cast<uintptr_t*>(instance);
		return VtableHook(vtable, hook, lMethodIndex);
	}
	void* VtableHook(uintptr_t addres, void* hook, size_t lMethodIndex) {
		uintptr_t vtable = addres;
		uintptr_t entry = vtable + sizeof(int) * (lMethodIndex - 1);
		uintptr_t original = *reinterpret_cast<uintptr_t*>(entry);

		*reinterpret_cast<uintptr_t*>(entry) = reinterpret_cast<uintptr_t>(hook);

		return reinterpret_cast<void*>(original);
	}
}

