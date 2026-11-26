#include "stdafx.h"
#include "../include/MemoryEx.h"

namespace MemoryEx
{
	void WriteMemoryBYTES(uintptr_t nAddress, const void* pBytes, size_t nSize)
	{
		if (nSize == 0) {
			return;
		}

		auto* pAddress = reinterpret_cast<void*>(nAddress);
		DWORD dwOldProtect = 0;
		if (!VirtualProtect(pAddress, nSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
			throw std::runtime_error("VirtualProtect failed before memory write");
		}

		memcpy(pAddress, pBytes, nSize);
		const BOOL bRestored = VirtualProtect(pAddress, nSize, dwOldProtect, &dwOldProtect);
		FlushInstructionCache(GetCurrentProcess(), pAddress, nSize);
		if (!bRestored) {
			throw std::runtime_error("VirtualProtect failed after memory write");
		}
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

	void NOPMemory(uintptr_t nAddress, size_t nSize)
	{
		static constexpr uint8_t NOP_BYTE = 0x90;
		static constexpr uint32_t NOP_DWORD = 0x90666666;
		size_t nDwordCount = nSize / sizeof(NOP_DWORD);
		size_t nByteCount = nSize % sizeof(NOP_DWORD);

		if (nSize == 0) {
			return;
		}
		auto* pchStart = reinterpret_cast<uint8_t*>(nAddress);
		auto* pchCurrent = pchStart;
		DWORD dwOldProtect = 0;
		if (!VirtualProtect(pchStart, nSize, PAGE_EXECUTE_READWRITE, &dwOldProtect)) {
			throw std::runtime_error("VirtualProtect failed before NOP fill");
		}
		while (nDwordCount != 0) {
			memcpy(pchCurrent, &NOP_DWORD, sizeof(NOP_DWORD));
			pchCurrent += sizeof(NOP_DWORD);
			--nDwordCount;
		}
		while (nByteCount != 0) {
			*pchCurrent = NOP_BYTE;
			++pchCurrent;
			--nByteCount;
		}

		const BOOL bRestored = VirtualProtect(pchStart, nSize, dwOldProtect, &dwOldProtect);
		FlushInstructionCache(GetCurrentProcess(), pchStart, nSize);
		if (!bRestored) {
			throw std::runtime_error("VirtualProtect failed after NOP fill");
		}
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

	bool TryGetRel32(uintptr_t nAddress, uintptr_t nTargetAddress, uint32_t& dwDisplacement)
	{
		constexpr size_t REL32_INSTRUCTION_SIZE = 5;
		if (nAddress > UINTPTR_MAX - REL32_INSTRUCTION_SIZE) {
			return false;
		}

		const uintptr_t nNextAddress = nAddress + REL32_INSTRUCTION_SIZE;
		if constexpr (sizeof(uintptr_t) > sizeof(uint32_t)) {
			if (nTargetAddress >= nNextAddress) {
				if (nTargetAddress - nNextAddress > INT32_MAX) {
					return false;
				}
			}
			else if (nNextAddress - nTargetAddress > static_cast<uintptr_t>(INT32_MAX) + 1) {
				return false;
			}
		}
		dwDisplacement = static_cast<uint32_t>(nTargetAddress - nNextAddress);
		return true;
	}

	void WriteInstruction(uintptr_t nAddress, uintptr_t nTargetAddress, uint8_t byOpcode)
	{
		uint32_t dwDisplacement = 0;
		if (!TryGetRel32(nAddress, nTargetAddress, dwDisplacement)) {
			throw std::invalid_argument("Target is outside rel32 reach");
		}
		uint8_t achInstruction[1 + sizeof(dwDisplacement)] = { byOpcode };
		memcpy(achInstruction + 1, &dwDisplacement, sizeof(dwDisplacement));
		WriteMemoryBYTES(nAddress, achInstruction, sizeof(achInstruction));
	}

	void WriteInstruction(uintptr_t Address, uintptr_t NewAddress, size_t NopZone, uint8_t Instruction)
	{
		if (Address > UINTPTR_MAX - 5 || NopZone > UINTPTR_MAX - (Address + 5)) {
			throw std::invalid_argument("Instruction range overflows address space");
		}
		WriteInstruction(Address, NewAddress, Instruction);
		if (NopZone != 0) {
			NOPMemory(Address + 5, NopZone);
		}
	}

	void WriteInstructionCallJmpEax(uintptr_t uAddress, uintptr_t uDestination, uintptr_t uNopEnd)
	{
		unsigned char ExecLine[7];
		ExecLine[0] = 0xE8;
		uint32_t dwDisplacement = 0;
		if (!TryGetRel32(uAddress, uDestination, dwDisplacement)) {
			throw std::invalid_argument("Target is outside rel32 reach");
		}
		memcpy(ExecLine + 1, &dwDisplacement, sizeof(dwDisplacement));
		ExecLine[5] = 0xFF;
		ExecLine[6] = 0xE0;
		WriteMemoryBYTES(uAddress, ExecLine, 7);
		if (uNopEnd && uNopEnd > (uAddress + 7))
			NOPMemory((uAddress + 7), (uNopEnd - (uAddress + 7)));
	}

	//(mnemonic:'CALL';opcode1:eo_cd;paramtype1:par_rel32;bytes:1;bt1:$e8),
	void WriteInstructionCall(uintptr_t uAddress, uintptr_t uDestination, uintptr_t uNopEnd)
	{
		WriteInstruction(uAddress, uDestination, 0xE8);
		if (uNopEnd && uNopEnd > (uAddress + 5))
			NOPMemory((uAddress + 5), (uNopEnd - (uAddress + 5)));
	}

	void WriteInstructionPushImm32(uintptr_t nAddress, uint32_t dwValue)
	{
		uint8_t achInstruction[1 + sizeof(dwValue)] = { 0x68 };
		memcpy(achInstruction + 1, &dwValue, sizeof(dwValue));
		WriteMemoryBYTES(nAddress, achInstruction, sizeof(achInstruction));
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
		uintptr_t result;
		uint8_t instruction;

		ReadMemoryBYTE(address, &instruction);
		if (instruction == 0xE9)
		{
			int32_t nDisplacement = 0;
			ReadMemoryBYTES(address + addrPosition, &nDisplacement, sizeof(nDisplacement));
			result = address + instructionSize + nDisplacement;
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
		WriteInstruction(uAddress, uDestination, 0xE9);
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
		if (lMethodIndex == 0 || lMethodIndex - 1 > (UINTPTR_MAX - vtable) / sizeof(uintptr_t)) {
			throw std::invalid_argument("Invalid VTable slot index");
		}
		const uintptr_t nEntryAddress = vtable + sizeof(uintptr_t) * (lMethodIndex - 1);
		uintptr_t original = 0;
		ReadMemoryBYTES(nEntryAddress, &original, sizeof(original));
		const uintptr_t nHookAddress = reinterpret_cast<uintptr_t>(hook);
		WriteMemoryBYTES(nEntryAddress, &nHookAddress, sizeof(nHookAddress));

		return reinterpret_cast<void*>(original);
	}
}

