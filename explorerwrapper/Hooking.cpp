#include "Hooking.h"

//char* concat(const char* s1, const char* s2)
//{
//    char* result = (char*)malloc(strlen(s1) + strlen(s2) + 1); // +1 for the null-terminator
//    // in real code you would check for errors in malloc here
//    strcpy(result, s1);
//    strcat(result, s2);
//    return result;
//}

BOOL WINAPI ChangeImportedAddress_FARPROC(HMODULE hModule, LPSTR modulename, FARPROC origfunc, FARPROC newfunc)
{
    DWORD_PTR lpFileBase = (DWORD_PTR)hModule;
    if (!lpFileBase || !modulename || !origfunc || !newfunc) return FALSE;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS pNTHeader;
    PIMAGE_IMPORT_DESCRIPTOR pImportDir;
    DWORD_PTR* pFunctions;
    LPSTR name;
    DWORD oldpr;


    dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
    pNTHeader = (PIMAGE_NT_HEADERS)(lpFileBase + dosHeader->e_lfanew);
    pImportDir = (PIMAGE_IMPORT_DESCRIPTOR)(lpFileBase + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pImportDir->Name)
    {
        name = (LPSTR)(lpFileBase + pImportDir->Name);

        if (lstrcmpiA(name, modulename) == 0) break;

        //auto toprint = concat(name, "\n");
        //OutputDebugStringA(toprint);
        //free(toprint);
        //dbgprintf(L"Redirected in %s\n", modulename);

        pImportDir++;
    }
    if (!pImportDir->Name) return FALSE;

    pFunctions = (DWORD_PTR*)(lpFileBase + pImportDir->FirstThunk);

    while (*pFunctions)
    {
        if (*pFunctions == (DWORD_PTR)origfunc) break;
        pFunctions++;
    }
    if (!*pFunctions) return FALSE;

    VirtualProtect(pFunctions, sizeof(DWORD_PTR), PAGE_EXECUTE_READWRITE, &oldpr);
    *pFunctions = (DWORD_PTR)newfunc;
    VirtualProtect(pFunctions, sizeof(DWORD_PTR), oldpr, &oldpr);
    return TRUE;
}

BOOL WINAPI ChangeImportedAddress_ORDINAL(HMODULE hModule, LPSTR modulename, ULONGLONG origOrdinal, FARPROC newfunc)
{
    DWORD_PTR lpFileBase = (DWORD_PTR)hModule;
    if (!lpFileBase || !newfunc || !modulename) return FALSE;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS pNTHeader;
    PIMAGE_IMPORT_DESCRIPTOR pImportDir;
    DWORD_PTR* pFunctions;
    LPSTR name;
    DWORD oldpr;


    dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
    pNTHeader = (PIMAGE_NT_HEADERS)(lpFileBase + dosHeader->e_lfanew);
    pImportDir = (PIMAGE_IMPORT_DESCRIPTOR)(lpFileBase + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

    while (pImportDir->Name)
    {
        name = (LPSTR)(lpFileBase + pImportDir->Name);
        if (!name) continue;
        //auto toprint = concat(name, "\n");
        //if (toprint)
        //{
        //    //OutputDebugStringA(toprint);
        //    //free(toprint);
        //}

        if (lstrcmpiA(name, modulename) == 0) break;



        //dbgprintf(L"Redirected in %s\n", modulename);

        pImportDir++;
    }
    if (!pImportDir->Name) return FALSE;

    pFunctions = (DWORD_PTR*)(lpFileBase + pImportDir->FirstThunk);

    PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)(lpFileBase + pImportDir->FirstThunk);
    PIMAGE_THUNK_DATA originalThunk = (PIMAGE_THUNK_DATA)(lpFileBase + pImportDir->OriginalFirstThunk);

    // Iterate through the thunks
    while (originalThunk->u1.AddressOfData) {
        if (originalThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
            if (originalThunk->u1.Ordinal == origOrdinal)
            {
                auto pFunc = reinterpret_cast<DWORD_PTR*>(originalThunk);
                VirtualProtect(pFunc, sizeof(DWORD_PTR), PAGE_EXECUTE_READWRITE, &oldpr);
                *pFunc = (DWORD_PTR)newfunc;
                VirtualProtect(pFunc, sizeof(DWORD_PTR), oldpr, &oldpr);
                // OutputDebugStringA("Good\n");
            }
            //dbgprintf(L"ordinal %i\n", originalThunk->u1.Ordinal);
            // Import by Ordinal
            //std::cout << "  Ordinal: " << (originalThunk->u1.Ordinal & 0xFFFF) << std::endl;
        }
        //else {
        //    // Import by Name
        //    PIMAGE_IMPORT_BY_NAME importByName = (PIMAGE_IMPORT_BY_NAME)(lpFileBase + originalThunk->u1.AddressOfData);
        //    std::cout << "  Function: " << importByName->Name << std::endl;
        //}
        thunk++;
        originalThunk++;
    }

    //VirtualProtect(pFunctions, sizeof(DWORD_PTR), PAGE_EXECUTE_READWRITE, &oldpr);
    //*pFunctions = (DWORD_PTR)newfunc;
    //VirtualProtect(pFunctions, sizeof(DWORD_PTR), oldpr, &oldpr);
    return FALSE;
}

BOOL WINAPI ChangeExportedAddress_ORDINAL(HMODULE hModule, ULONGLONG origOrdinal, LPCSTR newForward)
{
    DWORD_PTR lpFileBase = (DWORD_PTR)hModule;
    if (!lpFileBase || !newForward) return FALSE;
    PIMAGE_DOS_HEADER dosHeader;
    PIMAGE_NT_HEADERS pNTHeader;
    PIMAGE_EXPORT_DIRECTORY pImportDir;
    //LPSTR name;
    DWORD oldpr;

    dosHeader = (PIMAGE_DOS_HEADER)lpFileBase;
    pNTHeader = (PIMAGE_NT_HEADERS)(lpFileBase + dosHeader->e_lfanew);
    pImportDir = (PIMAGE_EXPORT_DIRECTORY)(lpFileBase + pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    DWORD* nameRvas = (DWORD*)(lpFileBase + pImportDir->AddressOfNames);
    WORD* ordinals = (WORD*)(lpFileBase + pImportDir->AddressOfNameOrdinals);
    DWORD* functionRvas = (DWORD*)(lpFileBase + pImportDir->AddressOfFunctions);

    DWORD VirtualAddress = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    DWORD Size = pNTHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;


    for (DWORD i = 0; i < pImportDir->NumberOfFunctions; i++)
    {
        DWORD ordinal = pImportDir->Base + i;

        char name[256] = "NO NAME";

        size_t x = 0;
        for (x = 0; x < pImportDir->NumberOfNames; ++x)
        {
            if (ordinals[x] == i)
            {
                char* functionName = (char*)(lpFileBase + nameRvas[x]);
                strcpy(name, functionName);
                break;
            }
        }
        DWORD functionRva = functionRvas[i];

        FARPROC functionAddress = (FARPROC)(lpFileBase + functionRva);
        if (functionRva >= VirtualAddress && functionRva < VirtualAddress + Size) {
            char* forwardedTo = (char*)functionAddress;
            //dbgprintfA("Forwarded Export: ordinal %i %s %s\n", ordinal, name, forwardedTo);
            if (origOrdinal == ordinal)
            {
                size_t len = strlen(newForward) + 1;
                VirtualProtect(forwardedTo, len * sizeof(CHAR), PAGE_EXECUTE_READWRITE, &oldpr);
                memcpy((void*)(lpFileBase + functionRva), newForward, sizeof(CHAR) * len);
                VirtualProtect(forwardedTo, len * sizeof(CHAR), oldpr, 0);
                //dbgprintfA("forwardedTo %s\n", forwardedTo);
                break;

            }
        }
        else
        {

            //dbgprintfA("Exported Function: %s,%i \n", name, ordinal);
        }

    }


    return FALSE;
}

uintptr_t FindPattern(uintptr_t baseAddress, const char* signature)
{
	const auto dosHeader = (PIMAGE_DOS_HEADER)baseAddress;
	const auto ntHeaders = (PIMAGE_NT_HEADERS)((unsigned char*)baseAddress + dosHeader->e_lfanew);

	const auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
	auto patternBytes = patternToByte(signature);
	const auto scanBytes = reinterpret_cast<unsigned char*>(baseAddress);

	const auto s = patternBytes->size;
	const auto d = patternBytes->data;

	for (size_t i = 0; i < sizeOfImage - s; ++i)
	{
		bool found = true;
		for (size_t j = 0; j < s; ++j)
		{
			if (scanBytes[i + j] != d[j] && d[j] != -1)
			{
				found = false;
				break;
			}
		}

		if (found)
		{
			uintptr_t address = reinterpret_cast<uintptr_t>(&scanBytes[i]);

			delete patternBytes;
			return address;
		}
	}

	delete patternBytes;

	return NULL;
}

//allocates memory close enough to the provided targetAddr argument to be reachable
	//from the targetAddr by a 32 bit jump instruction
void* _AllocatePageNearAddress(void* targetAddr)
{
	SYSTEM_INFO sysInfo;
	GetSystemInfo(&sysInfo);
	const uint64_t PAGE_SIZE = sysInfo.dwPageSize;

	uint64_t startAddr = (uint64_t(targetAddr) & ~(PAGE_SIZE - 1)); //round down to nearest page boundary
	uint64_t minAddr = min(startAddr - 0x7FFFFF00, (uint64_t)sysInfo.lpMinimumApplicationAddress);
	uint64_t maxAddr = max(startAddr + 0x7FFFFF00, (uint64_t)sysInfo.lpMaximumApplicationAddress);

	uint64_t startPage = (startAddr - (startAddr % PAGE_SIZE));

	uint64_t pageOffset = 1;
	while (1)
	{
		uint64_t byteOffset = pageOffset * PAGE_SIZE;
		uint64_t highAddr = startPage + byteOffset;
		uint64_t lowAddr = (startPage > byteOffset) ? startPage - byteOffset : 0;

		bool needsExit = highAddr > maxAddr && lowAddr < minAddr;

		if (highAddr < maxAddr)
		{
			void* outAddr = VirtualAlloc((void*)highAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr)
				return outAddr;
		}

		if (lowAddr > minAddr)
		{
			void* outAddr = VirtualAlloc((void*)lowAddr, PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
			if (outAddr != nullptr)
				return outAddr;
		}

		pageOffset++;

		if (needsExit)
		{
			break;
		}
	}

	return nullptr;
}

uint32_t _WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo)
{
	//this writes the absolute jump instructions into the memory allocated near the target
	//the E8 jump installed in the target function will jump to here

	//r10 is chosen here because it's a volatile register according to the windows x64 calling convention, 
	//but is not used for return values (like rax) or function arguments (like rcx, rdx, r8, r9)
	uint8_t absJumpInstructions[] = { 0x49, 0xBA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, //mov 64 bit value into r10
										0x41, 0xFF, 0xE2 }; //jmp r10

	uint64_t addrToJumpTo64 = (uint64_t)addrToJumpTo;
	memcpy(&absJumpInstructions[2], &addrToJumpTo64, sizeof(addrToJumpTo64));
	memcpy(absJumpMemory, absJumpInstructions, sizeof(absJumpInstructions));
	return sizeof(absJumpInstructions);
}

void DetourCall(void* Target, void* Detour)
{
	void* relayFuncMemory = _AllocatePageNearAddress(Target);

	_WriteAbsoluteJump64(relayFuncMemory, Detour); //write relay func instructions

	DWORD oldProtect;
	BOOL success = VirtualProtect(Target, 5, PAGE_EXECUTE_READWRITE, &oldProtect);

	//32 bit relative call opcode is E8, takes 1 32 bit operand for jump offset
	uint8_t jmpInstruction[5] = { 0xE8, 0x0, 0x0, 0x0, 0x0 };

	//to fill out the last 4 bytes of callInstruction, we need the offset between 
	//the relay function and the instruction immediately AFTER the jmp instruction
	const uint64_t relAddr = (uint64_t)relayFuncMemory - ((uint64_t)Target + sizeof(jmpInstruction));
	memcpy(jmpInstruction + 1, &relAddr, 4);

	//install the hook
	memcpy(Target, jmpInstruction, sizeof(jmpInstruction));
}

//Ittr: Consolidated function for pattern byte replacements.
void ChangeImportedPattern(void* dllPattern, const unsigned char* newBytes, SIZE_T size) //thank you wiktor
{
	if (dllPattern)
	{
		DWORD old;
		VirtualProtect(dllPattern, size, PAGE_EXECUTE_READWRITE, &old);
		memcpy(dllPattern, newBytes, size);
		VirtualProtect(dllPattern, size, old, 0);
	}
}