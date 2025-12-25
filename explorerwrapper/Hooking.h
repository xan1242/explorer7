#pragma once
#define WIN32_LEAN_AND_MEAN
//#define PRERELEASE_COPY
#include <windows.h>
#include <cstdint>
#include <climits>
#include <cstdlib>

#ifndef HOOKING_H
#define HOOKING_H

extern "C" void* _ReturnAddress(void);
#pragma intrinsic(_ReturnAddress)

extern HINSTANCE g_hInstance;

BOOL WINAPI ChangeImportedAddress_FARPROC(HMODULE hModule, LPSTR modulename, FARPROC origfunc, FARPROC newfunc);
__declspec(noinline) BOOL WINAPI ChangeImportedAddress_ORDINAL(HMODULE hModule, LPSTR modulename, ULONGLONG origOrdinal, FARPROC newfunc);
__declspec(noinline) BOOL WINAPI ChangeExportedAddress_ORDINAL(HMODULE hModule, ULONGLONG origOrdinal, LPCSTR newForward);
#define ChangeImportedAddress(hModule,modulename,origproc,newproc) ChangeImportedAddress_FARPROC(hModule,modulename,(FARPROC)origproc,(FARPROC)newproc)
#define ChangeImportedAddressORDINAL(hModule,modulename,origproc,newproc) ChangeImportedAddress_ORDINAL(hModule,modulename,origproc,(FARPROC)newproc)
#define ChangeExportedAddress_ORDINAL(hModule,origproc,newproc) ChangeExportedAddress_ORDINAL(hModule,origproc,newproc)

template <class T>
struct wiktorArray
{
	int size;
	T* data;

	wiktorArray()
	{
		size = 0;
		data = NULL;
	}

	~wiktorArray()
	{
		if (data)
		{
			free(data);
			data = NULL;
		}
	}

	void push_back(T InputData)
	{
		void* newData = realloc(data, sizeof(T) * (size + 1));
		if (newData)
		{
			data = (T*)newData;
			data[size++] = InputData;
		}
	}
};

namespace HookingSillyStuff
{
	inline int IsSpaceCS(char ch)
	{
		return ((ch == ' ') || (ch == '\t'));
	}

	inline int IsDigitCS(char ch)
	{
		return (((ch >= '0') && (ch <= '9')));
	}

	inline int isAlphaCS(char c)
	{
		/*
		 * Depends on ASCII-like character ordering.
		 */
		return ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ? 1 : 0);
	}

	inline int isUpperCS(int c)
	{
		return (c >= 'A' && c <= 'Z');
	}

	inline unsigned long strtoulCUSTOM(const char* nptr, char** endptr, int base)
	{
		const char* s = nptr;
		unsigned long acc;
		int c;
		unsigned long cutoff;
		int neg = 0, any, cutlim;

		/*
		 * See strtol for comments as to the logic used.
		 */
		do {
			c = *s++;
		} while (IsSpaceCS(c));
		if (c == '-') {
			neg = 1;
			c = *s++;
		}
		else if (c == '+')
			c = *s++;
		if ((base == 0 || base == 16) &&
			c == '0' && (*s == 'x' || *s == 'X')) {
			c = s[1];
			s += 2;
			base = 16;
		}
		if (base == 0)
			base = c == '0' ? 8 : 10;
		cutoff = (unsigned long)ULONG_MAX / (unsigned long)base;
		cutlim = (unsigned long)ULONG_MAX % (unsigned long)base;
		for (acc = 0, any = 0;; c = *s++) {
			if (IsDigitCS(c))
				c -= '0';
			else if (isAlphaCS(c))
				c -= isUpperCS(c) ? 'A' - 10 : 'a' - 10;
			else
				break;
			if (c >= base)
				break;
			if (any < 0 || acc > cutoff || (acc == cutoff && c > cutlim))
				any = -1;
			else {
				any = 1;
				acc *= base;
				acc += c;
			}
		}
		if (any < 0) {
			acc = ULONG_MAX;
			//errno = ERANGE;
		}
		else if (neg)
			acc = -(long)acc;
		if (endptr != 0)
			*endptr = (char*)(any ? s - 1 : nptr);
		return (acc);
	}
}

inline wiktorArray<int>* patternToByte(const char* pattern)
{
	auto bytes = new wiktorArray<int>();
	const auto start = const_cast<char*>(pattern);
	const auto end = const_cast<char*>(pattern) + strlen(pattern);

	for (auto current = start; current < end; ++current)
	{
		if (*current == '?')
		{
			++current;
			if (*current == '?')
				++current;
			bytes->push_back(-1);
		}
		else {
			bytes->push_back(HookingSillyStuff::strtoulCUSTOM(current, &current, 16));
		}
	}
	return bytes;
}

uintptr_t FindPattern(uintptr_t baseAddress, const char* signature);
void* _AllocatePageNearAddress(void* targetAddr);
uint32_t _WriteAbsoluteJump64(void* absJumpMemory, void* addrToJumpTo);
void DetourCall(void* Target, void* Detour);
void ChangeImportedPattern(void* dllPattern, const unsigned char* newBytes, SIZE_T size);


#endif