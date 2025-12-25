#pragma once
#include "common.h"
#include <cstdint>

void _dbgvprintf(LPCWSTR format, void* _argp);
void _dbgprintf(LPCWSTR format, ...);

#ifdef _DEBUG
#define dbgvprintf(f, p) (_dbgvprintf(f, p))
//#define dbgvprintfA(f, p) (_dbgvprintfA(f, p))
#define dbgprintf(f, ...) (_dbgprintf(f, __VA_ARGS__))
//#define dbgprintfA(f, ...) (_dbgprintfA(f, __VA_ARGS__))
#else
#define dbgvprintf(f, p)
//#define dbgvprintfA(f, p)
#define dbgprintf(f, ...)
//#define dbgprintfA(f, ...)
#endif
