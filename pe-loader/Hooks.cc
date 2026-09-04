#ifdef _DEBUG
#include <iostream>
#endif

#include "Common.h"

char* ArgsA;
wchar_t* ArgsW;
char** ArgsCmdA = nullptr;
wchar_t** ArgsCmdW = nullptr;
int LenArg = 0;

char* Hook_GetCommandLineA()
{
	return ArgsA;
}

wchar_t* Hook_GetCommandLineW()
{
	return ArgsW;
}

int Hook___wgetmainargs(
	int* Argc,
	wchar_t*** Argv,
	wchar_t*** Env,
	int				SoWildCard,
	void* StartInfo
)
{
	*Argc = LenArg;
	*Argv = ArgsCmdW;

	return 0;
}

int Hook___getmainargs(
	int* Argc,
	char*** Argv,
	char*** Env,
	int			doWildCard,
	void* StartInfo
)
{
	*Argc = LenArg;
	*Argv = ArgsCmdA;

	return 0;
}

char*** Hook___p___argv()
{
	return &ArgsCmdA;
}

wchar_t*** Hook___p___wargv()
{
	return &ArgsCmdW;
}

int* Hook___p___argc()
{
	return &LenArg;
}

_onexit_t __cdecl Hook__onexit(_onexit_t function)
{
	return 0;
}

int __cdecl Hook_atexit(void(__cdecl* func)(void))
{
	return 0;
}

int __cdecl Hook_Exit(int status)
{

	return 0;
}

void Hook_ExitProcess(UINT statuscode)
{
	ExitThread(0);
}

bool Hook_TerminateProcess(HANDLE hProcess, UINT uExitCode)
{
	if (hProcess == GetCurrentProcess())
	{
		ExitThread(0);
	}
	else
	{
		TerminateProcess(hProcess, uExitCode);
	}
}

void* FunctionHooks(
	_In_	int HashFunctionName
)
{
	/*
		Hooks for PE args
	*/
	if (HashFunctionName == ctime_HashStrA("GetCommandLineA"))
	{
		return reinterpret_cast<void*>(&Hook_GetCommandLineA);
	}
	if (HashFunctionName == ctime_HashStrA("GetCommandLineW"))
	{
		return reinterpret_cast<void*>(&Hook_GetCommandLineW);
	}
	if (HashFunctionName == ctime_HashStrA("__wgetmainargs"))
	{
		return reinterpret_cast<void*>(&Hook___wgetmainargs);
	}
	if (HashFunctionName == ctime_HashStrA("__getmainargs"))
	{
		return reinterpret_cast<void*>(&Hook___getmainargs);
	}
	if (HashFunctionName == ctime_HashStrA("__p___argv"))
	{
		return reinterpret_cast<void*>(&Hook___p___argv);
	}
	if (HashFunctionName == ctime_HashStrA("__p___wargv"))
	{
		return reinterpret_cast<void*>(&Hook___p___wargv);
	}
	if (HashFunctionName == ctime_HashStrA("__p___argc"))
	{
		return reinterpret_cast<void*>(&Hook___p___argc);
	}
	if (HashFunctionName == ctime_HashStrA("_onexit"))
	{
		return reinterpret_cast<void*>(&Hook__onexit);
	}
	if (HashFunctionName == ctime_HashStrA("_atexit"))
	{
		return reinterpret_cast<void*>(&Hook_atexit);
	}
	if (HashFunctionName == ctime_HashStrA("ExitProcess"))
	{
		return reinterpret_cast<void*>(&Hook_ExitProcess);
	}
	else
	{
		return nullptr;
	}

	return nullptr;
}

wchar_t** CmdLineToArgsW(
	_In_	wchar_t* ArgsW,
	_Inout_ int* NbrOfArgs
)
{
	if (!ArgsW || !NbrOfArgs)
		return nullptr;

	*NbrOfArgs = 1;
	int len = Hashing::StringLengthW(ArgsW);
	bool inArg = false;

	for (int i = 0; i < len; i++)
	{
		if (ArgsW[i] != L' ' && !inArg)
		{
			inArg = true;
			(*NbrOfArgs)++;
		}
		else if (ArgsW[i] == L' ')
		{
			inArg = false;
		}
	}

	if (*NbrOfArgs == 0)
		return nullptr;

	wchar_t** ArgsLine = (wchar_t**)malloc(sizeof(wchar_t*) * (*NbrOfArgs));
	if (!ArgsLine)
		return nullptr;
	memset(ArgsLine, 0, sizeof(wchar_t*) * (*NbrOfArgs));

	ArgsLine[0] = (wchar_t*)malloc(sizeof(wchar_t));
	if (!ArgsLine[0])
	{
		return nullptr;
	}
	ArgsLine[0][0] = L'\0';

	int argIndex = 1;
	int i = 0;
	while (i < len)
	{
		while (i < len && ArgsW[i] == L' ')
			i++;

		if (i >= len)
			break;

		int start = i;
		while (i < len && ArgsW[i] != L' ')
			i++;

		int argLen = i - start;
		ArgsLine[argIndex] = (wchar_t*)malloc(sizeof(wchar_t) * (argLen + 1));
		if (!ArgsLine[argIndex])
		{
			return nullptr;
		}

		memcpy(ArgsLine[argIndex], &ArgsW[start], sizeof(wchar_t) * argLen);
		ArgsLine[argIndex][argLen] = L'\0';
		argIndex++;
	}

	return ArgsLine;
}

char** CmdLineToArgsA(char* ArgsA, int* NbrOfArgs)
{
	if (!ArgsA || !NbrOfArgs)
		return nullptr;

	*NbrOfArgs = 1;
	int len = strlen(ArgsA);
	bool inArg = false;

	for (int i = 0; i < len; i++) {
		if (ArgsA[i] != ' ' && !inArg) {
			inArg = true;
			(*NbrOfArgs)++;
		}
		else if (ArgsA[i] == ' ') {
			inArg = false;
		}
	}

	if (*NbrOfArgs == 0)
		return nullptr;


	char** ArgsLine = (char**)malloc(sizeof(char*) * (*NbrOfArgs));
	if (!ArgsLine)
		return nullptr;
	memset(ArgsLine, 0, sizeof(char*) * (*NbrOfArgs));

	ArgsLine[0] = (char*)malloc(1);
	if (!ArgsLine[0])
	{
		return nullptr;
	}
	ArgsLine[0][0] = '\0';

	int argIndex = 1;
	int i = 0;
	while (i < len) {
		while (i < len && ArgsA[i] == ' ')
			i++;

		if (i >= len)
			break;

		int start = i;
		while (i < len && ArgsA[i] != ' ')
			i++;

		int argLen = i - start;

		ArgsLine[argIndex] = (char*)malloc(argLen + 1);
		if (!ArgsLine[argIndex])
			return nullptr;

		memcpy(ArgsLine[argIndex], &ArgsA[start], argLen);
		ArgsLine[argIndex][argLen] = '\0';
		argIndex++;
	}

	return ArgsLine;
}


bool InitArgs(
	_In_	char* ArgsA
)
{
	int ArgsSize = Hashing::StringLengthA(ArgsA);

	::ArgsA = ArgsA;
	::ArgsW = (wchar_t*)malloc(sizeof(wchar_t) * (ArgsSize + 1));
	if (!::ArgsW)
	{
		return false;
	}
	memset(::ArgsW, 0, sizeof(wchar_t) * (ArgsSize + 1));
	MultiByteToWideChar(CP_UTF8, 0, ArgsA, -1, ::ArgsW, ArgsSize + 1);

	int nbrOfArgs = 0;

	ArgsCmdA = CmdLineToArgsA(ArgsA, &nbrOfArgs);
	ArgsCmdW = CmdLineToArgsW(::ArgsW, &nbrOfArgs);

	LenArg = nbrOfArgs;

	if (!ArgsCmdA || !ArgsCmdW)
	{
#ifdef _DEBUG
		printf("Error during cmd line to args !\n");
#endif
		return false;
	}

	return true;
}



