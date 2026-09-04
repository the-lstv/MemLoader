**MemLoader** is a proof-of-concept framework for running native **PE** executables or **.NET** assemblies _entirely_ from memory.
It ships with two independent loaders:

| Loader            | Purpose                                          |
| ----------------- | ------------------------------------------------ |
| **pe-loader**     | Reflectively loads and runs a native PE (`.exe`) |
| **dotnet-loader** | Hosts the CLR and executes a managed assembly    |

Both loaders can be built either as a console **EXE** or as a **DLL**.

## Node.js addon (pe-loader)

You can also build **pe-loader** as a native Node addon (`.node`) exposing `run(path, args?)`.

```powershell
npm install
npm run build
```

Addon output:

- `memloader.node` (copied from `build/Release/memloader.node`)

Example:

```js
const loader = require("./memloader.node");
loader.run("C:\\path\\target.exe");
// optional arguments forwarded to target command line:
// loader.run("C:\\path\\target.exe", "arg1 arg2");
```

---
## Features

* **In-memory execution** – no payload ever touches disk once the loader starts.
* **RC4 payload encryption** – use `Common/Encrypt.py` to encrypt your binary and generate the header file included at build time.
* **Evasion techniques**
  * Indirect system-call stubs for every `Nt*` API
  * Obfuscated, lazy reconstruction of the `"LoadLibraryA"` string on a worker thread
  * **dotnet-loader** only
    * AMSI & ETW are patched with hardware breakpoints (HWBP)
    * `BaseThreadInitThunk` in `ntdll.dll` is redirected so _every_ newly-created thread starts with the same hooks
    * CPU context is taken with `RtlCaptureContext` and set via `NtContinue`, avoiding `Nt{Get|Set}ContextThread` detections
    * DOS headers of unbacked memory regions are wiped to defeat *Get-ClrReflection.ps1* heuristics

---

## Repository prerequisites

* **Visual Studio 2022** with the **LLVM/Clang-cl** toolset (except for *dotnet-loader*, which uses MSVC to leverage `mscorlib.tlb` for COM interop).
* Windows 10 x64 or later (tested on 22H2).

---

## Preparing an encrypted payload

```python
# Encrypt a PE or .NET assembly with RC4
python Common/Encrypt.py -p /path/to/payload.exe -o Payload.h
```

Then copy the Payload in the correct header file in visual studio project.
## DLL & Shellcode specification

The loaders implement a Cobalt Strike-compatible Reflective DLL entry point.

```C
__declspec(dllexport) bool WINAPI DllMain
(
	_In_	HINSTANCE	hinstDLL,
	_In_	DWORD		fdwReason,
	_In_	LPVOID		lpvReserved
)
{
	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		return true;
		break;

	case DLL_THREAD_ATTACH:
		break;

	case DLL_THREAD_DETACH:
		break;

	case 0x4:
		Run();
		break;

	case 0x0d:	//  DLL_BEACON_USER_DATA
		break;

	case DLL_PROCESS_DETACH:
		if (lpvReserved != nullptr)
		{
			break;
		}

		break;
	}
	return true;
}
```

As you can see, a cobaltstrike reflective dll uses it to execute the DLL :
```C
// DLL post-ex
DllMainAddress(Base, DLL_PROCESS_ATTACH, nullptr);
DllMainAddress(Base, 0x4,              nullptr);

// DLL beacon
DllMainAddress(Base, 0xD,              nullptr); // DLL_BEACON_USER_DATA
DllMainAddress(Base, DLL_PROCESS_ATTACH, nullptr);
DllMainAddress(Base, 0x4,                nullptr);

```


### Converting a DLL to shellcode

```python
python Shellcode.py -u /path/to/udrl.bin -d /path/to/dll.dll -o /path/to/output.bin
```

> [!Note]
Not all UDRLs are stable with this project; some crash for reasons yet unknown.
Confirmed working combinations:
> OdinLdr → dotnet-loader.dll
> KaynStrike → pe-loader (payload-dependent) and dotnet-loader

A reflective loader may be added in the future.

## Passing arguments to the payload

- dotnet-loader :Edit Main.cc, variable std::wstring AssemblyArgs (top of Run).
- pe-loader : Edit Main.cc, variable std::string PeArgs (top of Run).

## Compilation

- Debug : Make an exe, printf is present during compilation. Debug with printf > all
- Release : Make an exe, printf is excluse
- DLL : Make an dll, printf is excluse

# Credit
- Cobaltstrike UDRL : https://www.cobaltstrike.com/product/features/user-defined-reflective-loader
- Elastic hunting memory dotnet : https://www.elastic.co/security-labs/hunting-memory-net-attacks
- Get-ClrReflection : https://gist.github.com/dezhub/2875fa6dc78083cedeab10abc551cb58
- .net loading with CLR : https://github.com/med0x2e/ExecuteAssembly
- Verry interresting repos for pe-loader : https://github.com/Octoberfest7/Inline-Execute-PE
- Proxy Function call : https://github.com/paranoidninja/Proxy-Function-Calls-For-ETwTI
- ChatGPT for README refactoring : https://chatgpt.com
