#pragma once

#include <cstddef>
#include <string>

int Run();

int RunFromBuffer(
	const unsigned char* peBuffer,
	size_t peSize,
	const std::string& peArgs
);

int RunFromFile(
	const std::string& pePath,
	const std::string& peArgs = ""
);
