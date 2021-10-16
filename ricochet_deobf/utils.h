#pragma once
#include <Windows.h>
#include <fstream>
#include <iostream>

namespace utils {
	bool load_to_memory(const char* path, uintptr_t* copy, size_t* size);

}