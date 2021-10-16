#include "utils.h"
bool utils::load_to_memory(const char* path, uintptr_t* copy, size_t* size) {
	if (!GetFileAttributesA(path))
	{
		printf("File doesn't exist\n");
		return false;
	}

	std::ifstream sFile(path, std::ios::binary | std::ios::ate);

	if (sFile.fail())
	{
		printf("Couldn't open filestream\n");
		return false;
	}

	*size = sFile.tellg();

	if (!*size)
	{
		printf("Size 0\n");
		return false;
	}

	*copy = (uintptr_t)malloc(*size);
	if (!*copy)
	{
		printf("Not enough memory\n");
		return false;
	}
	printf("Allocated memory for image in local process at: 0x%p\n", *copy);

	sFile.seekg(0, std::ios::beg);
	sFile.read((char*)*copy, *size);
	sFile.close();
	printf("Read file! Dump {%x, %x}\n", *(uint8_t*)*copy, *(uint8_t*)((uintptr_t)*copy + 1));
	return true;
}
