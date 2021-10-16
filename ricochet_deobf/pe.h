#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
class PE {
private:
	void* BASE;
	size_t SIZE;
public:
	PE(uintptr_t base, size_t size);
	DWORD rva_to_file_offset(DWORD rva);
	void* get_base();
	size_t get_size();

	PIMAGE_DOS_HEADER get_dos_header();
	PIMAGE_NT_HEADERS get_nt_headers();
	PIMAGE_FILE_HEADER get_file_header();
	PIMAGE_OPTIONAL_HEADER get_optional_header();
	PIMAGE_SECTION_HEADER get_section_header();
	PIMAGE_SECTION_HEADER get_section_by_name(std::string name);
	void list_sections();
	void fix_imports();
	void fix_relocs(uintptr_t base);
	std::string import_by_rva(uintptr_t address);

};

