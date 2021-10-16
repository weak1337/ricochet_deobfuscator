#include "pe.h"

PE::PE(uintptr_t base, size_t size) {
	this->SIZE = size;
	this->BASE = (void*)base;
}

void* PE::get_base() {
	return this->BASE;
}

size_t PE::get_size() {
	return this->SIZE;
}



DWORD PE::rva_to_file_offset(DWORD rva) {



	PIMAGE_FILE_HEADER file_header = this->get_file_header();
	PIMAGE_SECTION_HEADER section_header = this->get_section_header();
	PIMAGE_SECTION_HEADER current_section = nullptr;
	for (int i = 0; i < file_header->NumberOfSections; i++) {
		current_section = &section_header[i];

		if (rva >= current_section->VirtualAddress && rva <= current_section->VirtualAddress + current_section->Misc.VirtualSize)
		{
			break;
		}
	}

	return rva - (current_section->VirtualAddress - current_section->PointerToRawData);

}

PIMAGE_DOS_HEADER PE::get_dos_header() {
	return (PIMAGE_DOS_HEADER)this->get_base();
}

PIMAGE_NT_HEADERS PE::get_nt_headers() {
	return (PIMAGE_NT_HEADERS)((uintptr_t)this->get_base() + this->get_dos_header()->e_lfanew);
}

PIMAGE_FILE_HEADER PE::get_file_header() {
	return (PIMAGE_FILE_HEADER)&this->get_nt_headers()->FileHeader;
}

PIMAGE_OPTIONAL_HEADER PE::get_optional_header() {
	return (PIMAGE_OPTIONAL_HEADER)&this->get_nt_headers()->OptionalHeader;
}

PIMAGE_SECTION_HEADER PE::get_section_header() {
	return (PIMAGE_SECTION_HEADER)IMAGE_FIRST_SECTION(this->get_nt_headers());
}


PIMAGE_SECTION_HEADER PE::get_section_by_name(std::string name) {
	PIMAGE_FILE_HEADER file_header = this->get_file_header();
	PIMAGE_SECTION_HEADER section_header = this->get_section_header();
	for (int i = 0; i < file_header->NumberOfSections; i++) {
		if (!_stricmp((char*)section_header[i].Name, name.c_str())) {
			return &section_header[i];
		}
	}
}

void PE::list_sections() {
	PIMAGE_FILE_HEADER file_header = this->get_file_header();
	PIMAGE_SECTION_HEADER section_header = this->get_section_header();
	printf("List of sections: \n");
	for (int i = 0; i < file_header->NumberOfSections; i++) {
		PIMAGE_SECTION_HEADER current_section = &section_header[i];
		printf("Name: %s Rawsize: 0x%x\n", current_section->Name, current_section->SizeOfRawData);
	}
}

void PE::fix_imports() {
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = this->get_nt_headers()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importsDirectory.VirtualAddress && importsDirectory.Size)
		importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(rva_to_file_offset(importsDirectory.VirtualAddress) + (DWORD_PTR)this->BASE);
	LPCSTR libraryName = NULL;
	HMODULE library = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL;
	while (importDescriptor && importDescriptor->Name != NULL)
	{

		libraryName = (LPCSTR)rva_to_file_offset(importDescriptor->Name) + (DWORD_PTR)this->BASE;
		if (libraryName) {
			library = LoadLibraryA(libraryName);
			if (library)
			{

				PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
				originalFirstThunk = (PIMAGE_THUNK_DATA)((uintptr_t)this->BASE + rva_to_file_offset(importDescriptor->OriginalFirstThunk));
				firstThunk = (PIMAGE_THUNK_DATA)((uintptr_t)this->BASE + rva_to_file_offset(importDescriptor->FirstThunk));
				//printf("%p %p %p %s\n", originalFirstThunk, originalFirstThunk->u1.AddressOfData, firstThunk);
				while (originalFirstThunk->u1.AddressOfData != NULL)
				{

					functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)this->BASE + rva_to_file_offset(originalFirstThunk->u1.AddressOfData));
					if (functionName && !IsBadReadPtr(functionName->Name, 8)) {
						firstThunk->u1.Function = (ULONGLONG)GetProcAddress(library, functionName->Name);
						printf("Solved %s to %p\n", functionName->Name, firstThunk->u1.Function);
					}

					++originalFirstThunk;
					++firstThunk;
				}

			}
		}


		importDescriptor++;
	}

}
std::string PE::import_by_rva(uintptr_t address) {
	PIMAGE_IMPORT_DESCRIPTOR importDescriptor = NULL;
	IMAGE_DATA_DIRECTORY importsDirectory = this->get_nt_headers()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importsDirectory.VirtualAddress && importsDirectory.Size)
		importDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(importsDirectory.VirtualAddress + (DWORD_PTR)this->BASE);
	LPCSTR libraryName = NULL;
	HMODULE library = NULL;
	PIMAGE_IMPORT_BY_NAME functionName = NULL;
	while (importDescriptor && importDescriptor->Name != NULL)
	{

		libraryName = (LPCSTR)(importDescriptor->Name) + (DWORD_PTR)this->BASE;
		PIMAGE_THUNK_DATA originalFirstThunk = NULL, firstThunk = NULL;
		originalFirstThunk = (PIMAGE_THUNK_DATA)((uintptr_t)this->BASE + (importDescriptor->OriginalFirstThunk));
		firstThunk = (PIMAGE_THUNK_DATA)((uintptr_t)this->BASE + (importDescriptor->FirstThunk));
		//printf("%p %p %p %s\n", originalFirstThunk, originalFirstThunk->u1.AddressOfData, firstThunk);
		while (originalFirstThunk->u1.AddressOfData != NULL) {
			functionName = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)this->BASE + (originalFirstThunk->u1.AddressOfData));
			if (functionName && !IsBadReadPtr(functionName->Name, 8)) {
			//	firstThunk->u1.Function = (ULONGLONG)GetProcAddress(library, functionName->Name);
				if (firstThunk->u1.Function == address)
					return std::string(functionName->Name);
			}

			++originalFirstThunk;
			++firstThunk;
		}
		importDescriptor++;
	}
	return "";
}
#define RELOC_FLAG64(RelInfo) ((RelInfo >> 0x0C) == IMAGE_REL_BASED_DIR64)
void PE::fix_relocs(uintptr_t base) {
	if (!this->get_optional_header()->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		return;
	uintptr_t LocationDelta = (base - this->get_optional_header()->ImageBase);
	if (LocationDelta)
	{
		auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>((uintptr_t)this->BASE + this->rva_to_file_offset(this->get_optional_header()->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress));
		while (pRelocData->VirtualAddress)
		{
			UINT AmountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
			WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

			for (UINT i = 0; i != AmountOfEntries; ++i, ++pRelativeInfo)
			{
				if (RELOC_FLAG64(*pRelativeInfo))
				{

					UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>((uintptr_t)this->BASE + this->rva_to_file_offset(pRelocData->VirtualAddress) + ((*pRelativeInfo) & 0xFFF));
					printf("OLD %p\n", *pPatch);
					*pPatch += LocationDelta;
					printf("New %p\n", *pPatch);

				}
			}
			pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);

		}
	}
}

