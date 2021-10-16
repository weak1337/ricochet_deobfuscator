#include <Windows.h>
#include <iostream>
#include <inttypes.h>
#include <Zydis/Zydis.h>
#pragma comment(lib, "zydis.lib")
#include "includes.h"
int main()
{
    /*
        Load driver from disk to memory
    */
    uintptr_t address_on_disk; size_t size_on_disk;
    if (!utils::load_to_memory("ricochetdriver.sys", &address_on_disk, &size_on_disk)) { //path to driver
        system("pause");
        return 0;
    }
    PE* driver_on_disk = new PE(address_on_disk, size_on_disk);
    DWORD size_of_image = driver_on_disk->get_optional_header()->SizeOfImage;
    /*
        Relocate the driver in a local buffer
    */
    void* address_in_memory = VirtualAlloc(0, size_of_image, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    memcpy(address_in_memory, driver_on_disk->get_base(), driver_on_disk->get_optional_header()->SizeOfHeaders);
    PIMAGE_SECTION_HEADER current_section = driver_on_disk->get_section_header();
    for (int i = 0; i < driver_on_disk->get_file_header()->NumberOfSections; ++i, ++current_section) {
        memcpy((void*)((uintptr_t)address_in_memory + current_section->VirtualAddress), (void*)((uintptr_t)driver_on_disk->get_base() + current_section->PointerToRawData), current_section->SizeOfRawData);
    }
    delete driver_on_disk;
    PE* driver_in_memory = new PE((uintptr_t)address_in_memory, size_of_image);

    uintptr_t base = (uintptr_t)driver_in_memory->get_base();
    DWORD rel_func_to_deobfuscate = 0x0;
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_ADDRESS_WIDTH_64);
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);

    while (true) {
        printf("Function to deobfuscate: 0x");
        std::cin >> std::hex >> rel_func_to_deobfuscate;
        system("cls");
        printf("[>] Deobfuscation of RVA 0x%x\n", rel_func_to_deobfuscate);
        printf("[>] Relocated driver to: %p\n", base);
        ZyanUSize offset = 0;
        ZydisDecodedInstruction instruction;
        bool should_run = true;
        while (should_run && ZYAN_SUCCESS(ZydisDecoderDecodeBuffer(&decoder, (void*)(base + rel_func_to_deobfuscate + offset), INT_MAX - offset,
            &instruction)))
        {
            char buffer[256];
            ZydisFormatterFormatInstruction(&formatter, &instruction, buffer, sizeof(buffer),
                base + rel_func_to_deobfuscate + offset);
            BYTE current = *(BYTE*)(base + rel_func_to_deobfuscate + offset);

            /*
                Check opcode
            */
            switch (current) {
            case 0xE9: { //Jump -> combine control flow
                uintptr_t destination = base + rel_func_to_deobfuscate + offset + *(signed int*)(base + rel_func_to_deobfuscate + offset + 1) + 5;
                rel_func_to_deobfuscate = destination - base;
                offset = 0x0;     
                break;
            }
            case 0xC3: { //Return
                printf("%016" PRIX64 " -> ", base + rel_func_to_deobfuscate + offset);
                printf("%s\n", buffer);
                should_run = false;
                break;
            }
            case 0xCC: { //Function end or breakpoint
                printf("%016" PRIX64 " -> ", base + rel_func_to_deobfuscate + offset);
                printf("%s\n", buffer);
                should_run = false;
                break;
            }
            case 0xCD: { //0x29 -> fastfail
                should_run = false;
                printf("%016" PRIX64 " -> ", base + rel_func_to_deobfuscate + offset);
                printf("%s\n", buffer);
                break;
            }
            case 0xFF: {
                if (*(BYTE*)(base + rel_func_to_deobfuscate + offset + 1) == 0x15) { //Call to import
                    printf("%016" PRIX64 " -> ", base + rel_func_to_deobfuscate + offset);
                    uintptr_t address = base + rel_func_to_deobfuscate + offset;
                    DWORD relative = *(DWORD*)(address + 2) + 6;
                    std::string import_name = driver_in_memory->import_by_rva(*(DWORD*)(address + relative)); //Resolve import name
                    printf("%s -> %s\n", buffer, import_name.c_str());
                    offset += instruction.length;
                }
                else {
                    printf("%016" PRIX64 " -> ", base + rel_func_to_deobfuscate + offset);
                    printf("%s\n");
                    offset += instruction.length;
                }
                break;
            }
            case 0xE8: { //Call resolve rva
                uintptr_t destination = base + rel_func_to_deobfuscate + offset + *(signed int*)(base + rel_func_to_deobfuscate + offset + 1) + 5;
                printf("%016" PRIX64 " -> ", base + rel_func_to_deobfuscate + offset);
                printf("%s (%x)\n", buffer, destination - base);
                offset += instruction.length;
                break;
            }
            case 0xEB: { //Short jump resolve rva
                uintptr_t destination = base + rel_func_to_deobfuscate + offset +  *(INT8*)(base + rel_func_to_deobfuscate + offset + 1)  + 2;
                printf("%016" PRIX64 " -> ", base + rel_func_to_deobfuscate + offset);
                printf("%s (%x)\n", buffer, destination - base);
                offset += instruction.length;
                break;
            }
            case 0x74: { //cond jump
                uintptr_t destination = base + rel_func_to_deobfuscate + offset + *(INT8*)(base + rel_func_to_deobfuscate + offset + 1) + 2;
                printf("%016" PRIX64 " -> ", base + rel_func_to_deobfuscate + offset);
                printf("%s (%x)\n", buffer, destination - base);
                offset += instruction.length;
                break;
            }
            case 0x0F: { //cond jump
                if (*(BYTE*)(base + rel_func_to_deobfuscate + offset + 1) == 0x84 || *(BYTE*)(base + rel_func_to_deobfuscate + offset + 1) == 0x85) {
                    uintptr_t destination = base + rel_func_to_deobfuscate + offset + *(signed int*)(base + rel_func_to_deobfuscate + offset + 2) + 6;
                    printf("%016" PRIX64 " -> ", base + rel_func_to_deobfuscate + offset);
                    printf("%s (%x)\n", buffer, destination - base);
                    offset += instruction.length;
                }
                else //Rdstc
                {
                    printf("%016" PRIX64 " -> ", base + rel_func_to_deobfuscate + offset);
                    printf("%s\n", buffer);
                    offset += instruction.length;

                }
                break;
            }
            default: {
                if (current != 0x90) { //Other instruction / ignore nops
                    printf("%016" PRIX64 " -> ", base + rel_func_to_deobfuscate + offset);
                    printf("%s\n", buffer);
                }

                offset += instruction.length;
                break;
            }
            }
        }
    }
    system("pause");
}
