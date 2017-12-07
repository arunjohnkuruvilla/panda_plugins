#define __STDC_FORMAT_MACROS
#define INVOKE_FREQ_PGD

// #include "config.h"
// #include "qemu-common.h"
// #include "panda_plugin.h"
// #include "panda_common.h"

// #include "panda_plugin_plugin.h"

extern "C" {

#include "panda_plugin.h"
#include "panda_common.h"
#include "pandalog.h"

#include "rr_log.h"
#include "rr_log_all.h"  
#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"

#include "panda_plugin_plugin.h"
    
bool init_plugin(void *);
void uninit_plugin(void *);

}

// #include "/home/test/Projects/panda/qemu/panda_plugins/osi/osi_types.h"
// #include "/home/test/Projects/panda/qemu/panda_plugins/osi/osi_ext.h"

#define IMAGE_NUMBEROF_DIRECTORY_ENTRIES 	16
#define IMAGE_SIZEOF_FILE_HEADER            20
#define IMAGE_SIZEOF_SHORT_NAME				8
typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef uint8_t BYTE;

typedef struct _IMAGE_EXPORT_DIRECTORY {
	DWORD 	Charecteristics;
	DWORD 	TimeDateStamp;
	WORD 	MajorVersion;
	WORD 	MinorVersion;
	DWORD 	Name;
	DWORD 	Base;
	DWORD 	NumberOfFunctions;
	DWORD 	NumberOfNames;
	DWORD 	AddressOfFunctions;
	DWORD 	AddressOfNames;
	DWORD 	AddressOfNameOrdinals;
} IMAGE_EXPORT_DIRECTORY;

typedef struct _COFF_HEADER {
	DWORD 	pe_header_sign;				/* PE Signature */				
	WORD 	magic;						/* Magic number */
	WORD 	number_of_sections;			/* Number of Sections */
	DWORD 	timestamp;					/* Time & date stamp */
	DWORD 	file_ptr_to_symbol_table;	/* File pointer to Symbol Table */
	DWORD 	number_of_symbols;			/* Number of Symbols */
	WORD 	size_of_optional_header;	/* sizeof(Optional Header) */
	WORD 	flags;						/* Flags */
} COFF_HEADER;

typedef struct _IMAGE_OPTIONAL_HEADER {
  	WORD	Magic;
  	BYTE 	MajorLinkerVersion;
  	BYTE 	MinorLinkerVersion;
  	DWORD 	SizeOfCode;
  	DWORD 	SizeOfInitializedData;
  	DWORD 	SizeOfUninitializedData;
  	DWORD 	AddressOfEntryPoint;
  	DWORD 	BaseOfCode;
  	DWORD 	BaseOfData;
    DWORD 	ImageBase;
} IMAGE_OPTIONAL_HEADER;

typedef struct _IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
} IMAGE_DATA_DIRECTORY;

typedef struct _IMAGE_SECTION_HEADER {
  	BYTE  	Name[IMAGE_SIZEOF_SHORT_NAME];
    DWORD 	VirtualSize;
  	DWORD 	VirtualAddress;
  	DWORD 	SizeOfRawData;
  	DWORD 	PointerToRawData;
  	DWORD 	PointerToRelocations;
  	DWORD 	PointerToLinenumbers;
  	WORD  	NumberOfRelocations;
  	WORD  	NumberOfLinenumbers;
  	DWORD 	Characteristics;
} IMAGE_SECTION_HEADER;

typedef struct _IMAGE_IMPORT_DIRECTORY {
	DWORD 	Characteristics;
	DWORD 	TimeDateStamp;
	DWORD 	ForwarderChain;
	DWORD 	Name;
	DWORD 	FirstThunk;
} IMAGE_IMPORT_DIRECTORY;


// bool init_plugin(void *);
// void uninit_plugin(void *);
int before_block_exec(CPUState *env, TranslationBlock *tb);
int vmi_pgd_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd);

int before_block_exec(CPUState *env, TranslationBlock *tb)
{
	uint8_t pe_offset;
	char name[4];
	unsigned long pc,pc_cur;
	//target_ulong asid = panda_current_asid(env);
    OsiProc *proc = get_current_process(env);

	OsiModules *ms = get_libraries(env, proc);
	if (ms != NULL) 
	{ 
        	for (int i = 0; i < ms->num; i++)
		{
        	//printf("\t0x" TARGET_FMT_lx "\t" TARGET_FMT_ld "\t%-24s %s\n", ms->module[i].base, ms->module[i].size, ms->module[i].name, ms->module[i].file);
			pc = ms->module[i].base;
			
			//printf("%s\n",ms->module[i].name);
			if (strcmp(ms->module[i].name,"kernel32.dll")==0 || strcmp(ms->module[i].name,"ntdll.dll")==0)
			{
				// printf("Base: %x\n",pc);
				unsigned char buf[2]= {};
				uint32_t sign;
				panda_virtual_memory_rw(env, pc, buf, 2, 0);
				panda_virtual_memory_rw(env, pc, (uint8_t *)&sign, 4, 0);

				if(buf[0] == 0x4D && buf[1] == 0x5A)
				{	
					uint32_t peheader;
					uint32_t import_offset;

					// Ideally all 4 bytes should be taken. Only lowest byte taken here.
					panda_virtual_memory_rw(env,pc+0x3C,(uint8_t *)&pe_offset,1,0);

					peheader = pc+pe_offset;

					COFF_HEADER coff_header;
					panda_virtual_memory_rw(env, peheader, (uint8_t *)&coff_header, sizeof(coff_header), 0);

					if (coff_header.pe_header_sign == 0x00004550) {

						// printf("Size of optional_header: %04x\n", coff_header.size_of_optional_header);

						uint32_t optional_header_offset;

						optional_header_offset = peheader + 0x18;

						IMAGE_OPTIONAL_HEADER image_optional_header;
						panda_virtual_memory_rw(env, optional_header_offset, (uint8_t *)&image_optional_header, sizeof(IMAGE_OPTIONAL_HEADER), 0);

						uint16_t pe_type;

						panda_virtual_memory_rw(env, optional_header_offset, (uint8_t *)&pe_type, 2, 0);

						uint32_t section_alignment;
						panda_virtual_memory_rw(env, optional_header_offset+0x20, (uint8_t *)&section_alignment, 4, 0);
						// printf("Section Alignment: %08x\n", section_alignment);

						uint32_t file_alignment;
						panda_virtual_memory_rw(env, optional_header_offset+0x24, (uint8_t *)&file_alignment, 4, 0);
						// printf("File Alignment: %08x\n", file_alignment);

						// PE format
						if (image_optional_header.Magic == 0x010b) {
							
							import_offset = optional_header_offset+0x60;

							IMAGE_DATA_DIRECTORY export_data_directory;
							panda_virtual_memory_rw(env, import_offset, (uint8_t *)&export_data_directory, sizeof(IMAGE_DATA_DIRECTORY), 0);

							uint32_t image_export_directory_offset = image_optional_header.ImageBase + export_data_directory.VirtualAddress;

							IMAGE_EXPORT_DIRECTORY image_export_directory;
							panda_virtual_memory_rw(env, image_export_directory_offset, (uint8_t *)&image_export_directory, sizeof(IMAGE_EXPORT_DIRECTORY), 0);

							uint32_t address_of_functions_offset, address_of_function_names_offset;

							address_of_functions_offset = image_optional_header.ImageBase + image_export_directory.AddressOfFunctions;
							address_of_function_names_offset = image_optional_header.ImageBase + image_export_directory.AddressOfNames;

							uint32_t function_counter = 0x0;

							// printf("Number of Functions: %08x\n", image_export_directory.NumberOfFunctions);
							// printf("Number of Names: %08x\n", image_export_directory.NumberOfNames);

							while(function_counter < image_export_directory.NumberOfFunctions) {
								uint32_t address_of_function;
								uint32_t address_of_function_name;

								int status = 0;

								status = 0;
								status = panda_virtual_memory_rw(env, address_of_functions_offset + function_counter*0x4, (uint8_t *)&address_of_function, 4, 0);
								if (status != 0) {
									printf("Page mapped out.\n");
									break;
								}

								status = 0;
								status = panda_virtual_memory_rw(env, address_of_function_names_offset + function_counter*0x4, (uint8_t *)&address_of_function_name, 4, 0);

								if (status != 0) {
									printf("Page mapped out.\n");
									break;
								}

								uint8_t letter;
								//panda_virtual_memory_rw(env, image_optional_header.ImageBase + address_of_function_name, (uint8_t *)&letter, 1, 0);
								//printf("Function name 1: ");
								uint8_t counter;

								char function_name[4096];

								uint8_t decimal_counter = 0;
								counter = 0x0;
								
								while (1) {
									status = 0;
									status = panda_virtual_memory_rw(env, image_optional_header.ImageBase + address_of_function_name + counter, (uint8_t *)&letter, 1, 0);


									function_name[decimal_counter] = letter;

									counter = counter + 0x1;
									decimal_counter = decimal_counter + 1;

									if(letter == 0x00) {
										break;
									}
									if (status != 0) {
										printf("Page mapped out.\n");
										break;
									}
								}

								
								// printf("Function name: %s\n",  function_name);
								function_counter = function_counter + 0x1;



								if (strcmp(function_name, "GetProcAddress") == 0 && strcmp(ms->module[i].name,"kernel32.dll")==0){
									printf("Function address 1: %08x\t", image_optional_header.ImageBase + address_of_function);
									printf("%s\n", function_name);
								}

								if (strcmp(function_name, "VirtualAlloc") == 0 && strcmp(ms->module[i].name,"kernel32.dll")==0){
									printf("Function address 1: %08x\t", image_optional_header.ImageBase + address_of_function);
									printf("%s\n", function_name);
								}

								if (strcmp(function_name, "VirtualFree") == 0 && strcmp(ms->module[i].name,"kernel32.dll")==0){
									printf("Function address 1: %08x\t", image_optional_header.ImageBase + address_of_function);
									printf("%s\n", function_name);
								}

								if (strcmp(function_name, "VirtualProtect") == 0 && strcmp(ms->module[i].name,"kernel32.dll")==0){
									printf("Function address 1: %08x\t", image_optional_header.ImageBase + address_of_function);
									printf("%s\n", function_name);
								}

								if (strcmp(function_name, "RtlAllocateHeap") == 0 && strcmp(ms->module[i].name,"ntdll.dll")==0){
									printf("Function address 1: %08x\t", image_optional_header.ImageBase + address_of_function);
									printf("%s\n", function_name);
								}

								if (strcmp(function_name, "RtlFreeHeap") == 0 && strcmp(ms->module[i].name,"ntdll.dll")==0){
									printf("Function address 1: %08x\t", image_optional_header.ImageBase + address_of_function);
									printf("%s\n", function_name);
								}

								if (status != 0) {
									printf("Page mapped out.\n");
									break;
								}
								
							}


							// uint32_t address_of_function_1;
							// uint32_t virtual_name_of_function_1;
							// uint64_t name_of_function_1;
							// panda_virtual_memory_rw(env, address_of_functions_offset, (uint32_t *)&address_of_function_1, 4, 0);
							// panda_virtual_memory_rw(env, address_of_function_names_offset, (uint32_t *)&virtual_name_of_function_1, 4, 0);


							

							// printf("Function address 1: %08x\t", image_optional_header.ImageBase + address_of_function_1);


							// uint8_t letter;
							// panda_virtual_memory_rw(env, image_optional_header.ImageBase + virtual_name_of_function_1, (uint8_t *)&letter, 1, 0);
							// printf("Function name 1: ");
							// uint8_t counter;
							// counter = 0x0;
							// while (letter != 0x00) {
							// 	printf("%c", letter);
							// 	counter = counter + 0x1;
							// 	panda_virtual_memory_rw(env, image_optional_header.ImageBase + virtual_name_of_function_1 + counter, (uint8_t *)&letter, 1, 0);
							// }

							// printf("\n");




							// uint32_t address_of_function_2;
							// uint32_t virtual_name_of_function_2;
							// uint64_t name_of_function_2;
							// panda_virtual_memory_rw(env, address_of_functions_offset + 0x4, (uint32_t *)&address_of_function_2, 4, 0);
							// panda_virtual_memory_rw(env, address_of_function_names_offset + 0x4, (uint32_t *)&virtual_name_of_function_2, 4, 0);


							// panda_virtual_memory_rw(env, image_optional_header.ImageBase + virtual_name_of_function_2, (uint64_t *)&name_of_function_2, 8, 0);

							// printf("Function address 1: %08x\t", image_optional_header.ImageBase + address_of_function_2);
							

							// panda_virtual_memory_rw(env, image_optional_header.ImageBase + virtual_name_of_function_2, (uint8_t *)&letter, 1, 0);
							// printf("Function name 2: ");
							// counter = 0x0;
							// while (letter != 0x00) {
							// 	printf("%c", letter);
							// 	counter = counter + 0x1;
							// 	panda_virtual_memory_rw(env, image_optional_header.ImageBase + virtual_name_of_function_2 + counter, (uint8_t *)&letter, 1, 0);
							// }

							// printf("\n");

							// uint32_t dll_name_offset;
							// dll_name_offset = image_optional_header.ImageBase + image_export_directory.Name;

							// printf("DLL name offset: %08x\n", dll_name_offset);

							// panda_virtual_memory_rw(env, dll_name_offset, (uint32_t *)&dll_name, 4, 0);
							// printf("DLL name: %08x\n", dll_name);
							// uint32_t RVA, data_size;
							// panda_virtual_memory_rw(env, import_offset, (uint32_t *)&RVA, 4, 0);
							// panda_virtual_memory_rw(env, import_offset+0x4, (uint32_t *)&data_size, 4, 0);
							// printf("RVA: %08x\n", RVA);
							// printf("Data_size: %08x\n", data_size);

							// // Section parsing
							// uint32_t section_header_offset = optional_header + coff_header.size_of_optional_header;


							// IMAGE_SECTION_HEADER text_section_header;
							// panda_virtual_memory_rw(env, section_header_offset, (IMAGE_SECTION_HEADER *)&text_section_header, sizeof(IMAGE_SECTION_HEADER), 0);

							// printf("Section name test: %02x %02x %02x %02x %02x %02x %02x %02x\n", 
							// 	text_section_header.Name[0],
							// 	text_section_header.Name[1],
							// 	text_section_header.Name[2],
							// 	text_section_header.Name[3],
							// 	text_section_header.Name[4],
							// 	text_section_header.Name[5],
							// 	text_section_header.Name[6],
							// 	text_section_header.Name[7]
							// );
							// printf("Section Virtual Size: %08x\n", text_section_header.VirtualSize);
							// printf("Section Virtual Address: %08x\n", text_section_header.VirtualAddress);
							// printf("Pointer to raw data: %08x\n", text_section_header.PointerToRawData);

							// uint32_t import_descriptor_offset = RVA - text_section_header.VirtualAddress + text_section_header.PointerToRawData;

							// // Parsing Import directory
							// IMAGE_IMPORT_DIRECTORY import_directory;
							// panda_virtual_memory_rw(env, import_descriptor_offset, (IMAGE_IMPORT_DIRECTORY *)&import_directory, sizeof(IMAGE_IMPORT_DIRECTORY), 0);

							// // TODO - Add remaining IMAGE_IMPORT_DIRECTORY entries - data_size/20
							// uint32_t image_import_by_name_offset;
							// image_import_by_name_offset = import_directory.Characteristics - text_section_header.VirtualAddress + text_section_header.PointerToRawData;
							// printf("Function pointer offset: %08x\n", import_directory.Characteristics);

							// uint32_t pointer;
							// panda_virtual_memory_rw(env, image_import_by_name_offset+0x4, (uint32_t *)&pointer, 4, 0);
							// printf("Pointer 1: %08x\n", pointer);

						}
						// PE+ format
						else {
							// import_offset = optional_header_offset+0x70;
							// uint32_t RVA, data_size;
							// panda_virtual_memory_rw(env, import_offset, (uint8_t *)&RVA, 4, 0);
							// panda_virtual_memory_rw(env, import_offset+0x4, (uint8_t *)&data_size, 4, 0);
							// printf("RVA: %08x\n", RVA);
							// printf("Data_size: %08x\n", data_size);
							printf("PE+ header, DLL name: %s\n", ms->module[i].name);
							exit(0);
						}
					} 
					
					//remove after testing.
					
				}
			}
		}
	}
	//printf("ASID = 0x%x \t PID = %u \t  Process = %s\n",panda_current_asid(env),proc->pid,proc->name, );

    free_osiproc(proc);
	free_osimodules(ms);
}

int vmi_pgd_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd) {
    // tb argument is not used by before_block_exec()
    return before_block_exec(env, NULL);
}

bool init_plugin(void *self) {

    panda_require("osi");
    assert(init_osi_api());
#if defined(INVOKE_FREQ_PGD)
    // relatively short execution
    panda_cb pcb = { .after_PGD_write = vmi_pgd_changed };
    panda_register_callback(self, PANDA_CB_VMI_PGD_CHANGED, pcb);
#else
    // expect this to take forever to run
    panda_cb pcb = { .before_block_exec = before_block_exec };
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);
#endif

    if(!init_osi_api()) return false;

    return true;
}

void uninit_plugin(void *self) { }