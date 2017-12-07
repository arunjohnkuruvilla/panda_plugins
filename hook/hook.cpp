#define __STDC_FORMAT_MACROS
#define INVOKE_FREQ_PGD

extern "C" {

#include "config.h"
#include "qemu-common.h"
#include "panda_plugin.h"
#include "panda_common.h"
#include "../osi/osi_types.h"
#include "../osi/osi_ext.h"
}

#include <iostream>
using namespace std;
#include <stdlib.h>
#include <string.h>

extern "C"
{

typedef uint32_t DWORD;
typedef uint16_t WORD;
typedef uint8_t BYTE;

//Structures that defines most of the PE headers structure

typedef struct _IMAGE_NT_HEADERS
{
	DWORD Signature;
	WORD Machine;
        WORD NumberOfSections;
        DWORD TimeDateStamp;
        DWORD PointerToSymbolTable;
        DWORD NumberOfSymbols;
        WORD SizeOfOptionalHeader;
        WORD Characteristics;
}IMAGE_NT_HEADERS;

typedef struct _IMAGE_EXPORT_DIRECTORY
{
        DWORD Charecteristics;
        DWORD TimeDateStamp;
        WORD MajorVersion;
        WORD MinorVersion;
        DWORD Name;
        DWORD Base;
        DWORD NumberOfFunctions;
        DWORD NumberOfNames;
        DWORD AddressOfFunctions;
        DWORD AddressOfNames;
        DWORD AddressOfNameOrdinals;
}EXPORT_DIRECTORY;

bool init_plugin(void *);
void uninit_plugin(void *);
int before_block_exec(CPUState *env, TranslationBlock *tb);
int vmi_pgd_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd);

}


int before_block_exec(CPUState *env, TranslationBlock *tb)
{
	int i;
	unsigned long pc;
	target_ulong asid = panda_current_asid(env);
        OsiProc *proc = get_current_process(env);

	OsiModules *ms = get_libraries(env, proc);
	if (ms != NULL)
	{
        	for (i = 0; i < ms->num; i++)
		{
        	//printf("\t0x" TARGET_FMT_lx "\t" TARGET_FMT_ld "\t%-24s %s\n", ms->module[i].base, ms->module[i].size, ms->module[i].name, ms->module[i].file);
			pc = ms->module[i].base;

			//cout << std::hex << pc;
			//cout << ms->module[i].name << "\n\n";

			if (strcmp(ms->module[i].name,(char *) "kernel32.dll")==0)
			{
				unsigned char buf[4]= {};
				panda_virtual_memory_rw(env, pc, buf, 2, 0);
				if(buf[0] == 0x4D && buf[1] == 0x5A)
				{
					uint32_t pe_offset;
					unsigned char signature[4];
					IMAGE_NT_HEADERS image_header;
					panda_virtual_memory_rw(env,pc+0x3C,(uint32_t *)&pe_offset,4,0);
                                        panda_virtual_memory_rw(env,pc+pe_offset,(IMAGE_NT_HEADERS *)&image_header,sizeof(image_header),0);
					//panda_virtual_memory_rw(env,pc+pe_offset,signature,4,0);
                                        if (IMAGE_HEADER.Signature==0x00004550)
                                        {
                                                uint32_t exportoffset,exportdir,exportsize;
						cout<<"PE HEADER";
                                                //unsigned char buf1[sizeof(exp_dir)];
/*
                                                //printf("Welcome to PE header\n");

                                                //Export Data_Directory Offset
                                                exportoffset = peheader+0x78;

                                                //Export directory Offset
                                                panda_virtual_memory_rw(env,exportoffset,(uint32_t *)&exportdir,4,0);
                                                //Export directory Size
                                                panda_virtual_memory_rw(env,exportoffset+4,(uint32_t *)&exportsize,4,0);
                                                //printf("%x  +  %x\n",exportdir, exportoffset);

                                                //Actual Address of Export Directory
                                                exportdir = exportdir + exportoffset;
                                                //printf("export dir : %x\n",exportdir);

					cout << "\n";
					//exit(1);
*/
					}
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
