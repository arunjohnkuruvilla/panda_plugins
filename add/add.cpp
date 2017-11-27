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

extern "C" {

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
				unsigned char buf[200]= {};
				panda_virtual_memory_rw(env, pc, buf, 2, 0);
				if(buf[0] == 0x4D && buf[1] == 0x5A)
				{
					panda_virtual_memory_rw(env,pc+0x3C,buf,4,0);
					for(int x=3;x>=0;x--)
					{
						fprintf(stdout, "%02X ", buf[x]);
					}
					cout << "\n";
					//exit(1);
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