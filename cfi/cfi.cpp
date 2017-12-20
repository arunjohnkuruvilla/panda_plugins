/* PANDABEGINCOMMENT
 * 
 * Authors:
 *  Tim Leek               tleek@ll.mit.edu
 *  Ryan Whelan            rwhelan@ll.mit.edu
 *  Joshua Hodosh          josh.hodosh@ll.mit.edu
 *  Michael Zhivich        mzhivich@ll.mit.edu
 *  Brendan Dolan-Gavitt   brendandg@gatech.edu
 * 
 * This work is licensed under the terms of the GNU GPL, version 2. 
 * See the COPYING file in the top-level directory. 
 * 
PANDAENDCOMMENT */
// This needs to be defined before anything is included in order to get
// the PRIx64 macro
#define __STDC_FORMAT_MACROS

#include <distorm.h>
namespace distorm {
#include <mnemonics.h>
}
// Choose a granularity for the OSI code to be invoked.
#define INVOKE_FREQ_PGD
//#define INVOKE_FREQ_BBL

extern "C" {
    #include "config.h"
    #include "qemu-common.h"
    #include "panda_common.h"
    #include "cpu.h"

    #include "panda_plugin.h"
    #include "../osi/osi_types.h"
    #include "../osi/osi_ext.h"

    bool init_plugin(void *);
    void uninit_plugin(void *);

}

#include "../common/prog_point.h"
#include <map>
#include <set>
#include <vector>
#include <stack>
#include <algorithm>

enum instr_type {
  INSTR_UNKNOWN = 0,
  INSTR_CALL,
  INSTR_RET,
  INSTR_SYSCALL,
  INSTR_SYSRET,
  INSTR_SYSENTER,
  INSTR_SYSEXIT,
  INSTR_INT,
  INSTR_IRET,
};

struct stack_entry {
    uint32_t pc;
    instr_type kind;
};

int last_ret_size = 0;

// std::map<uint32_t, char*> thread_list;

// std::map<uint32_t,std::set<uint32_t>> stacks_seen;

// // Use a typedef here so we can switch between the stack heuristic and
// // the original code easily
// #ifdef USE_STACK_HEURISTIC
// typedef std::pair<uint32_t,uint32_t> stackid;
// uint32_t cached_sp = 0;
// uint32_t cached_asid = 0;
// #else
// typedef uint32_t stackid;
// #endif

uint8_t ret_status = 0;
// // stackid -> shadow stack
// std::map<stackid, std::vector<stack_entry>> callstacks;

// <process_id, thread_id> -> stack
std::map<std::pair<uint32_t, uint32_t>, std::vector<stack_entry>> user_stacks;

// <process_id, thread_id> -> stack
std::map<std::pair<uint32_t, uint32_t>, std::vector<stack_entry>> kernel_stacks;

// EIP -> instr_type
std::map<uint32_t, instr_type> call_cache;

// <process_id, thread_id> -> status
std::map<std::pair<uint32_t, uint32_t>, uint8_t> user_ret_status;

// <process_id, thread_id> -> status
std::map<std::pair<uint32_t, uint32_t>, uint8_t> kernel_ret_status;

// process_id -> thread_list
std::map<uint32_t, std::vector<uint32_t>> process_lists;

int vmi_pgd_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd);
int after_block_translate(CPUState *env, TranslationBlock *tb);
int before_block_exec(CPUState *env, TranslationBlock *tb);
int after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb);

instr_type disas_block(CPUState* env, uint32_t pc, int size) {
    unsigned char *buf = (unsigned char *) malloc(size);
    int err = panda_virtual_memory_rw(env, pc, buf, size, 0);
    if (err == -1) printf("Couldn't read TB memory!\n");
    instr_type res = INSTR_UNKNOWN;

#if defined(TARGET_I386)
    _DInst dec[256];
    unsigned int dec_count = 0;
    _DecodeType dt = (env->hflags & HF_LMA_MASK) ? Decode64Bits : Decode32Bits;

    _CodeInfo ci;
    ci.code = buf;
    ci.codeLen = size;
    ci.codeOffset = pc;
    ci.dt = dt;
    ci.features = DF_NONE;

    distorm_decompose(&ci, dec, 256, &dec_count);
    for (int i = dec_count - 1; i >= 0; i--) {
        if (dec[i].flags == FLAG_NOT_DECODABLE) {
            continue;
        }

        if (META_GET_FC(dec[i].meta) == FC_CALL) {
            res = INSTR_CALL;
            goto done;
        }
        else if (META_GET_FC(dec[i].meta) == FC_RET) {
            // Ignore IRETs
            if (dec[i].opcode == distorm::I_IRET) {
                res = INSTR_UNKNOWN;
            }
            else {
                // For debugging only
                if (dec[i].ops[0].type == O_IMM)
                    last_ret_size = dec[i].imm.sdword;
                else
                    last_ret_size = 0;
                res = INSTR_RET;
            }
            goto done;
        }
        else if (META_GET_FC(dec[i].meta) == FC_SYS) {
            res = INSTR_UNKNOWN;
            goto done;
        }
        else {
            res = INSTR_UNKNOWN;
            goto done;
        }
    }
#endif

done:
    free(buf);
    return res;
}

int get_current_return_status(CPUState *env, uint32_t process_id, uint32_t thread_id) {

    //printf("Searching for signature (%d, %d)\n", process_id, thread_id);
    std::map<std::pair<uint32_t, uint32_t>, uint8_t>::iterator current_ret_status;
    uint8_t status;
    if (panda_in_kernel(env)) {
        current_ret_status = kernel_ret_status.find(std::make_pair(process_id, thread_id));
        if (current_ret_status == kernel_ret_status.end()) {
            // printf("Signature (%d, %d) not found\n", process_id, thread_id);
            return 0;
        }
        else {
            // printf("Signature (%d, %d) found\n", process_id, thread_id);
            status = current_ret_status->second;
            current_ret_status->second = 0;
        }
    }
    else {
        current_ret_status = user_ret_status.find(std::make_pair(process_id, thread_id));
        if (current_ret_status == user_ret_status.end()) {
            // printf("Signature (%d, %d) not found\n", process_id, thread_id);
            return 0;
        }
        else {
            // printf("Signature (%d, %d) found\n", process_id, thread_id);
            status = current_ret_status->second;
            current_ret_status->second = 0;

        }
    }

    return status;

}

// uint32_t get_current_stack_remove(CPUState *env, uint32_t process_id, uint32_t thread_id) {
//     std::map<std::pair<uint32_t, uint32_t>, std::stack<stack_entry>>::iterator current_stack_map_entry;
//     std::pair<uint32_t, uint32_t> context;
//     context = std::make_pair(process_id, thread_id);
//     if (panda_in_kernel(env)) {
//         current_stack_map_entry = kernel_stacks.find(context);
//         if (current_stack_map_entry == kernel_stacks.end()) {
//             // printf("ERROR: Specified kernel stack empty\n");
//             return 0x2;
//         }
//         else {
//             std::stack<stack_entry> temp;
//             temp = current_stack_map_entry->second;
//             stack_entry prev_ret_stack_entry = temp.top();
//             temp.pop();
//             return prev_ret_stack_entry.pc;
//         }
//     }
//     else {
//         current_stack_map_entry = user_stacks.find(context);
//         if (current_stack_map_entry == user_stacks.end()) {
//             // printf("ERROR: Specified kernel stack empty\n");
//             return 0x2;
//         }
//         else {
//             std::stack<stack_entry> temp;
//             temp = current_stack_map_entry->second;
//             stack_entry prev_ret_stack_entry = temp.top();
//             temp.pop();
//             return prev_ret_stack_entry.pc;
//         }
//     }
// }

int set_ret_status(CPUState *env) {
    OsiThread *current_thread = get_current_thread(env);

    std::map<std::pair<uint32_t, uint32_t>, uint8_t>::iterator current_ret_status;
    if (panda_in_kernel(env)) {
        current_ret_status = kernel_ret_status.find(std::make_pair(current_thread->process_id, current_thread->thread_id));
        if (current_ret_status == kernel_ret_status.end()) {
            // printf("No kernel ret status entry to set\n");
            return 0;
        }
        else {
            // printf("kernel ret status entry set\n");
            current_ret_status->second = 1;
        }
    }
    else {
        current_ret_status = user_ret_status.find(std::make_pair(current_thread->process_id, current_thread->thread_id));
        if (current_ret_status == user_ret_status.end()) {
            // printf("No user ret status entry to set\n");
            return 0;
        }
        else {
            // printf("user ret status entry set\n");
            current_ret_status->second = 1;
        }
    }

    free_osithrd(current_thread);

    return 0;
}

// Implementation of Thread Stack Layout Identification algorithm in http://doi.acm.org/10.1145/2484313.2484352
std::vector<stack_entry> *get_current_stack_v2(CPUState *env) {
    OsiThread *current_thread = get_current_thread(env);

    bool new_thread = false;

    // std::map<uint32_t, std::vector<uint32_t>>::iterator process_map_entry;
    // process_map_entry = process_lists.find(current_thread->process_id);

    // if (process_map_entry == process_lists.end()) {
    //     std::vector<uint32_t> new_thread_list;
    //     std::pair<std::map<uint32_t, std::vector<uint32_t>>, bool> process_map_new_entry;
    //     process_map_new_entry = process_lists.insert(std::make_pair(current_thread->process_id, new_thread_list));
    //     process_map_entry = process_map_new_entry.first;
    //     printf("Process id: %d\n", process_map_entry->first);
    // }
    std::pair<std::map<uint32_t, std::vector<uint32_t>>, bool> process_map_new_entry;
    process_map_entry = process_lists.insert(std::make_pair(current_thread->process_id, new_thread_list));


    free_osithrd(current_thread);

}

std::vector<stack_entry> *get_current_stack(CPUState *env) {
    OsiThread *current_thread = get_current_thread(env);

    std::map<std::pair<uint32_t, uint32_t>, std::vector<stack_entry>>::iterator current_stack_map_entry;

    std::pair<std::map<std::pair<uint32_t, uint32_t>, std::vector<stack_entry>>::iterator, bool> new_stack_entry;

    if(panda_in_kernel(env)) {
        current_stack_map_entry = kernel_stacks.find(std::make_pair(current_thread->process_id, current_thread->thread_id));
        if (current_stack_map_entry == kernel_stacks.end()) {
            std::vector<stack_entry> new_stack;
            new_stack_entry = kernel_stacks.insert(std::make_pair(std::make_pair(current_thread->process_id, current_thread->thread_id), new_stack));
            kernel_ret_status.insert(std::make_pair(std::make_pair(current_thread->process_id, current_thread->thread_id), 0));
            return &new_stack_entry.first->second;
        }
    }
    else {
        current_stack_map_entry = user_stacks.find(std::make_pair(current_thread->process_id, current_thread->thread_id));
        if (current_stack_map_entry == user_stacks.end()) {
            std::vector<stack_entry> new_stack;
            new_stack_entry = user_stacks.insert(std::make_pair(std::make_pair(current_thread->process_id, current_thread->thread_id), new_stack));
            user_ret_status.insert(std::make_pair(std::make_pair(current_thread->process_id, current_thread->thread_id), 0));
            return &new_stack_entry.first->second;
        }
    }
    free_osithrd(current_thread);
    return &current_stack_map_entry->second;
}

int after_block_translate(CPUState *env, TranslationBlock *tb) {
    call_cache[tb->pc] = disas_block(env, tb->pc, tb->size);
    return 1;
}

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    OsiThread *current_thread = get_current_thread(env);
    free_osithrd(current_thread);
    return 0;
}

int after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *next) {
    OsiThread *current_thread = get_current_thread(env);
    OsiProc *current_process = get_current_process(env);

#if defined(TARGET_X86_64)
    // printf("Page from thread: %x\n", current_thread->stack_base);
    // printf("Page from ESP: %x\n", env->regs[R_ESP]);
    // printf("Page from thread: %x\n", current_thread->stack_limit);
    // printf("Test: %x\n", env->regs[R_ESP] - current_thread->stack_limit);
    // printf("-----------------------------\n");
    // assert(env->regs[R_ESP] < current_thread->stack_limit);
    // // (env->regs[R_ESP] < current_thread->stack_base) && (
    get_current_stack_v2(env);
#endif

    free_osiproc(current_process);
    free_osithrd(current_thread);
    return 1;
}

int vmi_pgd_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd) {
    // tb argument is not used by before_block_exec()
    return before_block_exec(env, NULL);
}

bool init_plugin(void *self) {

    panda_cb pcb;
    panda_enable_memcb();
    panda_enable_precise_pc();
    //panda_enable_tb_chaining();

#if defined(INVOKE_FREQ_PGD)
    // relatively short execution
    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);

    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    pcb.after_block_exec = after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

    pcb.after_PGD_write = vmi_pgd_changed ;
    panda_register_callback(self, PANDA_CB_VMI_PGD_CHANGED, pcb);
#else
    // expect this to take forever to run

    pcb.after_block_translate = after_block_translate;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_TRANSLATE, pcb);

    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

    pcb.after_block_exec = after_block_exec;
    panda_register_callback(self, PANDA_CB_AFTER_BLOCK_EXEC, pcb);

    pcb.before_block_exec = before_block_exec;
    panda_register_callback(self, PANDA_CB_BEFORE_BLOCK_EXEC, pcb);

#endif

    if(!init_osi_api()) return false;

    return true;
}

void uninit_plugin(void *self) { }
