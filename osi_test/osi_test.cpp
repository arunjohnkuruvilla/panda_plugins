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
#include <mnemonics.h>
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
#include <iostream>
#include <fstream>
#include <map>
#include <set>
#include <vector>
#include <stack>
#include <algorithm>

#define PROCESS_ID 0x754
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
    INSTR_UNC_JUMP,
    INSTR_CND_JUMP
};

struct stack_entry {
    uint32_t pc;
    instr_type kind;
};

// Entry for call_jump_cache
typedef struct jump_instr_entry {
    uint32_t target_address;
    instr_type type;
} transfer_instr;

int last_ret_size = 0;

const char *whitelist_src = 0;

std::map<uint32_t, std::vector<uint32_t>> whitelist;

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
// std::map<uint32_t, instr_type> call_cache;

// EIP -> jump_instr_type
std::map<uint32_t, transfer_instr> call_cache;

// <process_id, thread_id> -> status
std::map<std::pair<uint32_t, uint32_t>, uint8_t> user_ret_status;

// <process_id, thread_id> -> status
std::map<std::pair<uint32_t, uint32_t>, uint8_t> kernel_ret_status;

int vmi_pgd_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd);
int after_block_translate(CPUState *env, TranslationBlock *tb);
int before_block_exec(CPUState *env, TranslationBlock *tb);
int after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *next_tb);

transfer_instr disas_block(CPUState* env, uint32_t pc, int size) {
    unsigned char *buf = (unsigned char *) malloc(size);
    int err = panda_virtual_memory_rw(env, pc, buf, size, 0);
    if (err == -1) printf("Couldn't read TB memory!\n");

    uint32_t target_address = 0x0;
    instr_type res = INSTR_UNKNOWN;

    transfer_instr return_instr;

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
            if (dec[i].opcode == I_IRET) {
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
        // Cheching for unconditional jumps
        else if (META_GET_FC(dec[i].meta) == FC_UNC_BRANCH) {
            if (dec[i].ops[0].type == O_PC) {
                res = INSTR_UNC_JUMP;
                target_address = INSTRUCTION_GET_TARGET(&dec[i]);
                // printf("Target Address in Unconditional Jump: %x\n", INSTRUCTION_GET_TARGET(&dec[i]));
            }
            else {
                // printf("Indirect addressing used\n");
                res = INSTR_UNKNOWN;
            }
            goto done;
        }
        // Cheching for conditional jumps
        else if (META_GET_FC(dec[i].meta) == FC_CND_BRANCH) {
            if (dec[i].ops[0].type == O_PC) {
                res = INSTR_CND_JUMP;
                target_address = INSTRUCTION_GET_TARGET(&dec[i]);
                // printf("Target Address in Conditional Jump: %x\n", INSTRUCTION_GET_TARGET(&dec[i]));
                // printf("%x\n", INSTRUCTION_GET_TARGET(&dec[i]));
            }
            else {
                // printf("Indirect addressing used\n");
                res = INSTR_UNKNOWN;
            }
            
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
    return_instr.target_address = target_address;
    return_instr.type = res;
    return return_instr;
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

void load_whitelist() {
    // printf("HERE\n");
    // std::ifstream file (whitelist);
    // std::vector<std::vector<std::string>> table = readCSV(file);
    // printf("%c\n", table[0]);
    // printf("%c\n", table[2]);
    // exit(1);
    std::vector<uint32_t> temp;
    temp.push_back(0x82a3160c);
    temp.push_back(0x82a31676);
    temp.push_back(0x82a315e0);
    temp.push_back(0x82a3160c);

    whitelist[0x0] = temp;
}

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
// std::vector<stack_entry> *get_current_stack_v2(CPUState *env) {
//     OsiThread *current_thread = get_current_thread();

//     bool new_thread = false;


//     free_osithrd(current_thread);
// }

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

void pop_until_address(std::vector<stack_entry> *current_stack, uint32_t addr) {
    while(current_stack->back().pc != addr) {
        current_stack->pop_back();
    }
    current_stack->pop_back();
}

int after_block_translate(CPUState *env, TranslationBlock *tb) {
    OsiThread *current_thread = get_current_thread(env);
    call_cache[tb->pc] = disas_block(env, tb->pc, tb->size);
    free_osithrd(current_thread);
    return 1;
}

int before_block_exec(CPUState *env, TranslationBlock *tb) {
    OsiThread *current_thread = get_current_thread(env);

    bool stack_status = false;
    if (get_current_return_status(env, current_thread->process_id, current_thread->thread_id) == 1) {
        std::vector<stack_entry> *current_thread_stack = get_current_stack(env);

        if (!current_thread_stack->empty()) {
            stack_entry top_entry = current_thread_stack->back();

            if((top_entry.pc != tb->pc) && (current_thread->process_id == PROCESS_ID)) {
                printf("Popping Function call(%d, %d, %s).\n", current_thread->process_id, current_thread->thread_id, current_thread->process_name);
                printf("Popped PC: %x\n", top_entry.pc);
                printf("Current PC: %x\n", tb->pc);
                printf("Printing Stack\n");
                for(std::vector<stack_entry>::reverse_iterator it = current_thread_stack->rbegin(); it != current_thread_stack->rend(); ++it) {
                    if (it->pc == tb->pc) {
                        stack_status = true;
                    }
                }
                if (stack_status) {
                    pop_until_address(current_thread_stack, tb->pc);
                }
                else {
                    for(std::vector<stack_entry>::reverse_iterator it = current_thread_stack->rbegin(); it != current_thread_stack->rend(); ++it) {
                        printf("%x\t", it->pc);
                    }
                    printf("\n");
                }
                
            }
            if((top_entry.pc == tb->pc) && (current_thread->process_id == PROCESS_ID)) {
                // printf("Popping Success call in (%d, %d, %s): %x.\n", current_thread->process_id, current_thread->thread_id, current_thread->process_name, tb->pc);
                current_thread_stack->pop_back();
            }
            
        }
        // else {
        //     printf("Stack empty\n");
        // }
        // if (return_pc == 0x0) {
        //     return 0;
        // }
        // else {
        //     printf("Popped PC: %x\n", return_pc);
        //     printf("Currnt PC: %x\n", tb->pc);
        //     // assert(return_pc == tb->pc);
        //     if (return_pc != tb->pc) {

        //     }
        //     assert(return_pc == tb->pc);
        // }
        
        // printf("Next instruction after RET return is: "TARGET_FMT_lx"\n", return_pc);
        free_osithrd(current_thread);
        return 0;
    }
    if (get_current_return_status(env, current_thread->process_id, current_thread->thread_id) == 0x2){
        printf("Invalid thread detected.\n");
        exit(1);
    }

    // //     printf("Next instruction after RET return is: "TARGET_FMT_lx"\n", tb->pc);
    // //     // uint32_t return_address = function_stacks[get_threadid(env,tb->pc)].pop(pc);

    // //     stack_entry return_item = get_current_stack(env).pop();

    // //     assert(return_item->pc == tb->pc);
    // // }
    free_osithrd(current_thread);
    return 0;
}

int is_present_in_whitelist(uint32_t process_id, uint32_t target_address) {
    std::map<uint32_t, std::vector<uint32_t>>::iterator iter;
    iter = whitelist.find(process_id);
    if (iter == whitelist.end()) {
        return 0;
    }
    for(std::vector<uint32_t>::iterator it = iter->second.begin(); it != iter->second.end(); ++it) {
        if (*it == target_address) {
            return 1;
        }
    }
    return 0;
}
int after_block_exec(CPUState *env, TranslationBlock *tb, TranslationBlock *next) {
    OsiThread *current_thread = get_current_thread(env);
    OsiProc *current_process = get_current_process(env);
//     ret_status = 0;
//     // OsiThread *current_thread = get_current_thread(env);
//     // printf("Current thread: %d\n", current_thread->thread_id);

#ifdef TARGET_X86_64

    transfer_instr tb_type = call_cache[tb->pc];

    if (tb_type.type == INSTR_CALL) {

        // stack_entry se = {tb->pc+tb->size,tb_type};
        // callstacks[get_stackid(env,tb->pc)].push_back(se);

        // Also track the function that gets called
        // uint32_t pc, cs_base;
        // int flags;
        // This retrieves the pc in an architecture-neutral way
        // cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
        //function_stacks[get_threadid(env,tb->pc)].push(pc);

        stack_entry se = {
            tb->pc+tb->size, 
            tb_type.type
        };

        // std::stack<stack_entry> *current_thread_stack = get_current_stack(env);
        // // OsiThread *current_thread = get_current_thread(env);
        // // printf("Function call in (%d, %d). Pushing into stack: %x\n", current_thread->process_id, current_thread->thread_id, tb->pc+tb->size);
        // // free_osithrd(current_thread);
        // current_thread_stack->push(se);
        // if (current_thread->process_id == PROCESS_ID) {
            std::vector<stack_entry> *current_thread_stack = get_current_stack(env);
            // OsiThread *current_thread = get_current_thread(env);
            // printf("Function call in (%d, %d). Pushing into stack: %x\n", current_thread->process_id, current_thread->thread_id, tb->pc+tb->size);
            // free_osithrd(current_thread);
            current_thread_stack->push_back(se);
        // }
        // printf("Stack size for (%d, %d) is %d\n", current_thread->process_id, current_thread->thread_id, current_thread_stack->size());

        // OsiThread *current_thread = get_current_thread(env);

        // std::map<uint32_t, std::stack<stack_entry>>::iterator current_stack_map_entry;



        // if (panda_in_kernel(env)) {
        //     current_stack_map_entry = kernel_stacks.find(current_thread->thread_id);
        //     if (current_stack_map_entry == kernel_stacks.end()) {
        //         std::stack<stack_entry> new_stack;
        //         new_stack.push(se);
        //         uint32_t temp_id = current_thread->thread_id;
        //         kernel_stacks.insert(std::make_pair(temp_id, new_stack));
        //     }
        //     else {
        //         std::stack<stack_entry> temp;
        //         temp = current_stack_map_entry->second;
        //         temp.push(se);

        //     }
        // }
        // else {
        //     current_stack_map_entry = user_stacks.find(current_thread->thread_id);
        //     if (current_stack_map_entry == user_stacks.end()) {
        //         std::stack<stack_entry> new_stack;
        //         new_stack.push(se);
        //         uint32_t temp_id = current_thread->thread_id;
        //         user_stacks.insert(std::make_pair(temp_id, new_stack));
        //     }
        //     else {
        //         std::stack<stack_entry> temp;
        //         temp = current_stack_map_entry->second;
        //         temp.push(se);

        //     }
        // }

        
        // current_stack.push(se);

        // printf("Just executed a INSTR_CALL in " TARGET_FMT_lx "\n", tb->pc);
        
    }
    else if (tb_type.type == INSTR_RET) {

        // std::stack<stack_entry>
        // get_current_return_stack(env);
           set_ret_status(env); 
        
        // OsiThread *current_thread = get_current_thread(env);
        // printf("Return call in (%d, %d). Popping from stack\n", current_thread->process_id, current_thread->thread_id);
        // free_osithrd(current_thread);

        
        // target_ulong pc, cs_base;
        // int flags;
        // // This retrieves the pc in an architecture-neutral way
        // cpu_get_tb_cpu_state(env, &pc, &cs_base, &flags);
        // std::stack<stack_entry> *current_thread_stack = get_current_stack(env);

        // // printf("Stack size for (%d, %d) is %d\n", current_thread->process_id, current_thread->thread_id, current_thread_stack->size());

        
        // if (!current_thread_stack->empty()) {
        //     stack_entry top_entry = current_thread_stack->top();

        //     if((top_entry.pc != pc) && (current_thread->process_id == 0x754)) {
                
        //         printf("Popping Function call in (%d, %d, %s): %x.\n", current_thread->process_id, current_thread->thread_id, current_thread->process_name, tb->pc);
        //         printf("Popped PC: %x\n", top_entry.pc);
        //         printf("Current PC: %x\n", pc);
        //     }

        //     current_thread_stack->pop();
        // }
        
        // printf("Address to be popped from stack: %x\n", pc);
        //if (next) printf("Next TB: " TARGET_FMT_lx "\n", next->pc);
    }
    else if (tb_type.type == INSTR_UNC_JUMP) {
        printf("Unconditional jump address:");
        printf("%x\n", next->pc);
        // if(is_present_in_whitelist(current_thread->process_id, tb_type.target_address)) {
        //     printf("Valid jump. Continuing.\n");
        // }
        // else {
        //     printf("Invalid jump. ALERT.\n");
        //     exit(1);
        // }
    }

    else if (tb_type.type == INSTR_CND_JUMP) {
        printf("Conditional jump address:");
        printf("%x\n", next->pc);
        // if(is_present_in_whitelist(current_thread->process_id, tb_type.target_address)) {
        //     printf("Valid jump. Continuing.\n");
        // }
        // else {
        //     printf("Invalid jump. ALERT.\n");
        //     exit(1);
        // }
    }

// #elif defined TARGET_X86_64
    

//     assert(env->regs[R_ESP] >= current_thread->stack_base &&  env->regs[R_ESP] < (current_thread->stack_base + current_thread->stack_limit));

//     printf("ESP value:%x\n", env->regs[R_ESP]);
//     printf("Assertion success\n");
//     // instr_type tb_type = call_cache[tb->pc];

//     // if (tb_type == INSTR_CALL) {

//     // }
//     // else if (tb_type == INSTR_RET) {
//     //     //printf("Just executed a RET in TB " TARGET_FMT_lx "\n", tb->pc);
//     //     //if (next) printf("Next TB: " TARGET_FMT_lx "\n", next->pc);
//     // }
#endif
    free_osiproc(current_process);
    free_osithrd(current_thread);
    return 1;
}

int vmi_pgd_changed(CPUState *env, target_ulong old_pgd, target_ulong new_pgd) {
    // tb argument is not used by before_block_exec()
    return before_block_exec(env, NULL);
}

// enum class CSVState {
//     UnquotedField,
//     QuotedField,
//     QuotedQuote
// };

// std::vector<std::string> readCSVRow(const std::string &row) {
//     CSVState state = CSVState::UnquotedField;
//     std::vector<std::string> fields {""};
//     size_t i = 0; // index of the current field
//     for (char c : row) {
//         switch (state) {
//             case CSVState::UnquotedField:
//                 switch (c) {
//                     case ',': // end of field
//                               fields.push_back(""); i++;
//                               break;
//                     case '"': state = CSVState::QuotedField;
//                               break;
//                     default:  fields[i].push_back(c);
//                               break; }
//                 break;
//             case CSVState::QuotedField:
//                 switch (c) {
//                     case '"': state = CSVState::QuotedQuote;
//                               break;
//                     default:  fields[i].push_back(c);
//                               break; }
//                 break;
//             case CSVState::QuotedQuote:
//                 switch (c) {
//                     case ',': // , after closing quote
//                               fields.push_back(""); i++;
//                               state = CSVState::UnquotedField;
//                               break;
//                     case '"': // "" -> "
//                               fields[i].push_back('"');
//                               state = CSVState::QuotedField;
//                               break;
//                     default:  // end of quote
//                               state = CSVState::UnquotedField;
//                               break; }
//                 break;
//         }
//     }
//     return fields;
// }

// /// Read CSV file, Excel dialect. Accept "quoted fields ""with quotes"""
// std::vector<std::vector<std::string>> readCSV(std::istream &in) {
//     std::vector<std::vector<std::string>> table;
//     std::string row;
//     while (!in.eof()) {
//         std::getline(in, row);
//         if (in.bad() || in.fail()) {
//             break;
//         }
//         auto fields = readCSVRow(row);
//         table.push_back(fields);
//     }
//     return table;
// }



bool init_plugin(void *self) {

    panda_cb pcb;
    panda_enable_memcb();
    panda_enable_precise_pc();

    // panda_arg_list *args = panda_get_args("osi_test");
    // const char *whitelist = panda_parse_string(args, "whitelist", NULL);

    load_whitelist();
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
