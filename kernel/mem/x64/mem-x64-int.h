// Contains x64-specific declarations.

#ifndef MEM_X64_INT_H_
#define MEM_X64_INT_H_

#include <stdint.h>

// Initial address of the PML4 paging address table.
extern uint64_t pml4_table;

const uint16_t PML4_LENGTH = 4096;

struct page_table_entry
{
  uint64_t target_addr;
  bool present;
  bool writable;
  bool user_mode;
  bool end_of_tree;
  uint8_t cache_type;
};

/// @brief Memory-manager data that is per-process and specific to the x64 architecture.
///
struct process_x64_data
{
  klib_list_item<process_x64_data *> pml4_list_item;

  uint64_t pml4_phys_addr;
  uint64_t pml4_virt_addr;
};

void mem_x64_map_virtual_page(uint64_t virt_addr,
                              uint64_t phys_addr,
                              task_process *context = nullptr,
                              MEM_CACHE_MODES cache_mode = MEM_WRITE_BACK);
void mem_x64_unmap_virtual_page(uint64_t virt_addr, task_process *context);

uint64_t mem_encode_page_table_entry(page_table_entry &pte);
page_table_entry mem_decode_page_table_entry(uint64_t encoded);
void mem_set_working_page_dir(uint64_t phys_page_addr);
extern "C" void mem_invalidate_page_table(uint64_t virt_addr);
uint64_t mem_x64_phys_addr_from_pte(uint64_t encoded);

#define PT_MARKED_PRESENT(x) ((x) & 1)

void mem_x64_pml4_init_sys(process_x64_data &task0_data);
void mem_x64_pml4_allocate(process_x64_data &new_proc_data);
void mem_x64_pml4_deallocate(process_x64_data &proc_data);
void mem_x64_pml4_synchronize(void *updated_pml4_table);
uint64_t *get_pml4_table_addr(task_process *context = nullptr);

extern void *mem_x64_kernel_stack_ptr;

// x64 Cache control declarations

// Note the mapping between these and MEM_CACHE_MODES - the latter is meant to be platform independent, but at the
// moment (while only x64 is supported) they have a 1:1 mapping.
namespace MEM_X64_CACHE_TYPES
{
  const uint8_t UNCACHEABLE = 0;
  const uint8_t WRITE_COMBINING = 1;
  const uint8_t WRITE_THROUGH = 4;
  const uint8_t WRITE_PROTECTED = 5;
  const uint8_t WRITE_BACK = 6;
}

uint8_t mem_x64_pat_get_val(const uint8_t cache_type, bool first_half);
uint8_t mem_x64_pat_decode(const uint8_t pat_idx);

#endif
