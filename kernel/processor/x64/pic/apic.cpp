/// @file
/// @brief Interface to control the APIC (but not x2APIC)

//#define ENABLE_TRACING

#include "klib/klib.h"
#include "apic.h"
#include "pic.h"
#include "processor/x64/processor-x64.h"
#include "processor/x64/processor-x64-int.h"

const uint64_t APIC_ENABLED = 0x0000000000000800;
const uint8_t APIC_SPURIOUS_INT_VECTOR = 127;
const uint32_t APIC_SIV_FLAGS = 0x100;
const uint64_t icr_delivery_status = 0x1000;

static apic_registers **local_apics = nullptr;

/// @brief Prepare the system to use APICs on all its processors
void proc_x64_configure_sys_apic_mode(uint32_t num_procs)
{
  KL_TRC_ENTRY;

  local_apics = new apic_registers *[num_procs];
  for (int i = 0; i < num_procs; i++)
  {
    local_apics[i] = nullptr;
  }

  KL_TRC_EXIT;
}

/// @brief Configures this processor to use its APIC.
void proc_x64_configure_local_apic_mode()
{
  KL_TRC_ENTRY;

  static_assert(sizeof(apic_registers) == 1024, "APIC register struct must be 1KB in size");

  asm_proc_disable_legacy_pic();
  proc_x64_configure_local_apic();

  end_of_irq_ack_fn = (void *)proc_x64_apic_irq_ack;

  KL_TRC_EXIT;
}

/// @brief Configures the processor's local APIC.
void proc_x64_configure_local_apic()
{
  KL_TRC_ENTRY;

  uint64_t apic_ctrl = proc_read_msr(PROC_X64_MSRS::IA32_APIC_BASE);
  uint64_t apic_base_addr;
  uint64_t page_base;
  uint64_t offset;
  uint32_t this_proc_id = proc_mp_this_proc_id();
  void *virtual_page;

  KL_TRC_TRACE(TRC_LVL::EXTRA, "Configuring APIC for processor", this_proc_id, "\n");

  // Make sure the APIC is actually enabled. At this point, interrupts are still disabled (by use of CLI)
  KL_TRC_TRACE(TRC_LVL::EXTRA, "APIC control flags", apic_ctrl, "\n");
  if (!(apic_ctrl & APIC_ENABLED))
  {
    KL_TRC_TRACE(TRC_LVL::FLOW, "Enabling APIC\n");
    apic_ctrl |= APIC_ENABLED;
    proc_write_msr(PROC_X64_MSRS::IA32_APIC_BASE, apic_ctrl);
  }

  // The APICs registers need mapping so that we can actually access them!
  apic_base_addr = apic_ctrl & 0xFFFFFFFFFFFFF000;
  offset = apic_base_addr % MEM_PAGE_SIZE;
  page_base = apic_base_addr - offset;
  virtual_page = mem_allocate_virtual_range(1);
  mem_map_range((void *)page_base, virtual_page, 1, nullptr, MEM_UNCACHEABLE);
  local_apics[this_proc_id] = (apic_registers *)(((uint64_t)virtual_page) + offset);

  // Configure a spurious interrupt vector, and using the magic flags, enable the APIC to send interrupts
  proc_configure_idt_entry(APIC_SPURIOUS_INT_VECTOR, 0, (void *)asm_proc_apic_spurious_interrupt, 0);
  asm_proc_install_idt();
  local_apics[this_proc_id]->spurious_interrupt_vector = APIC_SIV_FLAGS | APIC_SPURIOUS_INT_VECTOR;

  // The system relies on the value of the APIC ID provided by CPUID to identify processors, but the actual APIC ID
  // stored in the APIC registers is how they are addressed for interrupt routing. Make sure they match up.
  ASSERT(proc_x64_apic_get_local_id() == ((local_apics[this_proc_id]->local_apic_id & 0xFF000000) >> 24));

  KL_TRC_EXIT;
}

/// @brief Acknowledge an IRQ generated by the APIC.
void proc_x64_apic_irq_ack()
{
  KL_TRC_ENTRY;

  uint32_t this_proc_id = proc_mp_this_proc_id();
  KL_TRC_TRACE(TRC_LVL::EXTRA, "Acknowledging for proc", this_proc_id, "\n");
  local_apics[this_proc_id]->end_of_interrupt = 1;

  KL_TRC_EXIT;
}

/// @brief Get the ID of the local APIC
///
/// This can then be used as the index either for the target of IPIs, or to tell us which processor we're running on.
///
/// @return The ID of the local APIC.
uint8_t proc_x64_apic_get_local_id()
{
  KL_TRC_ENTRY;

  uint64_t ebx_eax;
  uint64_t edx_ecx;
  uint8_t id;

  //id = ((local_apic->local_apid_id & 0xFF000000) >> 24);
  asm_proc_read_cpuid(1, 0, &ebx_eax, &edx_ecx);
  id = static_cast<uint8_t>(ebx_eax >> 56);

  KL_TRC_TRACE(TRC_LVL::EXTRA, "Local APID ID", id, "\n");

  KL_TRC_EXIT;

  return id;
}

/// @brief Send an IPI to another processor.
///
/// A more detailed description of the meaning of these parameters can be found in the Intel System Programming Guide.
///
/// @param apic_dest The ID of the APIC to send the IPI to. May be zero if a shorthand is used.
///
/// @param shorthand If needed, the shorthand code for signalling multiple processors at once
///
/// @param interrupt The desired type of IPI to send
///
/// @param vector The vector number for this IPI. Depending on the type of IPI being sent, this may be ignored. For
///               INIT IPIs, 0 indicates ASSERT, 1 indicates deassert.
///
/// @param wait_for_delivery True if this processor should wait for the interrupt to have been delivered to the target.
void proc_apic_send_ipi(const uint32_t apic_dest,
                        const PROC_IPI_SHORT_TARGET shorthand,
                        const PROC_IPI_INTERRUPT interrupt,
                        const uint8_t vector,
                        const bool wait_for_delivery)
{
  KL_TRC_ENTRY;

  uint8_t short_code = static_cast<uint8_t>(shorthand);
  uint8_t int_code = static_cast<uint8_t>(interrupt);
  uint32_t this_proc_id = proc_mp_this_proc_id();
  uint32_t reg_high_part;
  uint32_t reg_low_part;
  uint32_t longer_vector = vector;

  KL_TRC_TRACE(TRC_LVL::EXTRA, "IPI destination", apic_dest, "\n");
  KL_TRC_TRACE(TRC_LVL::EXTRA, "Shorthand dest", short_code, "\n");
  KL_TRC_TRACE(TRC_LVL::EXTRA, "Interrupt to signal", int_code, "\n");
  KL_TRC_TRACE(TRC_LVL::EXTRA, "Interrupt vector", vector, "\n");

  if (interrupt == PROC_IPI_INTERRUPT::INIT)
  {
    if (vector == 0)
    {
      KL_TRC_TRACE(TRC_LVL::FLOW, "INIT level assert\n");
      longer_vector = 1 << 14;
    }
    else
    {
      KL_TRC_TRACE(TRC_LVL::FLOW, "INIT level deassert\n");
      longer_vector = 1 << 15;
    }
  }

  reg_high_part = apic_dest << 24;
  reg_low_part = ((uint32_t)short_code << 18) | ((uint32_t)int_code << 8) | longer_vector;

  KL_TRC_TRACE(TRC_LVL::EXTRA, "Register being written", ((uint64_t)reg_high_part << 32) | reg_low_part, "\n");

  // The high part must be written first, as writing the low part causes the interrupt to be sent.
  local_apics[this_proc_id]->lvt_interrupt_command_2 = reg_high_part;
  local_apics[this_proc_id]->lvt_interrupt_command_1 = reg_low_part;

  while (wait_for_delivery && ((local_apics[this_proc_id]->lvt_interrupt_command_1 & icr_delivery_status) != 0))
  {
    // Wait!
  }

  KL_TRC_EXIT;
}
