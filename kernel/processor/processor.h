/// @file
/// @brief Main processor control interface.

#ifndef PROCESSOR_H_
#define PROCESSOR_H_

#include <stdint.h>

#include "klib/data_structures/lists.h"
#include "klib/synch/kernel_locks.h"
#include "mem/mem.h"
#include "object_mgr/handles.h"
#include "object_mgr/ref_counter.h"
#include "system_tree/system_tree_leaf.h"
#include "klib/data_structures/string.h"
#include "klib/synch/kernel_messages.h"
#include "processor/synch_objects.h"

#include "devices/device_interface.h"

// Main kernel interface to processor specific functions. Includes the task management system.

// Definition of a possible entry point:
typedef void (* ENTRY_PROC)();

// Forward declare task_thread since task_process and task_thread refer to each other in a cycle.
class task_thread;

/// Structure to hold information about a process. All information is stored here, to be accessed by the various
/// components as needed. This removes the need for per-component lookup tables for each process.
class task_process : public IRefCounted, public WaitObject
{
public:
  /// Refer ourself back to the process list.
  klib_list_item<task_process *> process_list_item;

  /// A list of all child threads.
  klib_list<task_thread *> child_threads;

  /// A pointer to the memory manager's information for this task.
  mem_process_info *mem_info;

  /// Is the process running in kernel mode?
  bool kernel_mode;

  /// The process's queue of waiting messages.
  msg_msg_queue message_queue;

  /// Does this process accept messages? Messages can't be sent to the process unless this flag is true. Accepting
  /// messages is optional as not all processes will need the capability to receive messages.
  bool accepts_msgs;

  /// Lock to control the message queue.
  kernel_spinlock message_lock;

  /// The message currently being handled by the process. Invalid if no message is being handled.
  klib_message_hdr cur_msg;

  /// Is a message currently being handled by the receiving process?
  bool msg_outstanding;

  /// The number of messages currently waiting for this process.
  uint64_t msg_queue_len;

  /// Is this process currently being destroyed?
  bool being_destroyed;

  /// Called externally when all child threads are destroyed.
  void destroy_process();

protected:
  void ref_counter_zero();
};

/// @brief Class to hold information about a thread.
///
/// At present, the thread class has no real internal logic. This is all delegated to function-based code in
/// task_manager.cpp as it comes from a very early point in the project.
///
/// task_thread derives from WaitObject, but doesn't change the default logic of that class. The WaitObject is
/// signalled when the thread is scheduled for destruction.
class task_thread : public IRefCounted, public WaitObject
{
public:
  void destroy_thread();

  /// This thread's parent process. The process defines the address space, permissions, etc.
  task_process *parent_process;

  /// An entry for the parent's thread list.
  klib_list_item<task_thread *> process_list_item;

  /// A pointer to the thread's execution context. This is processor specific, so no specific structure can
  /// be pointed to. Only processor-specific code should access this field.
  void *execution_context;

  /// Is the thread running? It will only be considered for execution if so.
  volatile bool permit_running;

  /// Should the scheduler release it's acquisition of this thread? The thread will delete itself when no-one is
  /// interested in it any more. This should only be set by task_destroy_thread().
  bool release_thread;

  /// Has the thread been destroyed? Various operations are not permitted on a destroyed thread. This object will
  /// continue to exist until all references to it have been released.
  bool thread_destroyed;

  /// A pointer to the next thread. In normal operation, these form a cycle of threads, and the task manager is able
  /// to manipulate this cycle without breaking the chain.
  task_thread *next_thread;

  /// A lock used by the task manager to claim ownership of this thread. It has several meanings:
  /// - The task manager might be about to manipulate the thread cycle, so the scheduler should avoid scheduling this
  ///   thread
  /// - The scheduler might be running this thread, in which case no other processor should run it as well
  kernel_spinlock cycle_lock;

  // This item is used to associate the thread with the list of threads waiting for a mutex, semaphore or other
  // synchronization primitive. The list itself is owned by that primitive, but this item must be initialized with the
  // rest of this structure.
  klib_list_item<task_thread *> synch_list_item;

protected:
  void ref_counter_zero();
};

/// @brief Processor-specific information.
///
/// One of the processor-specific header files should typedef this struct with an appropriate template to create the
/// type processor_info.
template <typename T> struct processor_info_generic
{
  /// A zero-based ID for the processor to be identified by. In the range 0 -> n-1, where n is the number of processors
  /// in the system
  uint32_t processor_id;

  /// Has the processor been started or not? That is, (in x64 speak) has it finished responding to the STARTUP IPI?
  volatile bool processor_running;

  /// Platform specific processor information
  T platform_data;
};

/// Possible messages to signal between processes
enum class PROC_IPI_MSGS
{
  RESUME,          ///< Bring the processor back in to action after suspending it.
  SUSPEND,         ///< Halt the processor with interrupts disabled.
  TLB_SHOOTDOWN,   ///< Invalidate the processor's page tables.
  RELOAD_IDT,      ///< Pick up changes to the system IDT.
};

// Initialise the first processor and some of the data structures needed to manage all processors in the system.
void proc_gen_init();

// Continue initialisation such that the other processors can be started, but leave them idle for now.
void proc_mp_init();

// Start all APs.
void proc_mp_start_aps();

// Stop the processor this function is called on. It may then be reinitialised later.
void proc_stop_this_proc();

// Stop all other processors except this one.
void proc_stop_other_procs();

// Stop all processors, including this one. The system will completely stop.
void proc_stop_all_procs();

// Stop / start interrupts on this processor. It's not advisable for most code to call these functions, due to the
// performance impact.
void proc_stop_interrupts();
void proc_start_interrupts();

// Initialise the task management system.
task_process *task_init();
void task_gen_init();

// Begin multi-tasking
void task_start_tasking();

// Create a new process, with a thread starting at entry_point.
task_process *task_create_new_process(ENTRY_PROC entry_point,
    bool kernel_mode = false,
    mem_process_info *mem_info = nullptr);

void task_set_start_params(task_process * process, uint64_t argc, char **argv, char **env);

// Create a new thread starting at entry_point, with parent parent_process.
task_thread *task_create_new_thread(ENTRY_PROC entry_point, task_process *parent_process);

// Destroy a thread immediately.
void task_destroy_thread(task_thread *unlucky_thread);

// Destroy a process (and by definition, all threads within it) immediately.
void task_destroy_process(task_process *unlucky_process);

// Return information about a specific task. This is intended to allow the various components to access their data,
// without having to store a parallel task list internally.
task_thread *task_get_cur_thread();

// Start and stop threads and processes
void task_start_process(task_process *process);
void task_stop_process(task_process *process);
void task_start_thread(task_thread *thread);
void task_stop_thread(task_thread *thread);
void task_yield();

// Multiple processor control functions
uint32_t proc_mp_proc_count();
uint32_t proc_mp_this_proc_id();
void proc_mp_signal_processor(uint32_t proc_id, PROC_IPI_MSGS msg);
void proc_mp_signal_all_processors(PROC_IPI_MSGS msg);
void proc_mp_receive_signal(PROC_IPI_MSGS msg);

// Force the scheduler to re-schedule this thread continually, or allow it to schedule normally. This allows a thread
// to avoid being preempted in a state that might leave it in a deadlock. Naturally, it must be used with extreme care!
void task_continue_this_thread();
void task_resume_scheduling();

uint64_t proc_read_port(const uint64_t port_id, const uint8_t width);
void proc_write_port(const uint64_t port_id, const uint64_t value, const uint8_t width);

void proc_register_irq_handler(uint8_t irq_number, IIrqReceiver *receiver);
void proc_unregister_irq_handler(uint8_t irq_number, IIrqReceiver *receiver);

#ifdef AZALEA_TEST_CODE
void test_only_reset_task_mgr();
#endif

#endif /* PROCESSOR_H_ */