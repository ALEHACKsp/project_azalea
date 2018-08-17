#ifndef _TEST_CORE_H
#define _TEST_CORE_H

// Allow asserting in all tests. Expect to be linked against the dummy panic lib
// so that panics are caught by the test system.
#include "klib/misc/assert.h"
#include "klib/tracing/tracing.h"
#include "klib/panic/panic.h"

class assertion_failure
{
public:
  assertion_failure(const char *reason);
  const char *get_reason();

private:
  const char *_reason;
};

void test_spin_sleep(uint64_t sleep_time_ns);

// defined in processor.dummy.cpp
class task_thread;
void test_only_set_cur_thread(task_thread *thread);

#endif
