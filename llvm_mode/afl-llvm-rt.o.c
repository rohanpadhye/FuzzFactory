/*
   american fuzzy lop - LLVM instrumentation bootstrap
   ---------------------------------------------------

   Written by Laszlo Szekeres <lszekeres@google.com> and
              Michal Zalewski <lcamtuf@google.com>

   LLVM integration design comes from Laszlo Szekeres.

   Copyright 2015, 2016 Google Inc. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     http://www.apache.org/licenses/LICENSE-2.0

   This code is the rewrite of afl-as.h's main_payload.

*/

#include "../config.h"
#include "../types.h"
#include "waypoints.h"

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>
#include <string.h>
#include <assert.h>

#include <sys/mman.h>
#include <sys/shm.h>
#include <sys/wait.h>
#include <sys/types.h>

/* This is a somewhat ugly hack for the experimental 'trace-pc-guard' mode.
   Basically, we need to make sure that the forkserver is initialized after
   the LLVM-generated runtime initialization pass, not before. */

#ifdef USE_TRACE_PC
#  define CONST_PRIO 5
#else
#  define CONST_PRIO 1 // Let domain-specific front-ends initialize before forkserver
#endif /* ^USE_TRACE_PC */


/* Globals needed by the injected instrumentation. The __afl_area_initial region
   is used for instrumentation output before __afl_map_shm() has a chance to run.
   It will end up as .comm, so it shouldn't be too wasteful. */

u8  __afl_area_initial[MAP_SIZE * (DSF_MAX*sizeof(u32) + 1)];
u8* __afl_area_ptr = __afl_area_initial;                /* Main coverage map */

__thread u32 __afl_prev_loc;

/* Domain-specific fuzzing */
u32* __fuzzfactory_dsf_map = (u32*) (&__afl_area_initial[MAP_SIZE]); /* Additional feedback maps */
static dsf_config dsf_configs[DSF_MAX]; // Array of configs
static u32 dsf_count = 0; // Length of above array (i.e, number of non-zero items)

/* Running in persistent mode? */

static u8 is_persistent;


/* SHM setup. */

static void __afl_map_shm(void) {

  u8 *id_str = getenv(SHM_ENV_VAR);

  /* If we're running under AFL, attach to the appropriate region, replacing the
     early-stage __afl_area_initial region that is needed to allow some really
     hacky .init code to work correctly in projects such as OpenSSL. */

  if (id_str) {

    u32 shm_id = atoi(id_str);

    __afl_area_ptr = shmat(shm_id, NULL, 0);

    /* Whooooops. */

    if (__afl_area_ptr == (void *)-1) _exit(1);

    /* Write something into the bitmap so that even with low AFL_INST_RATIO,
       our parent doesn't give up on us. */

    __afl_area_ptr[0] = 1;
    
    /* Set waypoints map to be after the AFL code coverage shared memory region */
    __fuzzfactory_dsf_map = (u32*) &__afl_area_ptr[MAP_SIZE];

  }

}


/* Fork server logic. */

static void __afl_start_forkserver(void) {

  s32 child_pid;

  u8  child_stopped = 0;

  /* Phone home and tell the parent that we're OK. If parent isn't there,
     assume we're not running in forkserver mode and just execute program. */

  /* The value we send back is the number of domain-specific maps registered. */

  if (write(FORKSRV_FD + 1, &dsf_count, 4) != 4) return;

  if (dsf_count > 0) {
    // Send back config for each registered dsf
    if (write(FORKSRV_FD + 1, dsf_configs, sizeof(dsf_config) * dsf_count) != sizeof(dsf_config) * dsf_count) _exit(1);
  }

  while (1) {

    u32 was_killed;
    int status;

    /* Wait for parent by reading from the pipe. Abort if read fails. */

    if (read(FORKSRV_FD, &was_killed, 4) != 4) _exit(1);

    /* If we stopped the child in persistent mode, but there was a race
       condition and afl-fuzz already issued SIGKILL, write off the old
       process. */

    if (child_stopped && was_killed) {
      child_stopped = 0;
      if (waitpid(child_pid, &status, 0) < 0) _exit(1);
    }

    if (!child_stopped) {

      /* Once woken up, create a clone of our process. */

      child_pid = fork();
      if (child_pid < 0) _exit(1);

      /* In child process: close fds, resume execution. */

      if (!child_pid) {

        close(FORKSRV_FD);
        close(FORKSRV_FD + 1);
        return;
  
      }

    } else {

      /* Special handling for persistent mode: if the child is alive but
         currently stopped, simply restart it with SIGCONT. */

      kill(child_pid, SIGCONT);
      child_stopped = 0;

    }

    /* In parent process: write PID to pipe, then wait for child. */

    if (write(FORKSRV_FD + 1, &child_pid, 4) != 4) _exit(1);

    if (waitpid(child_pid, &status, is_persistent ? WUNTRACED : 0) < 0)
      _exit(1);

    /* In persistent mode, the child stops itself with SIGSTOP to indicate
       a successful run. In this case, we want to wake it up without forking
       again. */

    if (WIFSTOPPED(status)) child_stopped = 1;

    /* Relay wait status to pipe, then loop back. */

    if (write(FORKSRV_FD + 1, &status, 4) != 4) _exit(1);

  }

}


/* A simplified persistent mode handler, used as explained in README.llvm. */

int __afl_persistent_loop(unsigned int max_cnt) {

  static u8  first_pass = 1;
  static u32 cycle_cnt;

  if (first_pass) {

    /* Make sure that every iteration of __AFL_LOOP() starts with a clean slate.
       On subsequent calls, the parent will take care of that, but on the first
       iteration, it's our job to erase any trace of whatever happened
       before the loop. */

    if (is_persistent) {

      memset(__afl_area_ptr, 0, MAP_SIZE);
      memset(__fuzzfactory_dsf_map, 0, DSF_MAX * sizeof(u32));
      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;
    }

    cycle_cnt  = max_cnt;
    first_pass = 0;
    return 1;

  }

  if (is_persistent) {

    if (--cycle_cnt) {

      raise(SIGSTOP);

      __afl_area_ptr[0] = 1;
      __afl_prev_loc = 0;

      return 1;

    } else {

      /* When exiting __AFL_LOOP(), make sure that the subsequent code that
         follows the loop is not traced. We do that by pivoting back to the
         dummy output region. */

      __afl_area_ptr = __afl_area_initial;

    }

  }

  return 0;

}


/* This one can be called from user code when deferred forkserver mode
    is enabled. */

void __afl_manual_init(void) {

  static u8 init_done;

  if (!init_done) {

    __afl_map_shm();
    __afl_start_forkserver();
    init_done = 1;

  }

}


/* Proper initialization routine. */

__attribute__((constructor(CONST_PRIO))) void __afl_auto_init(void) {

  is_persistent = !!getenv(PERSIST_ENV_VAR);

  if (getenv(DEFER_ENV_VAR)) return;

  __afl_manual_init();

}


/* The following stuff deals with supporting -fsanitize-coverage=trace-pc-guard.
   It remains non-operational in the traditional, plugin-backed LLVM mode.
   For more info about 'trace-pc-guard', see README.llvm.

   The first function (__sanitizer_cov_trace_pc_guard) is called back on every
   edge (as opposed to every basic block). */

void __sanitizer_cov_trace_pc_guard(uint32_t* guard) {
  __afl_area_ptr[*guard]++;
}


/* Init callback. Populates instrumentation IDs. Note that we're using
   ID of 0 as a special value to indicate non-instrumented bits. That may
   still touch the bitmap, but in a fairly harmless way. */

void __sanitizer_cov_trace_pc_guard_init(uint32_t* start, uint32_t* stop) {

  u32 inst_ratio = 100;
  u8* x;

  if (start == stop || *start) return;

  x = getenv("AFL_INST_RATIO");
  if (x) inst_ratio = atoi(x);

  if (!inst_ratio || inst_ratio > 100) {
    fprintf(stderr, "[-] ERROR: Invalid AFL_INST_RATIO (must be 1-100).\n");
    abort();
  }

  /* Make sure that the first element in the range is always set - we use that
     to avoid duplicate calls (which can happen as an artifact of the underlying
     implementation in LLVM). */

  *(start++) = R(MAP_SIZE - 1) + 1;

  while (start < stop) {

    if (R(100) < inst_ratio) *start = R(MAP_SIZE - 1) + 1;
    else *start = 0;

    start++;

  }

}

int __fuzzfactory_new_domain(u32 size, enum fuzzfactory_reducer reducer, u32 initial) {
  // Enusre that we have space
  if (dsf_count == DSF_MAX) {
    fprintf(stderr, "[-] ERROR: Too many domain-specific maps! Max allowed is %d only.\n", DSF_MAX);
    _exit(1);
  }

  // Ensure that size is valid
  if (size <= 0 || size > MAP_SIZE) {
    fprintf(stderr, "[-] ERROR: Invalid domain-specific map size: %u\n", size);
    _exit(1);
  }

  // Okay, populate the next config
  int start = (dsf_count == 0) ? 0 : dsf_configs[dsf_count-1].end;
  int end = start + size;
  dsf_configs[dsf_count].start = start; 
  dsf_configs[dsf_count].end = end;
  dsf_configs[dsf_count].reducer = reducer;
  dsf_configs[dsf_count].initial = initial;

  // Increment the number of DSF maps registered and return old value
  return dsf_count++;

}

static inline int key_idx(int id, u32 key) {
  int start = dsf_configs[id].start;
  int size = dsf_configs[id].end - start;
  return start + (key % size);
}

void __fuzzfactory_dsf_max(dsf_t id, u32 key, u32 value) {
  int idx = key_idx(id, key);
  int old = __fuzzfactory_dsf_map[idx];
  __fuzzfactory_dsf_map[idx] = old > value ? old : value; 
}

void __fuzzfactory_dsf_set(dsf_t id, u32 key, u32 value) {
  int idx = key_idx(id, key);
  __fuzzfactory_dsf_map[idx] = value;
}

void __fuzzfactory_dsf_bitwise_or(dsf_t id, u32 key, u32 value) {
  int idx = key_idx(id, key);
  __fuzzfactory_dsf_map[idx] |= value;
}

void __fuzzfactory_dsf_increment(dsf_t id, u32 key, u32 value) {
  int idx = key_idx(id, key);
  __fuzzfactory_dsf_map[idx] += value;
}

void __fuzzfactory_dsfp_max(dsf_t* p, u32 key, u32 value) {
  __fuzzfactory_dsf_max(*p, key, value);
}

void __fuzzfactory_dsfp_set(dsf_t* p, u32 key, u32 value) {
  __fuzzfactory_dsf_set(*p, key, value);
}

void __fuzzfactory_dsfp_bitwise_or(dsf_t* p, u32 key, u32 value) {
  __fuzzfactory_dsf_bitwise_or(*p, key, value);
}

void __fuzzfactory_dsfp_increment(dsf_t* p, u32 key, u32 value) {
  __fuzzfactory_dsf_increment(*p, key, value);
}
