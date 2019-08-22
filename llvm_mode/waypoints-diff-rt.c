#include "waypoints.h"
#include <stdio.h>

/* Register DSF map global */
#define DIFF_DSF_SIZE MAP_SIZE
FUZZFACTORY_DSF_NEW(__afl_diff_dsf, DIFF_DSF_SIZE, FUZZFACTORY_REDUCER_LOG_BUCKET, 0);

/* Allocate other globals used by instrumentation */
u32 __afl_prev_diff_loc;
u32 __afl_hits_diff;
int __afl_in_main_loop =0;

void __afl_print_hits_diff() {
   if (__afl_in_main_loop) {
      printf("[WAYPOINTS] this input hit a diff BB\n");
   }
}
