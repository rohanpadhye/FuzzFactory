#include "waypoints.h"
#define VALID_DSF_SIZE (1 << 16)
FUZZFACTORY_DSF_NEW(__afl_valid_dsf, VALID_DSF_SIZE, FUZZFACTORY_REDUCER_LOG_BUCKET, 0);

/* Assumption failure; invalidates everything in the DSF map */
void __afl_valid_assumption_failure() {
  for (int i = 0; i < VALID_DSF_SIZE; i++) {
    FUZZFACTORY_DSF_SET(__afl_valid_dsf, i, 0);
  }
}
