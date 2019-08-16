#ifndef AFL_VALID
#define AFL_VALID

#include "unistd.h"
#include "stdio.h"

/* Function to call when assumptions fail */
#ifdef __cplusplus
extern "C"
#endif
void __afl_valid_assumption_failure();

/* Ensures that `expr` is true, else returns from current function with `rval` */
#define ASSUME_OR_RETURN(expr, rval) \
  do { \
    if (!(expr)) { \
      fprintf(stderr, "Assumption failure on %s:%d\n", __FILE__, __LINE__); \
      __afl_valid_assumption_failure(); \
      return rval; \
    } \
  } while(0)

/* Ensures that `expr` is true, else exits the program */
#define ASSUME_OR_EXIT(expr) \
  do { \
    if (!(expr)) { \
      fprintf(stderr, "Assumption failure on %s:%d\n", __FILE__, __LINE__); \
      __afl_valid_assumption_failure(); \
      _exit(1); \
    } \
  } while(0)

/* Convenience method for functions that return 1 to signal error */
#define ASSUME1(expr) ASSUME_OR_RETURN(expr, 1)

#endif // AFL_VALID
