#include "reducers.h"

/* All reducer functions need to meet this signature */
typedef u32 (*reducer_t)(u32 a, u32 v);

/** Reducer: max(a, v) */
u32 reducer_max(u32 a, u32 v) {
  return a > v ? a : v;
}

/** Reducer: min(a, v) */
u32 reducer_min(u32 a, u32 v) {
  return a < v ? a : v;
}

// Utility function to get floor(log2(n)), i.e., only highest bit set
static u32 hibit(u32 n) {
    n |= (n >>  1);
    n |= (n >>  2);
    n |= (n >>  4);
    n |= (n >>  8);
    n |= (n >> 16);
    return n - (n >> 1);
}

/** Reducer: a | log2(v) */
u32 reducer_log_bucket(u32 a, u32 v) {
  return a | hibit(v);
}

/** Reducer: a | v */
u32 reducer_bit_union(u32 a, u32 v) {
  return a | v;
}

/** Reducer: a & v */
u32 reducer_bit_intersection(u32 a, u32 v) {
  return a & v;
}

/* Make sure that this array is consistent with the enum defined in reducers.h */
reducer_t dsf_reducers[] = {
  [FUZZFACTORY_REDUCER_MAX]        = reducer_max,
  [FUZZFACTORY_REDUCER_MIN]        = reducer_min,
  [FUZZFACTORY_REDUCER_LOG_BUCKET] = reducer_log_bucket,
  [FUZZFACTORY_REDUCER_BIT_UNION]  = reducer_bit_union,
  [FUZZFACTORY_REDUCER_BIT_INTERSECT]  = reducer_bit_intersection,
};

/* Make sure that this array is consistent with the enum defined in reducers.h */
const char* dsf_reducer_names[] = {
  [FUZZFACTORY_REDUCER_MAX]        = "MAX",
  [FUZZFACTORY_REDUCER_MIN]        = "MIN",
  [FUZZFACTORY_REDUCER_LOG_BUCKET] = "LOG_BUCKETING",
  [FUZZFACTORY_REDUCER_BIT_UNION]  = "BITWISE_UNION",
  [FUZZFACTORY_REDUCER_BIT_INTERSECT]  = "BITWISE_INTERSECTION",
};

