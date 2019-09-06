/*
 * Copyright (c) 2019 The Regents of the University of California
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "../config.h"
#include "../types.h"
#include "reducers.h"

#ifndef WAYPOINTS_H
#define WAYPOINTS_H

#ifdef __cplusplus
extern "C" {
#endif

/* Conditionally declare external functions if compiling with AFL compiler */
#if defined(__AFL_COMPILER) || defined(AFL_PATH)

/* Type of DSF map reference */
typedef int dsf_t;

/* Functions that update DSF map at run-time */
void __fuzzfactory_dsf_max(dsf_t id, u32 key, u32 value);
void __fuzzfactory_dsf_bitwise_or(dsf_t id, u32 key, u32 value);
void __fuzzfactory_dsf_set(dsf_t id, u32 key, u32 value);
void __fuzzfactory_dsf_increment(dsf_t id, u32 key, u32 value);

/* Same as above but first arg is pointer to DSF map */
void __fuzzfactory_dsfp_max(dsf_t* p, u32 key, u32 value);
void __fuzzfactory_dsfp_bitwise_or(dsf_t* p, u32 key, u32 value);
void __fuzzfactory_dsfp_set(dsf_t* p, u32 key, u32 value);
void __fuzzfactory_dsfp_increment(dsf_t* p, u32 key, u32 value);

/* Macros for use in manual insertion of DSF calls */
#define FUZZFACTORY_DSF_MAX(id, k, v) (__fuzzfactory_dsf_max(id, k, v))
#define FUZZFACTORY_DSF_BIT(id, k, v) (__fuzzfactory_dsf_bitwise_or(id, k, v))
#define FUZZFACTORY_DSF_SET(id, k, v) (__fuzzfactory_dsf_set(id, k, v))
#define FUZZFACTORY_DSF_INC(id, k, v) (__fuzzfactory_dsf_increment(id, k, v))

void __afl_waypoints_set_state(u32 state);
u32  __afl_waypoints_get_state();
void __afl_waypoints_hash_state(int num_args, ...);

#define AFL_WAYPOINTS_SET_STATE(state) __afl_waypoints_set_state(state)
#define AFL_WAYPOINTS_GET_STATE() (__afl_waypoints_get_state())
#define AFL_WAYPOINTS_HASH_STATE(num_args, ...) (__afl_waypoints_hash_state((num_args), ##__VA_ARGS__))

/* Max number of domain-specific maps */
#define DSF_MAX 4

/* Config for domain-specific fuzzing */
typedef struct dsf_config_t {
  int start;
  int end;
  int reducer;
  u32 initial;
} dsf_config;

/* Register a new domain-specific fuzzing front-end */
dsf_t __fuzzfactory_new_domain(u32 size, enum fuzzfactory_reducer reducer, u32 initial);

#define FUZZFACTORY_DSF_NEW(name, size, reducer, initial) dsf_t name; \
  __attribute__((constructor(0))) static void __init_##name() { \
  name = __fuzzfactory_new_domain(size, reducer, initial); \
} \

#else // Not compiling with AFL

// Redefine macros as no-ops
#define AFL_WAYPOINT(key, val, agg)
#define AFL_WAYPOINTS_SET_STATE(state)
#define FUZZFACTORY_DSF_MAX(id, k, v)
#define FUZZFACTORY_DSF_BIT(id, k, v)
#define FUZZFACTORY_DSF_SET(id, k, v)
#define FUZZFACTORY_DSF_INC(id, k, v)
#define FUZZFACTORY_DSF_NEW(name, size, reducer, initial)

#endif // __AFL_COMPILER || AFL_PATH

#ifdef __cplusplus
}
#endif

#endif // WAYPOINTS_H
