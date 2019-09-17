
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

#ifndef REDUCERS_H
#define REDUCERS_H

/* 
 This file only defines the enums for the reducer functions, which
 serve as enum values to communicate via IPC between the fuzzer (afl-fuzz.c)
 and the instrumented test program.

 The implementation of these reducer functions is elsewhere (reducers.c),
 and must be kept in-sync with this file. The implementation is only linked into
 the fuzzer; the test program does not need it.
*/

enum fuzzfactory_reducer {
  FUZZFACTORY_REDUCER_MAX,
  FUZZFACTORY_REDUCER_MIN,
  FUZZFACTORY_REDUCER_LOG_BUCKET,
  FUZZFACTORY_REDUCER_BIT_UNION,
  FUZZFACTORY_REDUCER_BIT_INTERSECT,
};

#endif // REDUCERS_H
