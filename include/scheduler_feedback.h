/*
   american fuzzy lop++ - scheduler feedback header
   ------------------------------------------------

   Copyright 2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This is the header for the scheduler feedback mechanism that allows
   external eBPF schedulers to prioritize fuzzing processes based on
   their performance.

 */

#ifndef _SCHEDULER_FEEDBACK_H
#define _SCHEDULER_FEEDBACK_H

#include "types.h"

/* Shared memory structure for scheduler feedback */
typedef struct scheduler_feedback {
  pid_t pid;                  /* Process ID of this fuzzer */
  u64   last_update_time;     /* Timestamp of last update (ms) */
  u32   new_edges_found;      /* New edges found since last update */
  u32   total_edges_found;    /* Total edges found by this fuzzer */
  u32   execs_per_sec;        /* Current execution speed */
  u32   paths_found;          /* Total paths discovered */
  u32   unique_crashes;       /* Number of unique crashes found */
  u32   unique_hangs;         /* Number of unique hangs found */
  u32   queue_cycle;          /* Current queue cycle */
  u32   pending_favs;         /* Number of pending favored paths */
  u8    performance_score;    /* Calculated performance score (0-100) */
  u8    reserved[3];          /* Padding for alignment */
} scheduler_feedback_t;

/* Initialize the scheduler feedback shared memory */
void afl_scheduler_feedback_init(afl_state_t *afl);

/* Update the scheduler feedback with current metrics */
void afl_scheduler_feedback_update(afl_state_t *afl);

/* Clean up the scheduler feedback shared memory */
void afl_scheduler_feedback_deinit(afl_state_t *afl);

#endif /* _SCHEDULER_FEEDBACK_H */
