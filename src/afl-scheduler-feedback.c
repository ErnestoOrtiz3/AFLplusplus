/*
   american fuzzy lop++ - scheduler feedback implementation
   -------------------------------------------------------

   Copyright 2024 AFLplusplus Project. All rights reserved.

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at:

     https://www.apache.org/licenses/LICENSE-2.0

   This is the implementation of the scheduler feedback mechanism that allows
   external eBPF schedulers to prioritize fuzzing processes based on
   their performance.

 */

#include "afl-fuzz.h"
#include "scheduler_feedback.h"

/* Initialize the scheduler feedback shared memory */
void afl_scheduler_feedback_init(afl_state_t *afl) {

  if (!afl->scheduler_feedback_enabled) return;

  ACTF("Initializing scheduler feedback...");

  // Create shared memory region
  char shm_key[32];
  sprintf(shm_key, "afl_sched_%d", getpid());
  
  // Create or attach to shared memory
  int shm_id = shmget(IPC_PRIVATE, sizeof(scheduler_feedback_t), 
                      IPC_CREAT | IPC_EXCL | 0600);
  if (shm_id < 0) PFATAL("shmget() failed for scheduler feedback");
  
  // Attach to the shared memory
  afl->scheduler_feedback = shmat(shm_id, NULL, 0);
  if (afl->scheduler_feedback == (void *)-1) PFATAL("shmat() failed for scheduler feedback");
  
  // Initialize the shared memory
  memset(afl->scheduler_feedback, 0, sizeof(scheduler_feedback_t));
  afl->scheduler_feedback->pid = getpid();
  afl->scheduler_feedback->last_update_time = get_cur_time();
  
  // Store the shm_id for later use
  afl->scheduler_feedback_shm_id = shm_id;

  // Create a file with the shm_id so external processes can find it
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/scheduler_feedback.txt", afl->out_dir);
  FILE *f = fopen(path, "w");
  if (!f) PFATAL("Could not create scheduler_feedback.txt");
  fprintf(f, "%d\n", shm_id);
  fclose(f);

  OKF("Scheduler feedback initialized with SHM ID: %d", shm_id);
}

/* Update the scheduler feedback with current metrics */
void afl_scheduler_feedback_update(afl_state_t *afl) {

  if (!afl->scheduler_feedback_enabled || !afl->scheduler_feedback) return;
  
  scheduler_feedback_t *feedback = afl->scheduler_feedback;
  
  // Update metrics
  feedback->last_update_time = get_cur_time();
  feedback->execs_per_sec = afl->stats_avg_exec;
  feedback->total_edges_found = count_non_255_bytes(afl, afl->virgin_bits);
  feedback->paths_found = afl->queued_items;
  feedback->unique_crashes = afl->saved_crashes;
  feedback->unique_hangs = afl->saved_hangs;
  feedback->queue_cycle = afl->queue_cycle;
  feedback->pending_favs = afl->pending_favored;
  
  // Calculate a performance score (simple version)
  u8 score = 0;
  if (feedback->new_edges_found > 0) score += 50;
  if (feedback->unique_crashes > afl->last_reported_crashes) score += 30;
  if (feedback->execs_per_sec > afl->stats_avg_exec_prev) score += 20;
  
  feedback->performance_score = score;
  
  // Reset new edges counter after updating
  u32 current_edges = feedback->total_edges_found;
  feedback->new_edges_found = current_edges - afl->last_reported_edges;
  afl->last_reported_edges = current_edges;
  afl->last_reported_crashes = feedback->unique_crashes;
  afl->stats_avg_exec_prev = feedback->execs_per_sec;
}

/* Clean up the scheduler feedback shared memory */
void afl_scheduler_feedback_deinit(afl_state_t *afl) {

  if (!afl->scheduler_feedback_enabled || !afl->scheduler_feedback) return;
  
  // Detach from shared memory
  shmdt(afl->scheduler_feedback);
  
  // Mark for deletion
  shmctl(afl->scheduler_feedback_shm_id, IPC_RMID, NULL);
  
  // Remove the file with the shm_id
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "%s/scheduler_feedback.txt", afl->out_dir);
  unlink(path);
  
  afl->scheduler_feedback = NULL;
  OKF("Scheduler feedback cleaned up");
}
