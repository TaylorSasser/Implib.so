/*
 * Copyright 2025 Yury Gribov
 *
 * The MIT License (MIT)
 * 
 * Use of this source code is governed by MIT license that can be
 * found in the LICENSE.txt file.
 */

#include <dlfcn.h>
#include <stdio.h>
#include <assert.h>
#include <stdlib.h>

#include <pthread.h>
#include <unistd.h>

#ifdef __APPLE__
#ifndef PTHREAD_BARRIER_SERIAL_THREAD
#define PTHREAD_BARRIER_SERIAL_THREAD 1
#endif
typedef struct {
  pthread_mutex_t mutex;
  pthread_cond_t cond;
  unsigned int count;
  unsigned int tripCount;
} pthread_barrier_t;
static inline int pthread_barrier_init(pthread_barrier_t *barrier, const void *attr, unsigned int count) {
  (void)attr;
  if (count == 0) return -1;
  if (pthread_mutex_init(&barrier->mutex, 0) < 0) return -1;
  if (pthread_cond_init(&barrier->cond, 0) < 0) return -1;
  barrier->tripCount = count;
  barrier->count = 0;
  return 0;
}
static inline int pthread_barrier_wait(pthread_barrier_t *barrier) {
  pthread_mutex_lock(&barrier->mutex);
  ++(barrier->count);
  if (barrier->count >= barrier->tripCount) {
    barrier->count = 0;
    pthread_cond_broadcast(&barrier->cond);
    pthread_mutex_unlock(&barrier->mutex);
    return PTHREAD_BARRIER_SERIAL_THREAD;
  } else {
    pthread_cond_wait(&barrier->cond, &barrier->mutex);
    pthread_mutex_unlock(&barrier->mutex);
    return 0;
  }
}
#endif

#include "interposed.h"

#if defined __mips && __mips == 32
// For some reason pthread_create fails with EAGAIN
#define N 32
#else
#define N 128
#endif

static int args[N];
static pthread_t tids[N];
static pthread_barrier_t bar;

void *run(void *arg_) {
  int rc = pthread_barrier_wait(&bar);
  if (PTHREAD_BARRIER_SERIAL_THREAD != rc && 0 != rc)
    abort();

  int *arg = (int *)arg_;

  int (*foo)(int);
  switch(*arg % 10) {
    case 0:
      foo = foo0;
      break;
    case 1:
      foo = foo1;
      break;
    case 2:
      foo = foo2;
      break;
    case 3:
      foo = foo3;
      break;
    case 4:
      foo = foo4;
      break;
    case 5:
      foo = foo5;
      break;
    case 6:
      foo = foo6;
      break;
    case 7:
      foo = foo7;
      break;
    case 8:
      foo = foo8;
      break;
    case 9:
      foo = foo9;
      break;
    default:
      abort();
  }

  *arg = foo(*arg);

  return 0;
}

int main() {
  int exp = 0;
  for (int i = 0; i < N; ++i) {
    args[i] = i;
    exp += 1 + i + (i % 10);
  }

  if (0 != pthread_barrier_init(&bar, 0, N))
    abort();

  for (int i = 0; i < N; ++i) {
    if (0 != pthread_create(&tids[i], 0, run, &args[i]))
      abort();
  }

  for (int i = 0; i < N; ++i) {
    if (0 != pthread_join(tids[i], 0))
      abort();
  }

  int res = 0;
  for (int i = 0; i < N; ++i)
    res += args[i];

  if (res != exp)
    printf("Result: %d (%d exp)\n", res, exp);
  else
    printf("Correct result\n");

  return 0;
}
