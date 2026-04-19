/* afl-fuzz-linucb.c
 *
 * LinUCB queue prioritization for AFL++ / Faizz.
 *
 * Design goals:
 *  - enabled only when caller sets afl->linucb_mode
 *  - does NOT replace existing alias-table logic; it reranks alias samples
 *  - warmup phase learns from normal AFL++ selections before using UCB scores
 *  - keeps perf_score / fuzz_one semantics untouched
 *
 * Minimal required external changes:
 *  1) add `u8 linucb_mode;` to `afl_state_t`
 *  2) add function prototypes to include/afl-fuzz.h:
 *       void linucb_init(afl_state_t *afl);
 *       void linucb_deinit(afl_state_t *afl);
 *       u8   linucb_warmup_active(afl_state_t *afl);
 *       u32  linucb_select_next_queue_entry(afl_state_t *afl);
 *       void linucb_begin_episode(afl_state_t *afl, struct queue_entry *q);
 *       void linucb_finish_episode(afl_state_t *afl, struct queue_entry *q,
 *                                  u8 skipped);
 */

#include "afl-fuzz.h"

#include <float.h>
#include <math.h>
#include <string.h>

#ifndef LINUCB_DIM
  #define LINUCB_DIM 11u
#endif

#ifndef LINUCB_ALPHA
  #define LINUCB_ALPHA 0.85
#endif

#ifndef LINUCB_CANDIDATE_K
  #define LINUCB_CANDIDATE_K 16u
#endif

#ifndef LINUCB_MAX_CANDIDATES
  #define LINUCB_MAX_CANDIDATES 32u
#endif

#ifndef LINUCB_WARMUP_MIN_QUEUE
  #define LINUCB_WARMUP_MIN_QUEUE 16u
#endif

#ifndef LINUCB_WARMUP_MIN_EXECS
  #define LINUCB_WARMUP_MIN_EXECS 10000ULL
#endif

#ifndef LINUCB_WARMUP_MIN_UPDATES
  #define LINUCB_WARMUP_MIN_UPDATES 64ULL
#endif

#ifndef LINUCB_SAMPLE_ATTEMPT_MULT
  #define LINUCB_SAMPLE_ATTEMPT_MULT 8u
#endif

#ifndef LINUCB_L2_LAMBDA
  #define LINUCB_L2_LAMBDA 1.0
#endif

typedef struct linucb_runtime {

  afl_state_t *afl;
  u32          dim;
  u32          candidate_k;
  double       alpha;

  /* Online ridge-regression state */
  double *A_inv;   /* d x d */
  double *b;       /* d */
  double *theta;   /* d */
  double *tmp;     /* d scratch */
  double *ep_x;    /* d snapshot for current episode */

  /* Per-selected-seed episode snapshot */
  struct queue_entry *ep_seed;
  u32                 before_queued_items;
  u32                 before_queued_with_cov;
  u64                 before_saved_crashes;
  u64                 before_saved_hangs;
  u64                 before_saved_tmouts;
  u64                 before_total_execs;

  u64 updates;

  struct linucb_runtime *next;

} linucb_runtime_t;

static linucb_runtime_t *g_linucb_head = NULL;

static inline double linucb_clampd(double v, double lo, double hi) {

  if (v < lo) return lo;
  if (v > hi) return hi;
  return v;

}

static inline double linucb_log2_1p_u64(u64 v) {

  return log2(1.0 + (double)v);

}

static inline double linucb_log2_1p_u32(u32 v) {

  return log2(1.0 + (double)v);

}

static linucb_runtime_t *linucb_runtime_find(afl_state_t *afl) {

  linucb_runtime_t *rt = g_linucb_head;
  while (rt) {

    if (rt->afl == afl) return rt;
    rt = rt->next;

  }

  return NULL;

}

static linucb_runtime_t *linucb_runtime_create(afl_state_t *afl) {

  linucb_runtime_t *rt = linucb_runtime_find(afl);
  if (rt) return rt;

  rt = ck_alloc(sizeof(linucb_runtime_t));
  rt->afl = afl;
  rt->dim = LINUCB_DIM;
  rt->candidate_k = LINUCB_CANDIDATE_K;
  if (rt->candidate_k > LINUCB_MAX_CANDIDATES) {

    rt->candidate_k = LINUCB_MAX_CANDIDATES;

  }

  rt->alpha = LINUCB_ALPHA;

  rt->A_inv = ck_alloc(sizeof(double) * rt->dim * rt->dim);
  rt->b = ck_alloc(sizeof(double) * rt->dim);
  rt->theta = ck_alloc(sizeof(double) * rt->dim);
  rt->tmp = ck_alloc(sizeof(double) * rt->dim);
  rt->ep_x = ck_alloc(sizeof(double) * rt->dim);

  /* A = lambda * I  => A_inv = (1/lambda) * I */
  double diag = 1.0 / LINUCB_L2_LAMBDA;
  for (u32 i = 0; i < rt->dim; ++i) {

    rt->A_inv[i * rt->dim + i] = diag;

  }

  rt->next = g_linucb_head;
  g_linucb_head = rt;

  return rt;

}

static void linucb_runtime_destroy(afl_state_t *afl) {

  linucb_runtime_t **pp = &g_linucb_head;
  while (*pp) {

    linucb_runtime_t *rt = *pp;
    if (rt->afl == afl) {

      *pp = rt->next;
      ck_free(rt->A_inv);
      ck_free(rt->b);
      ck_free(rt->theta);
      ck_free(rt->tmp);
      ck_free(rt->ep_x);
      ck_free(rt);
      return;

    }

    pp = &((*pp)->next);

  }

}

static inline u32 linucb_alias_pick(afl_state_t *afl) {

  if (unlikely(!afl->queued_items)) return 0;

  if (likely(afl->alias_probability && afl->alias_table)) {

    u32    s = rand_below(afl, afl->queued_items);
    double p = rand_next_percent(afl);
    return (p < afl->alias_probability[s] ? s : afl->alias_table[s]);

  }

  /* Safe fallback if alias table has not been built yet. */
  return rand_below(afl, afl->queued_items);

}

static inline struct queue_entry *linucb_q_at(afl_state_t *afl, u32 idx) {

  if (unlikely(idx >= afl->queued_items)) return NULL;
  return afl->queue_buf[idx];

}

static void linucb_build_ctx(afl_state_t *afl, struct queue_entry *q,
                             double *x) {

  memset(x, 0, sizeof(double) * LINUCB_DIM);

  if (unlikely(!q)) return;

  const double n_fuzz =
      (afl->n_fuzz ? (double)afl->n_fuzz[q->n_fuzz_entry] : 0.0);

  /* Bias */
  x[0] = 1.0;

  /* Existing AFL++ queue metadata only: no new queue_entry fields required. */
  x[1] = q->favored ? 1.0 : 0.0;
  x[2] = q->was_fuzzed ? 0.0 : 1.0;
  x[3] = q->has_new_cov ? 1.0 : 0.0;

  /* Depth: more moderate preference for deeper seeds. */
  x[4] = linucb_clampd((double)q->depth / 64.0, 0.0, 2.0);

  /* Smaller and faster seeds get a slight prior advantage. */
  x[5] = 1.0 / (1.0 + linucb_log2_1p_u32(q->len));
  x[6] = 1.0 / (1.0 + linucb_log2_1p_u64(q->exec_us));

  /* Coverage density proxy. */
  x[7] = linucb_clampd(linucb_log2_1p_u32(q->bitmap_size) / 16.0, 0.0, 2.0);

  /* Less-fuzzed seeds get more optimism. */
  x[8] = 1.0 / (1.0 + log2(1.0 + n_fuzz));

  /* Handicap can help late-arriving seeds catch up. */
  x[9] = linucb_clampd((double)q->handicap / 16.0, 0.0, 2.0);

  /* Redundant flag is exposed for the model to learn against. */
  x[10] = q->fs_redundant ? 1.0 : 0.0;

}

static void linucb_matvec(const double *A, const double *x, double *out,
                          u32 dim) {

  for (u32 i = 0; i < dim; ++i) {

    double acc = 0.0;
    const double *row = &A[i * dim];

    for (u32 j = 0; j < dim; ++j) {

      acc += row[j] * x[j];

    }

    out[i] = acc;

  }

}

static double linucb_dot(const double *a, const double *b, u32 dim) {

  double acc = 0.0;
  for (u32 i = 0; i < dim; ++i) {

    acc += a[i] * b[i];

  }

  return acc;

}

static double linucb_score(linucb_runtime_t *rt, afl_state_t *afl,
                           struct queue_entry *q) {

  double x[LINUCB_DIM];
  linucb_build_ctx(afl, q, x);

  linucb_matvec(rt->A_inv, x, rt->tmp, rt->dim);

  const double mean = linucb_dot(rt->theta, x, rt->dim);
  const double quad = linucb_dot(x, rt->tmp, rt->dim);
  const double bonus = rt->alpha * sqrt(quad > 0.0 ? quad : 0.0);

  return mean + bonus;

}

static void linucb_update(linucb_runtime_t *rt, const double *x,
                          double reward) {

  /* Sherman-Morrison update:
     A_inv <- A_inv - (A_inv x x^T A_inv) / (1 + x^T A_inv x)
  */
  linucb_matvec(rt->A_inv, x, rt->tmp, rt->dim);

  const double denom = 1.0 + linucb_dot(x, rt->tmp, rt->dim);

  if (likely(denom > 1e-12)) {

    for (u32 i = 0; i < rt->dim; ++i) {

      for (u32 j = 0; j < rt->dim; ++j) {

        rt->A_inv[i * rt->dim + j] -=
            (rt->tmp[i] * rt->tmp[j]) / denom;

      }

    }

  }

  for (u32 i = 0; i < rt->dim; ++i) {

    rt->b[i] += reward * x[i];

  }

  linucb_matvec(rt->A_inv, rt->b, rt->theta, rt->dim);
  ++rt->updates;

}

static double linucb_delta_u64(u64 now, u64 before) {

  return (now >= before) ? (double)(now - before) : 0.0;

}

static double linucb_delta_u32(u32 now, u32 before) {

  return (now >= before) ? (double)(now - before) : 0.0;

}

static double linucb_compute_reward(linucb_runtime_t *rt, afl_state_t *afl,
                                    u8 skipped) {

  double reward = 0.0;

  reward += 3.0 * linucb_delta_u32(afl->queued_items, rt->before_queued_items);
  reward +=
      2.0 * linucb_delta_u32(afl->queued_with_cov, rt->before_queued_with_cov);
  reward +=
      8.0 * linucb_delta_u64(afl->saved_crashes, rt->before_saved_crashes);
  reward += 4.0 * linucb_delta_u64(afl->saved_hangs, rt->before_saved_hangs);
  reward += 1.5 * linucb_delta_u64(afl->saved_tmouts, rt->before_saved_tmouts);

  const double exec_delta =
      linucb_delta_u64(afl->fsrv.total_execs, rt->before_total_execs);

  reward -= 0.20 * log2(1.0 + exec_delta);

  if (skipped) reward -= 0.50;

  return linucb_clampd(reward, -2.0, 12.0);

}

void linucb_init(afl_state_t *afl) {

  if (unlikely(!afl)) return;
  if (!afl->linucb_mode) return;

  (void)linucb_runtime_create(afl);

}

void linucb_deinit(afl_state_t *afl) {

  if (unlikely(!afl)) return;
  linucb_runtime_destroy(afl);

}

u8 linucb_warmup_active(afl_state_t *afl) {

  if (unlikely(!afl) || !afl->linucb_mode) return 0;

  linucb_runtime_t *rt = linucb_runtime_find(afl);
  if (!rt) return 1;

  if (afl->queued_items < LINUCB_WARMUP_MIN_QUEUE) return 1;
  if (afl->fsrv.total_execs < LINUCB_WARMUP_MIN_EXECS) return 1;
  if (rt->updates < LINUCB_WARMUP_MIN_UPDATES) return 1;

  return 0;

}

u32 linucb_select_next_queue_entry(afl_state_t *afl) {

  if (unlikely(!afl || !afl->queued_items)) return 0;

  /* Keep old-selection semantics untouched. */
  if (unlikely(afl->old_seed_selection)) return afl->current_entry;

  linucb_runtime_t *rt = linucb_runtime_find(afl);
  if (!rt) rt = linucb_runtime_create(afl);

  if (unlikely(linucb_warmup_active(afl))) {

    /* During warmup: behave like vanilla weighted-random selection. */
    u32 id;
    do {

      id = linucb_alias_pick(afl);

    } while (unlikely(id >= afl->queued_items));

    return id;

  }

  const u32 cand_need =
      (rt->candidate_k < afl->queued_items) ? rt->candidate_k : afl->queued_items;

  u32 cand_ids[LINUCB_MAX_CANDIDATES];
  u32 cand_count = 0;
  u32 attempts = cand_need * LINUCB_SAMPLE_ATTEMPT_MULT;
  if (attempts < cand_need) attempts = cand_need;

  while (cand_count < cand_need && attempts--) {

    const u32 idx = linucb_alias_pick(afl);
    if (unlikely(idx >= afl->queued_items)) continue;

    struct queue_entry *q = linucb_q_at(afl, idx);
    if (unlikely(!q || q->disabled)) continue;

    u8 seen = 0;
    for (u32 i = 0; i < cand_count; ++i) {

      if (cand_ids[i] == idx) {

        seen = 1;
        break;

      }

    }

    if (!seen) cand_ids[cand_count++] = idx;

  }

  if (!cand_count) {

    /* Conservative fallback: first enabled seed, otherwise current/random. */
    for (u32 i = 0; i < afl->queued_items; ++i) {

      struct queue_entry *q = linucb_q_at(afl, i);
      if (q && !q->disabled) return i;

    }

    return (afl->current_entry < afl->queued_items) ? afl->current_entry : 0;

  }

  u32    best_idx = cand_ids[0];
  double best_score = -DBL_MAX;

  for (u32 i = 0; i < cand_count; ++i) {

    struct queue_entry *q = linucb_q_at(afl, cand_ids[i]);
    if (unlikely(!q || q->disabled)) continue;

    const double score = linucb_score(rt, afl, q);
    if (score > best_score) {

      best_score = score;
      best_idx = cand_ids[i];

    }

  }

  return best_idx;

}

void linucb_begin_episode(afl_state_t *afl, struct queue_entry *q) {

  if (unlikely(!afl || !afl->linucb_mode || !q)) return;

  linucb_runtime_t *rt = linucb_runtime_find(afl);
  if (!rt) rt = linucb_runtime_create(afl);

  rt->ep_seed = q;
  linucb_build_ctx(afl, q, rt->ep_x);

  rt->before_queued_items = afl->queued_items;
  rt->before_queued_with_cov = afl->queued_with_cov;
  rt->before_saved_crashes = afl->saved_crashes;
  rt->before_saved_hangs = afl->saved_hangs;
  rt->before_saved_tmouts = afl->saved_tmouts;
  rt->before_total_execs = afl->fsrv.total_execs;

}

void linucb_finish_episode(afl_state_t *afl, struct queue_entry *q, u8 skipped) {

  if (unlikely(!afl || !afl->linucb_mode)) return;

  linucb_runtime_t *rt = linucb_runtime_find(afl);
  if (!rt || !rt->ep_seed) return;

  /* If caller passes a different queue entry pointer due to control-flow
     changes, still update from the stored episode seed. */
  (void)q;

  const double reward = linucb_compute_reward(rt, afl, skipped);
  linucb_update(rt, rt->ep_x, reward);

  rt->ep_seed = NULL;

}