// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

#include "arguments.h"
#include "go_context.h"
#include "go_net.h"
#include "go_types.h"
#include "trace/span_context.h"
#include "trace/start_span.h"
#include "uprobe.h"

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_QUERY_SIZE 256
#define MAX_CONCURRENT 50

// Injected in init
volatile const u64 ctx_ptr_offset_pos;
volatile const u64 stmt_offset_pos;
volatile const u64 consistency_level_offset_pos;
volatile const u64 page_size_offset_pos;

struct cql_request_t {
  BASE_SPAN_PROPERTIES
  char query[MAX_QUERY_SIZE];
  net_addr_t local_addr;
  net_addr_t peer_addr;
  int consistency_level;
  u32 page_size;
};

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, void *);
  __type(value, struct cql_request_t);
  __uint(max_entries, MAX_CONCURRENT);
} cql_events SEC(".maps");

// This instrumentation attaches uprobe to the following function:
// func (q *Query) Iter() *Iter
SEC("uprobe/Iter")
int uprobe_Iter(struct pt_regs *ctx) {
  bpf_printk("uprobe/Iter: Entered");

  // argument positions
  u64 ptr_pos = 1;
  void *query_ptr = get_argument(ctx, ptr_pos);

  struct cql_request_t cql_request = {0};
  cql_request.start_time = bpf_ktime_get_ns();

  struct go_iface go_context = {0};
  get_Go_context(ctx, ptr_pos, ctx_ptr_offset_pos, false, &go_context);

  if (!get_go_string_from_user_ptr((void *)(query_ptr + stmt_offset_pos),
                                   cql_request.query,
                                   sizeof(cql_request.query))) {
    bpf_printk("uprobe_Iter: Failed to get stmt from Query");
  }

  //    void *local_addr_ptr = 0;
  //    u8 conn_offset_pos = 152;
  //    u8 local_addr_offset_pos = 0; // lost here, since the struct has methods
  //    void *local_addr_pos = query_ptr +  + peer_local_addr_pos;
  //    bpf_probe_read_user(&local_addr_ptr, sizeof(local_addr_ptr),
  //    get_go_interface_instance(local_addr_pos));
  //    get_tcp_net_addr_from_tcp_addr(ctx, &cql_request->local_addr, (void
  //    *)(local_addr_ptr));

  bpf_probe_read_user(&cql_request.consistency_level,
                      sizeof(cql_request.consistency_level),
                      (void *)(query_ptr + consistency_level_offset_pos));

  bpf_probe_read_user(&cql_request.page_size, sizeof(cql_request.page_size),
                      (void *)(query_ptr + consistency_level_offset_pos));

  start_span_params_t start_span_params = {
      .ctx = ctx,
      .go_context = &go_context,
      .psc = &cql_request.psc,
      .sc = &cql_request.sc,
      .get_parent_span_context_fn = NULL,
      .get_parent_span_context_arg = NULL,
  };

  start_span(&start_span_params);

  // Get key
  void *key = (void *)GOROUTINE(ctx);

  bpf_map_update_elem(&cql_events, &key, &cql_request, 0);
  return 0;
}

// This instrumentation attaches uprobe to the following function:
// func (q *Query) Iter() *Iter
UPROBE_RETURN(Iter, struct cql_request_t, cql_events)