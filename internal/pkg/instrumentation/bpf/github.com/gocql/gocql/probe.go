// Copyright The OpenTelemetry Authors
// SPDX-License-Identifier: Apache-2.0

package gocql

import (
	"log/slog"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"

	"go.opentelemetry.io/auto/internal/pkg/instrumentation/context"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/probe"
	"go.opentelemetry.io/auto/internal/pkg/instrumentation/utils"
	"go.opentelemetry.io/auto/internal/pkg/structfield"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64,arm64 bpf ./bpf/probe.bpf.c

const (
	// pkg is the package being instrumented.
	pkg = "github.com/gocql/gocql"

	// IncludeDBStatementEnvVar is the environment variable to opt-in for sql query inclusion in the trace.
	IncludeDBStatementEnvVar = "OTEL_GO_AUTO_INCLUDE_DB_STATEMENT"

	// ParseDBStatementEnvVar is the environment variable to opt-in for sql query operation in the trace.
	ParseDBStatementEnvVar = "OTEL_GO_AUTO_PARSE_DB_STATEMENT"
)

// New returns a new [probe.Probe].
func New(logger *slog.Logger, version string) probe.Probe {
	id := probe.ID{
		SpanKind:        trace.SpanKindClient,
		InstrumentedPkg: pkg,
	}
	return &probe.SpanProducer[bpfObjects, event]{
		Base: probe.Base[bpfObjects, event]{
			ID:     id,
			Logger: logger,
			Consts: []probe.Const{
				probe.AllocationConst{},
				// https://github.com/apache/cassandra-gocql-driver/blob/953e0df999cabb3f5eef714df9921c00e9f632c2/session.go#L903
				probe.StructFieldConst{
					Key: "ctx_ptr_offset_pos",
					ID:  structfield.NewID("github.com/gocql/gocql", "github.com/gocql/gocql", "Query", "context"),
				},
				probe.StructFieldConst{
					Key: "stmt_offset_pos",
					ID:  structfield.NewID("github.com/gocql/gocql", "github.com/gocql/gocql", "Query", "stmt"),
				},
				probe.StructFieldConst{
					Key: "consistency_level_offset_pos",
					ID:  structfield.NewID("github.com/gocql/gocql", "github.com/gocql/gocql", "Query", "cons"),
				},
				probe.StructFieldConst{
					Key: "page_size_offset_pos",
					ID:  structfield.NewID("github.com/gocql/gocql", "github.com/gocql/gocql", "Query", "pageSize"),
				},
			},
			Uprobes: []*probe.Uprobe{
				{
					Sym:         "github.com/gocql/gocql.(*Query).Iter",
					EntryProbe:  "uprobe_Iter",
					ReturnProbe: "uprobe_Iter_Returns",
					FailureMode: probe.FailureModeError, // keeping for testing purpose
				},
			},

			SpecFn: loadBpf,
		},
		Version:   version,
		SchemaURL: semconv.SchemaURL,
		ProcessFn: processFn,
	}
}

// event represents an event in an SQL database
// request-response.
type event struct {
	context.BaseSpanProperties
	Query            [256]byte
	LocalAddr        NetAddr
	PeerAddr         NetAddr
	ConsistencyLevel int8
	PageSize         uint32
}

type NetAddr struct {
	IP   [16]uint8
	Port int32
}

func processFn(e *event) ptrace.SpanSlice {

	spans := ptrace.NewSpanSlice()
	span := spans.AppendEmpty()
	span.SetName("DB")
	span.SetKind(ptrace.SpanKindClient)
	span.SetStartTimestamp(utils.BootOffsetToTimestamp(e.StartTime))
	span.SetEndTimestamp(utils.BootOffsetToTimestamp(e.EndTime))
	span.SetTraceID(pcommon.TraceID(e.SpanContext.TraceID))
	span.SetSpanID(pcommon.SpanID(e.SpanContext.SpanID))
	span.SetFlags(uint32(trace.FlagsSampled))

	if e.ParentSpanContext.SpanID.IsValid() {
		span.SetParentSpanID(pcommon.SpanID(e.ParentSpanContext.SpanID))
	}

	span.Attributes().PutStr(string(semconv.DBSystemKey), semconv.DBSystemCassandra.Value.AsString())

	query := unix.ByteSliceToString(e.Query[:])
	if query != "" {
		span.Attributes().PutStr(string(semconv.DBQueryTextKey), query)
		// TODO: Add parsing of the query
		// TODO: Trace values to prepare the query
	}

	if e.ConsistencyLevel != 0 {
		span.Attributes().PutInt("db.consistency_level", int64(e.ConsistencyLevel))
	}

	if e.PageSize != 0 {
		span.Attributes().PutInt("db.page_size", int64(e.PageSize))
	}

	return spans
}
