package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aidansteele/gha-stats/toposort"
	"github.com/sevlyar/go-daemon"
	"github.com/shirou/gopsutil/v3/process"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.7.0"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/grpc/credentials"
	"io/ioutil"
	"os"
	"sort"
	"strconv"
	"time"
)

type processIdentity struct {
	Pid  int32
	Ppid int32
	Name string
	Exe  string
}

type processSnapshot struct {
	processIdentity
	CpuPct   float64
	Mem      uint64
	MemPct   float32
	MemCumul float32
}

type snapshot struct {
	GithubRunId string
	Time        time.Time
	Processes   []processSnapshot
}

func start() (*daemon.Context, bool) {
	dctx := &daemon.Context{
		PidFileName: "/tmp/gha.pid",
		LogFileName: "/tmp/gha.log",
		WorkDir:     "./",
	}

	d, err := dctx.Reborn()
	if err != nil {
		panic(err)
	}

	return dctx, d != nil
}

func setupOtel(ctx context.Context) (func(ctx context.Context) error, error) {
	exp, err := newExporter(ctx)
	if err != nil {
		return nil, fmt.Errorf("setting up otel exporter: %w", err)
	}

	tp := newTraceProvider(exp, "gha-stats")

	otel.SetTracerProvider(tp)
	otel.SetTextMapPropagator(
		propagation.NewCompositeTextMapPropagator(
			propagation.TraceContext{},
			propagation.Baggage{},
		),
	)

	return tp.ForceFlush, nil
}

func newExporter(ctx context.Context) (*otlptrace.Exporter, error) {
	opts := []otlptracegrpc.Option{
		otlptracegrpc.WithEndpoint("api.honeycomb.io:443"),
		otlptracegrpc.WithHeaders(map[string]string{
			"x-honeycomb-team":    os.Getenv("HONEYCOMB_API_KEY"),
			"x-honeycomb-dataset": "gha-stats",
		}),
		otlptracegrpc.WithTLSCredentials(credentials.NewClientTLSFromCert(nil, "")),
	}

	client := otlptracegrpc.NewClient(opts...)
	return otlptrace.New(ctx, client)
}

func newTraceProvider(exp *otlptrace.Exporter, serviceName string) *sdktrace.TracerProvider {
	// The service.name attribute is required.
	res := resource.NewWithAttributes(
		semconv.SchemaURL,
		semconv.ServiceNameKey.String(serviceName),
	)

	return sdktrace.NewTracerProvider(
		sdktrace.WithSampler(sdktrace.AlwaysSample()),
		sdktrace.WithBatcher(exp),
		sdktrace.WithResource(res),
		//sdktrace.WithIDGenerator(xray.NewIDGenerator()),
	)
}

func run(interval time.Duration) {
	ctx := context.Background()

	flush, err := setupOtel(ctx)
	if err != nil {
		panic(err)
	}

	defer flush(ctx)

	for {
		time.Sleep(interval)

		snap, err := getSnapshot(ctx, interval)
		if err != nil {
			panic(err)
		}

		j, _ := json.Marshal(snap)
		fmt.Fprintln(os.Stderr, string(j))
	}
}

func stop() {
	fmt.Println("i stopped")

	pidBytes, err := ioutil.ReadFile("/tmp/gha.pid")
	if err != nil {
		panic(err)
	}

	pid, _ := strconv.Atoi(string(pidBytes))
	fmt.Printf("pid = %d\n", pid)

	proc, err := os.FindProcess(pid)
	if err != nil {
		panic(err)
	}

	err = proc.Kill()
	if err != nil {
		panic(err)
	}
}

func main() {
	switch os.Args[1] {
	case "start":
		dctx, parent := start()

		interval, err := time.ParseDuration(os.Args[2])
		if err != nil {
			panic(err)
		}

		if parent {
			fmt.Fprintf(os.Stderr, "i am the parent (pid=%d). goodbye\n", os.Getpid())
		} else {
			defer dctx.Release()
			run(interval)
		}
	case "stop":
		stop()
	default:
		fmt.Println("unrecognised command " + os.Args[1])
	}
}

func getSnapshot(ctx context.Context, interval time.Duration) (*snapshot, error) {
	endTimestamp := time.Now().Add(time.Duration(0.9 * float64(interval)))

	S := attribute.String
	I := attribute.Int64
	F := attribute.Float64

	tracer := otel.GetTracerProvider().Tracer("github.com/aidansteele/gha-stats")
	ctx, span := tracer.Start(ctx, "snapshot")
	span.SetAttributes(
		S("gha.run-id", os.Getenv("GITHUB_RUN_ID")),
		S("gha.actor", os.Getenv("GITHUB_ACTOR")),
		S("gha.repository", os.Getenv("GITHUB_REPOSITORY")),
		S("gha.workflow-name", os.Getenv("GITHUB_WORKFLOW")),
		S("gha.job-name", os.Getenv("GITHUB_JOB")),
	)
	defer span.End(trace.WithTimestamp(endTimestamp))

	procs, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("getting processes: %w", err)
	}

	processes := make([]processSnapshot, len(procs))
	byPid := make(map[int32]*processSnapshot, len(procs))
	topo := toposort.NewGraph[int32](len(procs))

	for idx, proc := range procs {
		func(idx int, proc *process.Process) {
			_, span := tracer.Start(ctx, "process")
			defer span.End(trace.WithTimestamp(endTimestamp))

			pid := proc.Pid
			ppid, _ := proc.Ppid()
			name, _ := proc.Name()
			exe, _ := proc.Exe()
			cpu, _ := proc.CPUPercent()
			mem, _ := proc.MemoryPercent()
			memInfo, _ := proc.MemoryInfo()
			rss := memInfo.RSS

			span.SetAttributes(
				S("process.pid", fmt.Sprintf("%d", pid)),
				S("process.ppid", fmt.Sprintf("%d", ppid)),
				S("process.name", name),
				S("process.exe", exe),
				F("process.cpu.pct", cpu),
				F("process.mem.pct", float64(mem)),
				I("process.mem.rss", int64(rss)),
			)

			processes[idx] = processSnapshot{
				processIdentity: processIdentity{
					Pid:  pid,
					Ppid: ppid,
					Name: name,
					Exe:  exe,
				},
				CpuPct: cpu,
				Mem:    rss,
				MemPct: mem,
			}

			byPid[pid] = &processes[idx]
			topo.AddNodes(pid)
			topo.AddEdge(pid, ppid)
		}(idx, proc)
	}

	sorted, ok := topo.Toposort()
	if !ok {
		return nil, fmt.Errorf("doing topo sort")
	}

	for _, pid := range sorted {
		snap := byPid[pid]
		if snap == nil {
			continue
		}

		parent := byPid[snap.Ppid]
		if parent == nil {
			continue
		}

		snap.MemCumul += snap.MemPct
		parent.MemCumul += snap.MemCumul
	}

	sort.Slice(processes, func(i, j int) bool {
		return processes[i].MemCumul < processes[j].MemCumul
	})

	return &snapshot{
		GithubRunId: "",
		Time:        time.Now(),
		Processes:   processes,
	}, nil
}
