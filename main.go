package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/aidansteele/gha-stats/toposort"
	"github.com/sevlyar/go-daemon"
	"github.com/shirou/gopsutil/v3/process"
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

func run(interval time.Duration) {
	ctx := context.Background()

	for {
		time.Sleep(interval)

		snap, err := getSnapshot(ctx)
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

func getSnapshot(ctx context.Context) (*snapshot, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("getting processes: %w", err)
	}

	processes := make([]processSnapshot, len(procs))
	byPid := make(map[int32]*processSnapshot, len(procs))
	topo := toposort.NewGraph[int32](len(procs))

	for idx, proc := range procs {
		pid := proc.Pid
		ppid, _ := proc.Ppid()
		name, _ := proc.Name()
		cpu, _ := proc.CPUPercent()
		mem, _ := proc.MemoryPercent()
		exe, _ := proc.Exe()
		memInfo, _ := proc.MemoryInfo()
		rss := memInfo.RSS

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
