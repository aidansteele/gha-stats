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

type snapshot struct {
	Pid      int32
	Ppid     int32
	Name     string
	Exe      string
	CpuPct   float64
	MemPct   float32
	MemCumul float32
}

func start() (*daemon.Context, bool) {
	dctx := &daemon.Context{
		PidFileName: "/tmp/gha.pid",
		//PidFilePerm: 0,
		LogFileName: "/tmp/gha.log",
		//LogFilePerm: 0,
		WorkDir: "./",
		//Chroot:      "",
		//Env:         nil,
		//Args:        nil,
		//Credential: &syscall.Credential{
		//	Uid:         0,
		//	Gid:         0,
		//	Groups:      nil,
		//	NoSetGroups: false,
		//},
		//Umask: 0,
	}

	d, err := dctx.Reborn()
	if err != nil {
		panic(err)
	}

	return dctx, d != nil
}

func run() {
	ctx := context.Background()

	for {
		time.Sleep(time.Second)

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

	log, err := ioutil.ReadFile("/tmp/gha.log")
	if err != nil {
		panic(err)
	}

	fmt.Println(string(log))

	fmt.Println("i logged ^")
}

func main() {
	switch os.Args[1] {
	case "start":
		dctx, parent := start()
		if parent {
			fmt.Fprintf(os.Stderr, "i am the parent (pid=%d). goodbye\n", os.Getpid())
		} else {
			defer dctx.Release()
			run()
		}
	case "stop":
		stop()
	default:
		fmt.Println("unrecognised command " + os.Args[1])
	}
}

func getSnapshot(ctx context.Context) ([]snapshot, error) {
	procs, err := process.Processes()
	if err != nil {
		return nil, fmt.Errorf("getting processes: %w", err)
	}

	slice := make([]snapshot, len(procs))
	byPid := make(map[int32]*snapshot, len(procs))
	topo := toposort.NewGraph[int32](len(procs))

	for idx, proc := range procs {
		pid := proc.Pid
		ppid, _ := proc.Ppid()
		name, _ := proc.Name()
		cpu, _ := proc.CPUPercent()
		mem, _ := proc.MemoryPercent()
		exe, _ := proc.Exe()

		slice[idx] = snapshot{
			Pid:    pid,
			Ppid:   ppid,
			Name:   name,
			Exe:    exe,
			CpuPct: cpu,
			MemPct: mem,
		}

		byPid[pid] = &slice[idx]
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
			fmt.Fprintf(os.Stderr, "didn't find pid %d\n", pid)
			continue
		}

		parent := byPid[snap.Ppid]
		if parent == nil {
			fmt.Fprintf(os.Stderr, "didn't find ppid %d\n", parent)
			continue
		}

		snap.MemCumul += snap.MemPct
		parent.MemCumul += snap.MemCumul
	}

	sort.Slice(slice, func(i, j int) bool {
		return slice[i].MemCumul < slice[j].MemCumul
	})

	return slice, nil
}
