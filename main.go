package main

import (
	"encoding/json"
	"fmt"
	"github.com/aidansteele/gha-stats/toposort"
	"github.com/shirou/gopsutil/v3/process"
	"sort"
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

func main() {
	for {
		time.Sleep(time.Second)
		dump()
	}
}

func dump() {
	procs, err := process.Processes()
	if err != nil {
		panic(err)
	}

	snapshots := make([]snapshot, len(procs))
	byPid := make(map[int32]*snapshot, len(procs))
	topo := toposort.NewGraph[int32](len(procs))

	for idx, proc := range procs {
		pid := proc.Pid
		ppid, _ := proc.Ppid()
		name, _ := proc.Name()
		cpu, _ := proc.CPUPercent()
		mem, _ := proc.MemoryPercent()
		exe, _ := proc.Exe()

		snapshots[idx] = snapshot{
			Pid:    pid,
			Ppid:   ppid,
			Name:   name,
			Exe:    exe,
			CpuPct: cpu,
			MemPct: mem,
		}

		byPid[pid] = &snapshots[idx]
		topo.AddNodes(pid)
		topo.AddEdge(pid, ppid)
	}

	sorted, ok := topo.Toposort()
	if !ok {
		panic("topo failed")
	}

	for _, pid := range sorted {

		snap := byPid[pid]
		if snap == nil {
			fmt.Printf("didn't find pid %d\n", pid)
			continue
		}

		parent := byPid[snap.Ppid]
		if parent == nil {
			fmt.Printf("didn't find ppid %d\n", parent)
			continue
		}

		snap.MemCumul += snap.MemPct
		parent.MemCumul += snap.MemCumul
	}

	sort.Slice(snapshots, func(i, j int) bool {
		return snapshots[i].MemCumul < snapshots[j].MemCumul
	})

	j, _ := json.Marshal(snapshots)
	fmt.Println(string(j))
}
