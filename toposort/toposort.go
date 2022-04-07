// Package toposort is a generic version of https://github.com/philopon/go-toposort
package toposort

type Graph[T comparable] struct {
	nodes   []T
	outputs map[T]map[T]int
	inputs  map[T]int
}

func NewGraph[T comparable](cap int) *Graph[T] {
	return &Graph[T]{
		nodes:   make([]T, 0, cap),
		inputs:  make(map[T]int),
		outputs: make(map[T]map[T]int),
	}
}

func (g *Graph[T]) AddNode(name T) bool {
	g.nodes = append(g.nodes, name)

	if _, ok := g.outputs[name]; ok {
		return false
	}
	g.outputs[name] = make(map[T]int)
	g.inputs[name] = 0
	return true
}

func (g *Graph[T]) AddNodes(names ...T) bool {
	for _, name := range names {
		if ok := g.AddNode(name); !ok {
			return false
		}
	}
	return true
}

func (g *Graph[T]) AddEdge(from, to T) bool {
	m, ok := g.outputs[from]
	if !ok {
		return false
	}

	m[to] = len(m) + 1
	g.inputs[to]++

	return true
}

func (g *Graph[T]) unsafeRemoveEdge(from, to T) {
	delete(g.outputs[from], to)
	g.inputs[to]--
}

func (g *Graph[T]) RemoveEdge(from, to T) bool {
	if _, ok := g.outputs[from]; !ok {
		return false
	}
	g.unsafeRemoveEdge(from, to)
	return true
}

func (g *Graph[T]) Toposort() ([]T, bool) {
	L := make([]T, 0, len(g.nodes))
	S := make([]T, 0, len(g.nodes))

	for _, n := range g.nodes {
		if g.inputs[n] == 0 {
			S = append(S, n)
		}
	}

	for len(S) > 0 {
		var n T
		n, S = S[0], S[1:]
		L = append(L, n)

		ms := make([]T, len(g.outputs[n]))
		for m, i := range g.outputs[n] {
			ms[i-1] = m
		}

		for _, m := range ms {
			g.unsafeRemoveEdge(n, m)

			if g.inputs[m] == 0 {
				S = append(S, m)
			}
		}
	}

	N := 0
	for _, v := range g.inputs {
		N += v
	}

	if N > 0 {
		return L, false
	}

	return L, true
}
