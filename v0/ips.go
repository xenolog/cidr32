package cidr32

import (
	"net"
	"sort"
	"strings"
)

type IPList []uint32

func NewIPList(ips []string) *IPList {
	// rv := make(IPList, len(ips))
	rv := IPList{}
	for _, ip := range ips {
		if tmp := net.ParseIP(ip); tmp != nil {
			rv = append(rv, IPtoUint32(tmp))
		}
	}
	rv.Sort()
	return &rv
}

// ----------------------------------------------------------------------------

// Sort --
func (r IPList) Sort() {
	sort.Sort(r)
}

// Len for https://godoc.org/sort#Interface
func (r IPList) Len() int {
	return len(r)
}

// Less for https://godoc.org/sort#Interface
func (r IPList) Less(i, j int) bool {
	return r[i] < r[j]
}

// Swap for https://godoc.org/sort#Interface
func (r IPList) Swap(i, j int) {
	r[i], r[j] = r[j], r[i]
}

// Index -- seach IP and return it's index.
// returns -1 if not found
func (r IPList) Index(targetIP uint32) int {
	for i, ip := range r {
		if ip == targetIP {
			return i
		}
	}
	return -1
}

func (r IPList) Strings() []string {
	rv := make([]string, len(r))
	for i, ip := range r {
		rv[i] = Uint32toIP(ip).String()
	}
	return rv
}

func (r IPList) String() string {
	return strings.Join(r.Strings(), ", ")
}
