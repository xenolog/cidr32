package cidr32

import (
	"fmt"
	"net"
	"strings"
)

// IPRange -- struct, perpesnts a IP range and set of corresponded methods
type IPRange struct {
	i32 [2]uint32
}

func (r IPRange) First32() uint32 {
	return r.i32[0]
}

func (r IPRange) Last32() uint32 {
	return r.i32[1]
}

func (r *IPRange) First() net.IP {
	return Uint32toIP(r.First32())
}

func (r *IPRange) Last() net.IP {
	return Uint32toIP(r.Last32())
}

func (r *IPRange) Len() int {
	return int(r.i32[1]-r.i32[0]) + 1
}

func (r *IPRange) String() string {
	return fmt.Sprintf("%s-%s", Uint32toIP(r.i32[0]), Uint32toIP(r.i32[1]))
}

//Cidr()

// IsIntersect -- return true if base range intercects with given
func (r *IPRange) IsIntersect(exRange *IPRange) (rv bool) {
	if exRange.Last32() < r.First32() || exRange.First32() > r.Last32() {
		// exRange outside me
		rv = false
	} else {
		rv = true
	}
	return
}

//CutToCidr --
func (r *IPRange) CutToCidr(cidr *net.IPNet, reserveNetBorders bool) (rv *IPRange, err error) {
	var edges [2]uint32
	exRange, err := CidrToRange(cidr, reserveNetBorders)
	if err != nil {
		return nil, err
	}

	if !r.IsIntersect(exRange) {
		return nil, fmt.Errorf("Ranges (%s) and (%s) are not intersected", r, exRange)
	}

	if r.First32() < exRange.First32() {
		edges[0] = exRange.First32()
	} else {
		edges[0] = r.First32()
	}
	if r.Last32() > exRange.Last32() {
		edges[1] = exRange.Last32()
	} else {
		edges[1] = r.Last32()
	}
	return New32Range(edges[0], edges[1])
}

// ExcludeRange -- Remove exRange's addresses and returns new IPRangeList as first.
// Also returns:
//   0 if no actions was
//   1 if range was changed
//   2 if range was splitted
//  -1 if range was absorbing
func (r *IPRange) ExcludeRange(exRange *IPRange) (rv IPRangeList, n int) {
	if !r.IsIntersect(exRange) {
		// No intersection
		rv = IPRangeList{r}
		return rv, 0
	}
	if exRange.First32() > r.First32() && exRange.Last32() < r.Last32() {
		// dvide R to parts
		r1, _ := New32Range(r.First32(), exRange.First32()-1)
		r2, _ := New32Range(exRange.Last32()+1, r.Last32())

		rv = IPRangeList{r1, r2}
	} else if exRange.First32() <= r.First32() && exRange.Last32() >= r.Last32() {
		// absorbing
		return IPRangeList{}, -1
	} else if exRange.First32() <= r.First32() && exRange.Last32() >= r.First32() {
		// Left
		tmp, _ := New32Range(exRange.Last32()+1, r.Last32())
		rv = IPRangeList{tmp}
	} else if exRange.First32() <= r.Last32() && exRange.Last32() >= r.Last32() {
		// Right
		tmp, _ := New32Range(r.First32(), exRange.First32()-1)
		rv = IPRangeList{tmp}
	}
	return rv, len(rv)
}

// ----------------------------------------------------------------------------

// New32Range -- got IP range in the uint32 format
func New32Range(first, last uint32) (*IPRange, error) {
	if first > last {
		return nil, fmt.Errorf("IP Range creation error: first edge IP should be less than last (%s,%s)", Uint32toIP(first), Uint32toIP(last))
	}
	return &IPRange{
		i32: [2]uint32{first, last},
	}, nil
}

// NewIPRange -- got IP range in the net.IP format
func NewIPRange(first, last net.IP) (*IPRange, error) {
	a := IPtoUint32(first.To4())
	b := IPtoUint32(last.To4())
	return New32Range(a, b)
}

// NewRange -- got IP range in the `A.B.C.D-E.F.G.H` or `A.B.C.D` for single
// address format. return pointer to IPRange struct
func NewRange(rangeS string) (*IPRange, error) {
	var ips [2]net.IP
	addrs := strings.Split(strings.TrimSpace(rangeS), "-")
	if len(addrs) == 0 {
		return &IPRange{}, fmt.Errorf("Can't parse range '%s', wrong format", rangeS)
	} else if len(addrs) == 1 {
		addrs = append(addrs, addrs[0])
	}
	for i, aS := range addrs {
		if ip := net.ParseIP(aS); ip != nil {
			ips[i] = ip.To4()
		} else {
			return &IPRange{}, fmt.Errorf("Can't parse range '%s': addr '%s' wrong", rangeS, aS)
		}
	}
	return NewIPRange(ips[0], ips[1])
}

// CidrToRange -- returns a pointer to IPRange for whole CIDR
// or without NET and Broadcast addresses if rserveation enabled
func CidrToRange(cidr *net.IPNet, reserveNetBorders bool) (rv *IPRange, err error) {
	first := IPtoUint32(cidr.IP.To4())
	last := first | ^IPtoUint32(net.IP(cidr.Mask).To4())
	if n, _ := cidr.Mask.Size(); reserveNetBorders && n < 31 {
		rv, err = New32Range(first+1, last-1)
	} else {
		rv, err = New32Range(first, last)
	}
	return rv, err
}
