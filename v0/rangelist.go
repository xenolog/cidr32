package cidr32

import (
	"strings"
)

// IPRangeList -- list of IPRanges
type IPRangeList []IPRange

// Strings -- returns a list of string representation ranges
func (r IPRangeList) Strings() []string {
	var rv []string
	for _, r := range r {
		rv = append(rv, r.String())
	}
	return rv
}

func (r IPRangeList) String() string {
	return strings.Join(r.Strings(), "\n")
}

// ExcludeRange -- Remove exRange's addresses and returns pointer to new IPRangeList.
// also returns:
//   0 if no actions was
//   1 if amount of ranges unchanged
//   2 if amount of ranges was changed
func (r IPRangeList) ExcludeRange(exRange *IPRange) (IPRangeList, int) {
	var tmp IPRangeList
	n := 0
	rv := append(IPRangeList{}, r...) // initialize & copy
	e := len(rv)
	for i, shift := 0, 0; i < e; i++ {
		ner, nn := rv[i+shift].ExcludeRange(exRange)
		if nn == 0 {
			// no excludes was
		} else if nn == 1 {
			// curent range should be replaced by another range
			rv[i+shift] = ner[0]
			if n == 0 {
				n = 1
			}
		} else if nn == 2 {
			// curent range should be splitted and replaced by two
			if i+shift == 0 {
				tmp = append(IPRangeList{}, ner...)
				tmp = append(tmp, rv[1:]...)
			} else {
				tmp = append(IPRangeList{}, rv[:i+shift]...)
				tmp = append(tmp, ner[0])
				tmp = append(tmp, rv[i+shift:]...)
				tmp[i+shift+1] = ner[1]
			}
			shift = shift + 1
			rv = tmp
			if n < 2 {
				n = 2
			}
		} else if nn == -1 {
			// curent range should be removed
			rv = append(rv[:i+shift], rv[i+shift+1:]...)
			e = e - 1
			if n < 2 {
				n = 2
			}
		}
	}
	return rv, n
}

// Capacity --
func (r IPRangeList) Capacity() (rv int) {
	for _, r := range r {
		rv = rv + r.Len()
	}
	return rv
}

// Sorted --
func (r IPRangeList) Sorted() IPRangeList {
	// todo(sv): IMPLEMENT!!!
	return r
}

// Glued --
func (r IPRangeList) Glued() IPRangeList {
	// todo(sv): IMPLEMENT!!!
	return r
}

// Arranged -- sorted and Glued
func (r IPRangeList) Arranged() IPRangeList {
	// todo(sv): IMPLEMENT!!!
	tmp := r.Sorted()
	return tmp.Glued()
}

// ----------------------------------------------------------------------------
