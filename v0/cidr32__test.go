package cidr32

import (
	"fmt"
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRange(t *testing.T) {
	Range1, err := NewRange("172.22.132.10")
	assert.Nil(t, err)
	assert.Equal(t,
		"172.22.132.10-172.22.132.10",
		Range1.String(),
	)
	assert.Equal(t,
		1,
		Range1.Len(),
	)

	Range2, err := NewRange("172.22.132.0-172.22.132.255")
	assert.Nil(t, err)
	assert.Equal(t,
		"172.22.132.0-172.22.132.255",
		Range2.String(),
	)
	assert.Equal(t,
		256,
		Range2.Len(),
	)

	Range3, err := NewRange("172.22.132.5-172.22.132.13")
	assert.Nil(t, err)
	assert.Equal(t,
		"172.22.132.5-172.22.132.13",
		Range3.String(),
	)
	assert.Equal(t,
		9,
		Range3.Len(),
	)
}

func TestCompareIP(t *testing.T) {
	assert.Equal(t,
		0,
		CompareIP(net.ParseIP("172.22.132.33"), net.ParseIP("172.22.132.33")),
	)
	assert.Equal(t,
		-1,
		CompareIP(net.ParseIP("172.22.132.33"), net.ParseIP("172.22.132.32")),
	)
	assert.Equal(t,
		1,
		CompareIP(net.ParseIP("172.22.132.33"), net.ParseIP("172.22.132.34")),
	)
	assert.Equal(t,
		32,
		CompareIP(net.ParseIP("172.22.132.0"), net.ParseIP("172.22.132.32")),
	)
	assert.Equal(t,
		2*256+127,
		CompareIP(net.ParseIP("172.22.132.0"), net.ParseIP("172.22.134.127")),
	)
}

func TestIPtoUint32(t *testing.T) {
	assert.Equal(t,
		uint32(0b01111111111110001100000010000001),
		IPtoUint32(net.ParseIP("127.248.192.129")),
	)
	assert.Equal(t,
		uint32(0b11111111111111111111111111111111),
		IPtoUint32(net.ParseIP("255.255.255.255")),
	)
	assert.Equal(t,
		uint32(0b00000000000000000000000000000000),
		IPtoUint32(net.ParseIP("0.0.0.0")),
	)
	assert.Equal(t,
		uint32(0b00000001000000010000000100000001),
		IPtoUint32(net.ParseIP("1.1.1.1")),
	)
}

func TestUint32toIP(t *testing.T) {
	assert.Equal(t,
		net.ParseIP("127.248.192.129").To4(),
		Uint32toIP(uint32(0b01111111111110001100000010000001)),
	)
	assert.Equal(t,
		net.ParseIP("255.255.255.255").To4(),
		Uint32toIP(uint32(0b11111111111111111111111111111111)),
	)
	assert.Equal(t,
		net.ParseIP("0.0.0.0").To4(),
		Uint32toIP(uint32(0b00000000000000000000000000000000)),
	)
	assert.Equal(t,
		net.ParseIP("1.1.1.1").To4(),
		Uint32toIP(uint32(0b00000001000000010000000100000001)),
	)
}

func TestNextIP(t *testing.T) {
	assert.Equal(t,
		net.ParseIP("0.0.0.1").To4(),
		NextIP(net.ParseIP("0.0.0.0").To4()),
	)
	assert.Equal(t,
		net.ParseIP("0.0.0.0").To4(),
		NextIP(net.ParseIP("255.255.255.255").To4()),
	)
	assert.Equal(t,
		net.ParseIP("127.0.0.1").To4(),
		NextIP(net.ParseIP("127.0.0.0").To4()),
	)
}

func TestPrevIP(t *testing.T) {
	assert.Equal(t,
		net.ParseIP("255.255.255.255").To4(),
		PrevIP(net.ParseIP("0.0.0.0").To4()),
	)
	assert.Equal(t,
		net.ParseIP("255.255.255.254").To4(),
		PrevIP(net.ParseIP("255.255.255.255").To4()),
	)
	assert.Equal(t,
		net.ParseIP("127.0.0.0").To4(),
		PrevIP(net.ParseIP("127.0.0.1").To4()),
	)
}

func TestCidrToRange(t *testing.T) {
	_, cidr, _ := net.ParseCIDR("192.168.92.0/24")
	rng, err := CidrToRange(cidr, true)
	assert.Nil(t, err)
	assert.Equal(t,
		"192.168.92.1-192.168.92.254",
		rng.String(),
	)
	assert.Equal(t,
		254,
		rng.Len(),
	)
	//
	rng, err = CidrToRange(cidr, false)
	assert.Nil(t, err)
	assert.Equal(t,
		"192.168.92.0-192.168.92.255",
		rng.String(),
	)
	assert.Equal(t,
		256,
		rng.Len(),
	)
	//
	_, cidr, _ = net.ParseCIDR("192.168.92.0/25")
	rng, err = CidrToRange(cidr, true)
	assert.Nil(t, err)
	assert.Equal(t,
		"192.168.92.1-192.168.92.126",
		rng.String(),
	)
	assert.Equal(t,
		126,
		rng.Len(),
	)
	//
	rng, err = CidrToRange(cidr, false)
	assert.Nil(t, err)
	assert.Equal(t,
		"192.168.92.0-192.168.92.127",
		rng.String(),
	)
	assert.Equal(t,
		128,
		rng.Len(),
	)
	//
	_, cidr, _ = net.ParseCIDR("192.168.92.33/32")
	rng, err = CidrToRange(cidr, true)
	assert.Nil(t, err)
	assert.Equal(t,
		"192.168.92.33-192.168.92.33", // one IP -- nothing to reserve
		rng.String(),
	)
	assert.Equal(t,
		1,
		rng.Len(),
	)
	//
	rng, err = CidrToRange(cidr, false)
	assert.Nil(t, err)
	assert.Equal(t,
		"192.168.92.33-192.168.92.33", // one IP -- nothing to reserve
		rng.String(),
	)
	assert.Equal(t,
		1,
		rng.Len(),
	)
	//
	_, cidr, _ = net.ParseCIDR("0.0.0.0/0")
	rng, err = CidrToRange(cidr, true)
	assert.Nil(t, err)
	assert.Equal(t,
		"0.0.0.1-255.255.255.254",
		rng.String(),
	)
	assert.Equal(t,
		256*256*256*256-2,
		rng.Len(),
	)
	//
	rng, err = CidrToRange(cidr, false)
	assert.Nil(t, err)
	assert.Equal(t,
		"0.0.0.0-255.255.255.255",
		rng.String(),
	)
	assert.Equal(t,
		256*256*256*256,
		rng.Len(),
	)
}

func TestNew32Range(t *testing.T) {
	rng, err := New32Range(
		IPtoUint32(net.ParseIP("192.168.1.10")),
		IPtoUint32(net.ParseIP("192.168.1.20")),
	)
	assert.Nil(t, err)
	assert.Equal(t,
		[2]uint32{0xc0a8010a, 0xc0a80114},
		rng.i32,
	)

	rng, err = New32Range(
		IPtoUint32(net.ParseIP("192.168.1.20")),
		IPtoUint32(net.ParseIP("192.168.1.10")),
	)
	assert.Error(t, err)

}

func TestCutToCidr(t *testing.T) {
	_, leftCidr, _ := net.ParseCIDR("172.22.132.0/28")
	_, middleCidr, _ := net.ParseCIDR("172.22.132.16/29")
	_, rightCidr, _ := net.ParseCIDR("172.22.132.32/28")
	_, absorbingCidr, _ := net.ParseCIDR("172.22.132.0/24")
	_, outsideLeftCidr, _ := net.ParseCIDR("172.22.131.64/28")
	_, outsideRightCidr, _ := net.ParseCIDR("172.22.132.64/28")
	rng, _ := NewRange("172.22.132.4-172.22.132.40")
	expectedLeft, _ := NewRange("172.22.132.4-172.22.132.15")
	expectedMiddle, _ := NewRange("172.22.132.16-172.22.132.23")
	expectedRight, _ := NewRange("172.22.132.32-172.22.132.40")
	expectedAbsorbing := rng

	// left
	actual, err := rng.CutToCidr(leftCidr, false)
	assert.Nil(t, err)
	assert.Equal(t, expectedLeft, actual)

	// middle
	actual, err = rng.CutToCidr(middleCidr, false)
	assert.Nil(t, err)
	assert.Equal(t, expectedMiddle, actual)

	// right
	actual, err = rng.CutToCidr(rightCidr, false)
	assert.Nil(t, err)
	assert.Equal(t, expectedRight, actual)

	// absorbing
	actual, err = rng.CutToCidr(absorbingCidr, false)
	assert.Nil(t, err)
	assert.Equal(t, expectedAbsorbing, actual)

	// outside left
	actual, err = rng.CutToCidr(outsideLeftCidr, false)
	assert.Error(t, err)
	assert.Nil(t, actual)

	// outside right
	actual, err = rng.CutToCidr(outsideRightCidr, false)
	assert.Error(t, err)
	assert.Nil(t, actual)
}

func TestIsIntersect(t *testing.T) {
	rng, _ := NewRange("172.22.132.50-172.22.132.100")
	// Negative
	exRng, _ := NewRange("172.22.132.10-172.22.132.20")
	assert.Equal(t,
		false,
		rng.IsIntersect(exRng),
	)
	exRng, _ = NewRange("172.22.132.120-172.22.132.200")
	assert.Equal(t,
		false,
		rng.IsIntersect(exRng),
	)
	// Positive
	exRng, _ = NewRange("172.22.132.40-172.22.132.50")
	assert.Equal(t,
		true,
		rng.IsIntersect(exRng),
	)
	exRng, _ = NewRange("172.22.132.90-172.22.132.110")
	assert.Equal(t,
		true,
		rng.IsIntersect(exRng),
	)
	exRng, _ = NewRange("172.22.132.60-172.22.132.80")
	assert.Equal(t,
		true,
		rng.IsIntersect(exRng),
	)
	exRng, _ = NewRange("172.22.132.80-172.22.132.200")
	assert.Equal(t,
		true,
		rng.IsIntersect(exRng),
	)
}

func TestExcludeRange(t *testing.T) {
	rng, _ := NewRange("172.22.132.50-172.22.132.100")
	// Negative
	exRng, _ := NewRange("172.22.132.10-172.22.132.20")
	actualRngs, n := rng.ExcludeRange(exRng)
	expectedRngs := IPRangeList{rng}
	assert.Equal(t, 0, n)
	assert.Equal(t, expectedRngs, actualRngs)
	//
	exRng, _ = NewRange("172.22.132.110-172.22.132.120")
	actualRngs, n = rng.ExcludeRange(exRng)
	expectedRngs = IPRangeList{rng}
	assert.Equal(t, 0, n)
	assert.Equal(t, expectedRngs, actualRngs)
	// Divide to 2
	exRng, _ = NewRange("172.22.132.60-172.22.132.80")
	actualRngs, n = rng.ExcludeRange(exRng)
	r1, _ := NewRange("172.22.132.50-172.22.132.59")
	r2, _ := NewRange("172.22.132.81-172.22.132.100")
	expectedRngs = IPRangeList{r1, r2}
	assert.Equal(t, 2, n)
	assert.Equal(t, expectedRngs, actualRngs)
	// Divide to 2 by one IP
	exRng, _ = NewRange("172.22.132.60-172.22.132.60")
	actualRngs, n = rng.ExcludeRange(exRng)
	r1, _ = NewRange("172.22.132.50-172.22.132.59")
	r2, _ = NewRange("172.22.132.61-172.22.132.100")
	expectedRngs = IPRangeList{r1, r2}
	assert.Equal(t, 2, n)
	assert.Equal(t, expectedRngs, actualRngs)
	// Left
	exRng, _ = NewRange("172.22.132.40-172.22.132.60")
	actualRngs, n = rng.ExcludeRange(exRng)
	r1, _ = NewRange("172.22.132.61-172.22.132.100")
	expectedRngs = IPRangeList{r1}
	assert.Equal(t, 1, n)
	assert.Equal(t, expectedRngs, actualRngs)
	// Left, same left edge
	exRng, _ = NewRange("172.22.132.50-172.22.132.60")
	actualRngs, n = rng.ExcludeRange(exRng)
	r1, _ = NewRange("172.22.132.61-172.22.132.100")
	expectedRngs = IPRangeList{r1}
	assert.Equal(t, 1, n)
	assert.Equal(t, expectedRngs, actualRngs)
	// Left, just touch
	exRng, _ = NewRange("172.22.132.40-172.22.132.50")
	actualRngs, n = rng.ExcludeRange(exRng)
	r1, _ = NewRange("172.22.132.51-172.22.132.100")
	expectedRngs = IPRangeList{r1}
	assert.Equal(t, 1, n)
	assert.Equal(t, expectedRngs, actualRngs)
	// Right, same right edge
	exRng, _ = NewRange("172.22.132.90-172.22.132.100")
	actualRngs, n = rng.ExcludeRange(exRng)
	r1, _ = NewRange("172.22.132.50-172.22.132.89")
	expectedRngs = IPRangeList{r1}
	assert.Equal(t, 1, n)
	assert.Equal(t, expectedRngs, actualRngs)
	// Right, just touch
	exRng, _ = NewRange("172.22.132.100-172.22.132.110")
	actualRngs, n = rng.ExcludeRange(exRng)
	r1, _ = NewRange("172.22.132.50-172.22.132.99")
	expectedRngs = IPRangeList{r1}
	assert.Equal(t, 1, n)
	assert.Equal(t, expectedRngs, actualRngs)
	// absorbing
	exRng, _ = NewRange("172.22.132.40-172.22.132.110")
	actualRngs, n = rng.ExcludeRange(exRng)
	expectedRngs = IPRangeList{}
	assert.Equal(t, -1, n)
	assert.Equal(t, expectedRngs, actualRngs)
}

func TestIPRangeList(t *testing.T) {
	ipRanges := IPRangeList{}
	for i := 0; i <= 4; i = i + 2 {
		r, _ := NewRange(fmt.Sprintf("192.169.%d.0-192.169.%d.255", i, i))
		ipRanges = append(ipRanges, r)
	}
	assert.Equal(t,
		"192.169.0.0-192.169.0.255\n192.169.2.0-192.169.2.255\n192.169.4.0-192.169.4.255",
		ipRanges.String(),
	)
	assert.Equal(t,
		256*3,
		ipRanges.Capacity(),
	)
}

func TestExcludeRangeFromRangeList(t *testing.T) {
	r1, _ := NewRange("172.22.132.10-172.22.132.20")
	r2, _ := NewRange("172.22.132.30-172.22.132.50")
	r3, _ := NewRange("172.22.132.80-172.22.132.90")
	baseRangeList := IPRangeList{r1, r2, r3}

	// outside existing ranges
	exRng, _ := NewRange("172.22.132.3-172.22.132.5")
	actualRangeList, n := baseRangeList.ExcludeRange(exRng)
	assert.Equal(t, 0, n)
	assert.Equal(t, baseRangeList, *actualRangeList)

	// split first of existing ranges
	exRng, _ = NewRange("172.22.132.13-172.22.132.16")
	actualRangeList, n = baseRangeList.ExcludeRange(exRng)
	d1, _ := NewRange("172.22.132.10-172.22.132.12")
	d2, _ := NewRange("172.22.132.17-172.22.132.20")
	expectedRangeList := IPRangeList{d1, d2, r2, r3}
	assert.Equal(t, 2, n)
	assert.Equal(t, expectedRangeList, *actualRangeList)
	// split one of midle in existing ranges
	exRng, _ = NewRange("172.22.132.35-172.22.132.40")
	actualRangeList, n = baseRangeList.ExcludeRange(exRng)
	d1, _ = NewRange("172.22.132.30-172.22.132.34")
	d2, _ = NewRange("172.22.132.41-172.22.132.50")
	expectedRangeList = IPRangeList{r1, d1, d2, r3}
	assert.Equal(t, 2, n)
	assert.Equal(t, expectedRangeList, *actualRangeList)
	// split last of existing ranges
	exRng, _ = NewRange("172.22.132.83-172.22.132.85")
	actualRangeList, n = baseRangeList.ExcludeRange(exRng)
	d1, _ = NewRange("172.22.132.80-172.22.132.82")
	d2, _ = NewRange("172.22.132.86-172.22.132.90")
	expectedRangeList = IPRangeList{r1, r2, d1, d2}
	assert.Equal(t, 2, n)
	assert.Equal(t, expectedRangeList, *actualRangeList)

	// cut one of existing ranges
	exRng, _ = NewRange("172.22.132.25-172.22.132.40")
	actualRangeList, n = baseRangeList.ExcludeRange(exRng)
	d1, _ = NewRange("172.22.132.41-172.22.132.50")
	expectedRangeList = IPRangeList{r1, d1, r3}
	assert.Equal(t, 1, n)
	assert.Equal(t, expectedRangeList, *actualRangeList)

	// cut two of existing ranges by one range
	exRng, _ = NewRange("172.22.132.45-172.22.132.85")
	actualRangeList, n = baseRangeList.ExcludeRange(exRng)
	d1, _ = NewRange("172.22.132.30-172.22.132.44")
	d2, _ = NewRange("172.22.132.86-172.22.132.90")
	expectedRangeList = IPRangeList{r1, d1, d2}
	assert.Equal(t, 1, n)
	assert.Equal(t, expectedRangeList, *actualRangeList)

	// absorbing a first of existing ranges by larger range
	exRng, _ = NewRange("172.22.132.5-172.22.132.25")
	actualRangeList, n = baseRangeList.ExcludeRange(exRng)
	expectedRangeList = IPRangeList{r2, r3}
	assert.Equal(t, 2, n)
	assert.Equal(t, expectedRangeList, *actualRangeList)
	// absorbing a middle of existing ranges by larger range
	exRng, _ = NewRange("172.22.132.25-172.22.132.55")
	actualRangeList, n = baseRangeList.ExcludeRange(exRng)
	expectedRangeList = IPRangeList{r1, r3}
	assert.Equal(t, 2, n)
	assert.Equal(t, expectedRangeList, *actualRangeList)
	// absorbing a last of existing ranges by larger range
	exRng, _ = NewRange("172.22.132.75-172.22.132.95")
	actualRangeList, n = baseRangeList.ExcludeRange(exRng)
	expectedRangeList = IPRangeList{r1, r2}
	assert.Equal(t, 2, n)
	assert.Equal(t, expectedRangeList, *actualRangeList)
}

func TestIPSearchIndex(t *testing.T) {
	allocatedAddrs := []string{
		"192.168.1.38", "192.168.1.39", "192.168.1.40", "192.168.1.41", "192.168.1.79", "192.168.1.80", "192.168.1.81", "192.168.1.82",
	}
	allocatedIPs := NewIPList(allocatedAddrs)

	assert.Equal(t,
		2,
		allocatedIPs.Index(IPtoUint32(net.ParseIP("192.168.1.40"))),
	)
	assert.Equal(t,
		-1,
		allocatedIPs.Index(IPtoUint32(net.ParseIP("192.168.1.36"))),
	)

}
func TestIPSort(t *testing.T) {
	allocatedAddrs := []string{
		"192.168.1.79", "192.168.1.80", "192.168.1.81", "192.168.1.82", "192.168.1.38", "192.168.1.39", "192.168.1.40", "192.168.1.41",
	}
	allocatedIPs := NewIPList(allocatedAddrs)
	allocatedIPs.Sort()

	assert.Equal(t,
		"192.168.1.38, 192.168.1.39, 192.168.1.40, 192.168.1.41, 192.168.1.79, 192.168.1.80, 192.168.1.81, 192.168.1.82",
		allocatedIPs.String(),
	)

}
