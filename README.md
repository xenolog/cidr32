# cidr32

Go-lang library to manipulate CIDR and IP range objects

usage:

```:go
import (
    "net"
    cidr32 "github.com/xenolog/cidr32/v0"
)

// ...

_, cidr, _ := net.ParseCIDR("192.168.1.0/25")
baseRange := cidr32.CidrToRange(cidr, true)

a := baseRange.String() // will be "192.168.1.0-192.168.1.126"



```
