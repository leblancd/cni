// Copyright 2015 CNI authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package allocator

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/Masterminds/semver"
	"github.com/containernetworking/cni/pkg/types"
)

const (
	// Maximum number of subnets allowed per family
	maxV4Subnets = 1
	maxV6Subnets = 1
)

// IPAMConfig represents the IP related network configuration.
// Subnet configuration can either be provided as a single "subnet"
// (or range) and "gateway" combination (legacy configuration), or as
// a list of multiple subnets, with each subnet configured as a "cidr"
// or range plus "gateway". Currently, a maximum of one subnet per IP
// family is allowed.
type IPAMConfig struct {
	Name       string
	Type       string         `json:"type"`
	RangeStart net.IP         `json:"rangeStart"`
	RangeEnd   net.IP         `json:"rangeEnd"`
	Subnets    []SubnetConfig `json:"subnets"`
	Subnet     types.IPNet    `json:"subnet"`
	Gateway    net.IP         `json:"gateway"`
	Routes     []types.Route  `json:"routes"`
	DataDir    string         `json:"dataDir"`
	ResolvConf string         `json:"resolvConf"`
	ReqIPs     []net.IP       `json:"-"`
}

// SubnetConfig defines a combination of either subnet CIDR or IP range
// and a gateway address to be used for multiple-subnet IPAM allocation.
type SubnetConfig struct {
	CIDR       types.IPNet `json:"cidr"`
	Gateway    net.IP      `json:"gateway"`
	RangeStart net.IP      `json:"rangeStart"`
	RangeEnd   net.IP      `json:"rangeEnd"`
}

type EnvArgs struct {
	types.CommonArgs
	IP  net.IP `json:"ip,omitempty"`
}

type Net struct {
	Name       string      `json:"name"`
	CNIVersion string      `json:"cniVersion"`
	Args       *NetArgs    `json:"args,omitempty"`
	IPAM       *IPAMConfig `json:"ipam,omitempty"`
}

type NetArgs struct {
	CNI  *CNIArgs `json:"cni,omitempty"`
}

type CNIArgs struct {
	IP   net.IP   `json:"ip,omitempty"`
	IPS  []net.IP `json:"ips,omitempty"`
}

// LoadIPAMConfig unmarshals a JSON network configuration and returns
// the embedded IPAM configuration, CNI version, and network name.
func LoadIPAMConfig(bytes []byte, args string) (*IPAMConfig, string, string, error) {
	n := Net{}
	if err := json.Unmarshal(bytes, &n); err != nil {
		return nil, "", "", err
	}

	ipamConf := n.IPAM
	if ipamConf == nil {
		return nil, "", "", fmt.Errorf("IPAM config missing 'ipam' key")
	}

	// Merge the singular subnet config into the multiple subnets
	// config so that all subnet config is available in one place.
	ipamConf.mergeSubnets()

	err := ipamConf.checkSubnetCount(n.CNIVersion)
	if err != nil {
		return nil, "", "", err
	}

	// Read requested IP from CNI_ARGS environment variable (deprecated)
	var reqIP net.IP
	if args != "" {
		envArgs := &EnvArgs{}
		err := types.LoadArgs(args, envArgs)
		if err != nil {
			return nil, "", "", err
		}
		reqIP = envArgs.IP
	}

	// Merge requested IP from CNI_ARGS environment with requested IPs
	// in the network configuration so that all requested IPs are
	// available in one list.
	ipamConf.mergeRequestedIPs(n.Args, reqIP)

	ipamConf.Name = n.Name

	return ipamConf, n.CNIVersion, n.Name, nil
}

// mergeSubnets merges any singular subnet configuration into the
// multiple subnets list configuration.
func (conf *IPAMConfig) mergeSubnets() {
	if conf.Subnet.IP != nil || conf.RangeStart != nil || conf.RangeEnd != nil {
		subnet := SubnetConfig{
			conf.Subnet,
			conf.Gateway,
			conf.RangeStart,
			conf.RangeEnd,
		}
		conf.Subnets = append(conf.Subnets, subnet)
	}
}

// checkSubnetCount returns an error if there are too many subnets
// configured for this CNI version or per IP family.
func (conf *IPAMConfig) checkSubnetCount(version string) error {
	maxOneSubnet, err := isSingleSubnetVersion(version)
	if err != nil {
		return err
	}

	var count, count4, count6 int
	for _, subnet := range conf.Subnets {
		if maxOneSubnet {
			if count++; count > 1 {
				return fmt.Errorf("cniVersion %s does not support multiple subnets", version)
			}
		}
		if ipVersion(subnet.CIDR.IP) == "4" {
			if count4++; count4 > maxV4Subnets {
				return fmt.Errorf("Too many IPv4 subnets configured, only %d allowed", maxV4Subnets)
			}
		} else {
			if count6++; count6 > maxV6Subnets {
				return fmt.Errorf("Too many IPv6 subnets configured, only %d allowed", maxV6Subnets)
			}
		}
	}
	return nil
}

// mergeRequestedIPs compiles a list of requested IP(s) by combining
// requested IP(s) from network configuration with any requested IP
// from the CNI_ARGS environment variable.
func (conf *IPAMConfig) mergeRequestedIPs(args *NetArgs, envReqIP net.IP) {
	if args != nil && args.CNI != nil {
		conf.ReqIPs = args.CNI.IPS
		if args.CNI.IP != nil {
			conf.ReqIPs = append(conf.ReqIPs, args.CNI.IP)
		}
	}
	if envReqIP != nil {
		conf.ReqIPs = append(conf.ReqIPs, envReqIP)
	}
}

// isSingleSubnetVersion determines if the selected CNI version supports
// only a single IP subnet/address.
func isSingleSubnetVersion(version string) (bool, error) {
	c, _ := semver.NewConstraint("< 0.3.0")
	v, err := semver.NewVersion(version)
	if err != nil {
		return false, fmt.Errorf("Invalid cniVersion: %s", version)
	}
	return c.Check(v), nil
}

// SubnetNameStr creates a unique name for a subnet by appending the
// IP version to the network name. In the future, if more than one
// subnet per IP version is allowed, then the generated name will need
// to depend on the subnet's CIDR in order to guarantee uniqueness
// among subnets of a given IP version.
func SubnetNameStr(netName string, subnet SubnetConfig) string {
	return netName + ipVersion(subnet.CIDR.IP)
}

func convertRoutesToCurrent(routes []types.Route) []*types.Route {
	var currentRoutes []*types.Route
	for _, r := range routes {
		currentRoutes = append(currentRoutes, &types.Route{
			Dst: r.Dst,
			GW:  r.GW,
		})
	}
	return currentRoutes
}
