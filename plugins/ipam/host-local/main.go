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

package main

import (
	"fmt"
	"strings"

	"github.com/containernetworking/cni/plugins/ipam/host-local/backend/allocator"
	"github.com/containernetworking/cni/plugins/ipam/host-local/backend/disk"

	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/current"
	"github.com/containernetworking/cni/pkg/version"
)

func main() {
	skel.PluginMain(cmdAdd, cmdDel, version.All)
}

func cmdAdd(args *skel.CmdArgs) error {
	ipamConf, confVersion, netName, err := allocator.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	result := &current.Result{}

	// Generate allocator for each configured subnet
	var allocators []*allocator.IPAllocator
	for _, subnet := range ipamConf.Subnets {
		subdir := allocator.SubnetNameStr(netName, subnet)
		store, err := disk.New(subdir, ipamConf.DataDir)
		if err != nil {
			return err
		}
		defer store.Close()

		allocator, err := allocator.NewIPAllocator(ipamConf, subnet, store)
		if err != nil {
			return err
		}

		if ipamConf.ResolvConf != "" {
			dns, err := parseResolvConf(ipamConf.ResolvConf)
			if err != nil {
				return err
			}
			result.DNS = *dns
		}

		allocators = append(allocators, allocator)
	}

	// Allocate IP(s)
	for index, allocator := range allocators {
		ipConf, routes, err := allocator.Get(args.ContainerID)
		if err != nil {
			// Roll back on failure: Release any IPs that
			// were just allocated.
			for i := 0; i < index; i++ {
				allocators[i].Release(args.ContainerID)
			}
			return err
		}
		result.IPs = append(result.IPs, ipConf)
		result.Routes = append(result.Routes, routes...)
	}

	return types.PrintResult(result, confVersion)
}

func cmdDel(args *skel.CmdArgs) error {
	ipamConf, _, netName, err := allocator.LoadIPAMConfig(args.StdinData, args.Args)
	if err != nil {
		return err
	}

	// Release IP for each configured subnet, keeping a list of
	// any errors encountered.
	var errors []string
	for _, subnet := range ipamConf.Subnets {
		subdir := allocator.SubnetNameStr(netName, subnet)
		store, err := disk.New(subdir, ipamConf.DataDir)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}
		defer store.Close()

		allocator, err := allocator.NewIPAllocator(ipamConf, subnet, store)
		if err != nil {
			errors = append(errors, err.Error())
			continue
		}

		err = allocator.Release(args.ContainerID)
		if err != nil {
			errors = append(errors, err.Error())
		}
	}

	if errors != nil {
		return fmt.Errorf(strings.Join(errors, ","))
	}
	return nil
}
