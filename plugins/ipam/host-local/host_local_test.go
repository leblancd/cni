// Copyright 2016 CNI authors
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
	"io/ioutil"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/containernetworking/cni/pkg/ip"
	"github.com/containernetworking/cni/pkg/skel"
	"github.com/containernetworking/cni/pkg/testutils"
	"github.com/containernetworking/cni/pkg/types"
	"github.com/containernetworking/cni/pkg/types/020"
	"github.com/containernetworking/cni/pkg/types/current"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

// Interface name and namespace path for testing
const (
	ifname string = "eth0"
	nspath string = "/some/where"
)

// Snippets for generating JSON network configuration.
const (
	netConfStr = `
    "cniVersion": "%s",
    "name": "mynet",
    "type": "ipvlan",
    "master": "foo0",
    "ipam": {
        "type":    "host-local",
        "dataDir": "%s"`

	// Singular subnet configuration (legacy)
	subnetConfStr = `,
        "subnet":  "%s"`
	gatewayConfStr = `,
        "gateway": "%s"`

	// Subnets list configuration
	subnetsStartStr = `,
        "subnets": [`
	cidrConfStr = `
            {
                "cidr":    "%s"
            }`
	cidrGWConfStr = `
            {
                "cidr":    "%s",
                "gateway": "%s"
            }`
	cidrRangeGWConfStr = `
            {
                "cidr":       "%s",
	        "rangeStart": "%s",
	        "rangeEnd":   "%s",
                "gateway":    "%s"
            }`
	subnetsEndStr = `
        ]`

	resolvConfStr = `,
        "resolvConf": "%s/resolv.conf"`

	ipamEndStr = `
    }`

	// Requested IP(s) configuration
	reqIPStartStr = `,
    "args": {
        "cni": {`

	// Singlular requested IP configuration
	singleReqIPStr = `
            "ip": "%s"`

	// Multiple requested IP configuration
	multiReqIPsStartStr = `
            "ips": [`
	multiReqIPsStr = `
                "%s"`
	multiReqIPsEndStr = `
            ]`

	reqIPEndStr = `
        }
    }`
)

// Format of CNI_ARGS environment variable content for requesting
// a specific IP to be allocated. (The use of CNI_ARGS has been deprecated).
const cniArgsReqIPStr = "IP=%s"

// testCase defines the CNI network configuration and optionally
// a simulated fault to include in a given test case.
type testCase struct {
	cniVersion   string         // CNI Version
	subnet       string         // Single subnet configuration: Subnet CIDR
	gateway      string         // Single subnet configuration: Gateway
	subnets      []subnetInfo   // Multiple subnets configuration
	dnsAddrs     []string       // List of DNS servers
	envReqIP     string         // Simulate IP requested via CNI_ARGS environment
	requestedIPs []string       // List of IPs to request via network config
	fault        simulatedFault // Fault to simulate for test
	expError     string         // Expect an error containing this substring
}

// Subnet definition for each entry in a multiple subnets list
type subnetInfo struct {
	cidr       string
	gateway    string
	rangeStart string
	rangeEnd   string
}

// Enumeration of simulated faults to test
type simulatedFault int
const (
	whiteSpaceInDiskFile simulatedFault = iota
)

// netConf() generates a JSON network configuration string for testing
// based upon the testCase configuration.
func (tc testCase) netConf(dataDir string, resolvDir string) string {
	conf := fmt.Sprintf(netConfStr, tc.cniVersion, dataDir)
	if tc.subnet != "" {
		conf += tc.singleSubnetConfig()
	}
	if tc.subnets != nil {
		conf += tc.multipleSubnetsConfig()
	}
	if resolvDir != "" {
		conf += fmt.Sprintf(resolvConfStr, resolvDir)
	}
	conf += ipamEndStr
	if len(tc.requestedIPs) == 1 {
		conf += tc.singleReqIPConfig()
	} else if len(tc.requestedIPs) > 1 {
		conf += tc.multipleReqIPsConfig()
	}
	return "{" + conf + "\n}"
}

func (tc testCase) singleSubnetConfig() string {
	conf := fmt.Sprintf(subnetConfStr, tc.subnet)
	if tc.gateway != "" {
		conf += fmt.Sprintf(gatewayConfStr, tc.gateway)
	}
	return conf
}

func (tc testCase) multipleSubnetsConfig() string {
	conf := subnetsStartStr
	for i, subnet := range tc.subnets {
		if i > 0 {
			conf += ","
		}
		switch {
		case subnet.gateway == "":
			conf += fmt.Sprintf(cidrConfStr, subnet.cidr)
		case subnet.rangeStart != "":
			conf += fmt.Sprintf(cidrRangeGWConfStr, subnet.cidr, subnet.rangeStart, subnet.rangeEnd, subnet.gateway)
		default:
			conf += fmt.Sprintf(cidrGWConfStr, subnet.cidr, subnet.gateway)
		}
	}
	return conf + subnetsEndStr
}

func (tc testCase) createResolvFile(tmpDir string) error {
	var resolvStr string
	for _, addr := range tc.dnsAddrs {
		resolvStr += fmt.Sprintf("nameserver %s\n", addr)
	}
	return ioutil.WriteFile(filepath.Join(tmpDir, "resolv.conf"), []byte(resolvStr), 0644)
}

func (tc testCase) singleReqIPConfig() string {
	conf := fmt.Sprintf(singleReqIPStr, tc.requestedIPs[0])
	return reqIPStartStr + conf + reqIPEndStr
}

func (tc testCase) multipleReqIPsConfig() string {
	conf := reqIPStartStr + multiReqIPsStartStr
	for i, reqIP := range tc.requestedIPs {
		if i > 0 {
			conf += ","
		}
		conf += fmt.Sprintf(multiReqIPsStr, reqIP)
	}
	return conf + multiReqIPsEndStr + reqIPEndStr
}

func (tc testCase) createCmdArgs(tmpDir string) (*skel.CmdArgs, error) {
	var resolvDir string
	if tc.dnsAddrs != nil {
		err := tc.createResolvFile(tmpDir)
		if err != nil {
			return nil, err
		}
		resolvDir = tmpDir
	}
	conf := tc.netConf(tmpDir, resolvDir)
	var containerID string
	if tc.fault == whiteSpaceInDiskFile {
		containerID = "   dummy\n "
	} else {
		containerID = "dummy"
	}
	var envArgs string
	if tc.envReqIP != "" {
		envArgs = fmt.Sprintf(cniArgsReqIPStr, tc.envReqIP)
	}
	cmdArgs := skel.CmdArgs{
		ContainerID: containerID,
		Netns:       nspath,
		IfName:      ifname,
		Args:        envArgs,
		StdinData:   []byte(conf),
	}
	return &cmdArgs, nil
}

func (tc testCase) expectedAddrs(subnet subnetInfo) (net.IP, net.IP, error) {
	var gw, addr net.IP
	subnetIP, subnetNet, err := net.ParseCIDR(subnet.cidr)
	if err != nil {
		return nil, nil, err
	}
	firstIP := ip.NextIP(subnetIP)

	// If there are any requested IPs, see if any of them are
	// contained within the target subnet range.
	reqIPs := tc.requestedIPs
	if tc.envReqIP != "" {
		reqIPs = append(reqIPs, tc.envReqIP)
	}
	for _, reqIP := range reqIPs {
		targetIP := net.ParseIP(reqIP)
		if subnetNet.Contains(targetIP) {
			gw   = firstIP
			addr = targetIP
		}
	}

	switch {
	case addr != nil:
		// Address already chosen from requested IPs
	case subnet.gateway == "":
		gw = firstIP
		addr = ip.NextIP(gw)
	case subnet.rangeStart != "":
		gw = net.ParseIP(subnet.gateway)
		addr = net.ParseIP(subnet.rangeStart)
	default:
		gw = net.ParseIP(subnet.gateway)
		if gw.String() == firstIP.String() {
			addr = ip.NextIP(gw)
		} else {
			addr = firstIP
		}
	}
	return addr.To16(), gw.To16(), nil
}

func ipVersion(ip net.IP) string {
	if ip.To4() != nil {
		return "4"
	}
	return "6"
}

func createTmpDir() string {
	tmpDir, err := ioutil.TempDir("", "host_local_artifacts")
	Expect(err).NotTo(HaveOccurred())
	return tmpDir
}

type cniTester interface {
	cmdAddTest(tc testCase, cniVersion string)
	cmdDelTest()
	getRawResult() []byte
}

func cniTesterByVersion(version string) cniTester {
	switch {
	case strings.HasPrefix(version, "0.3."):
		return &cniTestV03x{}
	default:
		return &cniTestV01or2x{}
	}
}

type cniTestV03x struct {
	args      *skel.CmdArgs
	rawResult []byte
	ipFiles   []string
}

func (test *cniTestV03x) cmdAddTest(tc testCase, tmpDir string) {
	var err error
	test.args, err = tc.createCmdArgs(tmpDir)
	Expect(err).NotTo(HaveOccurred())

	// Allocate the IP(s)
	var r types.Result
	r, test.rawResult, err = testutils.CmdAddWithResult(nspath, ifname, test.args.StdinData, func() error {
		return cmdAdd(test.args)
	})
	Expect(err).NotTo(HaveOccurred())
	Expect(strings.Index(string(test.rawResult), "\"version\":")).Should(BeNumerically(">", 0))

	result, err := current.GetResult(r)
	Expect(err).NotTo(HaveOccurred())

	allSubnets := tc.subnets
	if tc.subnet != "" {
		allSubnets = append(allSubnets,
			subnetInfo{cidr: tc.subnet, gateway: tc.gateway})
	}
	for _, subnet := range allSubnets {
		expAddress, expGateway, err := tc.expectedAddrs(subnet)
		Expect(err).NotTo(HaveOccurred())
		found := false
		for _, ip := range result.IPs {
			if ip.Address.IP.String() == expAddress.String() {
				Expect(ip.Gateway).To(Equal(expGateway))
				found = true
			}
		}
		Expect(found).To(Equal(true))

		netDir := "mynet" + ipVersion(expAddress)
		ipFilePath := filepath.Join(tmpDir, netDir, expAddress.String())
		test.ipFiles = append(test.ipFiles, ipFilePath)
		contents, err := ioutil.ReadFile(ipFilePath)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(contents)).To(Equal("dummy"))

		lastFilePath := filepath.Join(tmpDir, netDir, "last_reserved_ip")
		contents, err = ioutil.ReadFile(lastFilePath)
		Expect(err).NotTo(HaveOccurred())
		Expect(string(contents)).To(Equal(expAddress.String()))
	}

	// Check that the results include all DNS server addresses
	for _, addr := range tc.dnsAddrs {
		found := false
		for _, dns := range result.DNS.Nameservers {
			if dns == addr {
				found = true
			}
		}
		Expect(found).To(Equal(true))
	}
}

func (test *cniTestV03x) cmdDelTest() {
	// Release the IP(s)
	err := testutils.CmdDelWithResult(nspath, ifname, func() error {
		return cmdDel(test.args)
	})
	Expect(err).NotTo(HaveOccurred())

	for _, ipFile := range test.ipFiles {
		_, err = os.Stat(ipFile)
		Expect(err).To(HaveOccurred())
	}
}

func (test *cniTestV03x) getRawResult() []byte {
	return test.rawResult
}

type cniTestV01or2x struct {
	args       *skel.CmdArgs
	rawResult  []byte
	ipFilePath string
}

func (test *cniTestV01or2x) cmdAddTest(tc testCase, tmpDir string) {
	var err error
	test.args, err = tc.createCmdArgs(tmpDir)
	Expect(err).NotTo(HaveOccurred())

	// Allocate the IP(s)
	var r types.Result
	r, test.rawResult, err = testutils.CmdAddWithResult(nspath, ifname, test.args.StdinData, func() error {
		return cmdAdd(test.args)
	})
	if tc.expError != "" {
		Expect(err).To(MatchError(ContainSubstring(tc.expError)))
		return
	}
	Expect(err).NotTo(HaveOccurred())
	Expect(strings.Index(string(test.rawResult), "\"ip\":")).Should(BeNumerically(">", 0))

	result, err := types020.GetResult(r)
	Expect(err).NotTo(HaveOccurred())

	subnet := subnetInfo{cidr: tc.subnet, gateway: tc.gateway}
	expAddress, expGateway, err := tc.expectedAddrs(subnet)
	Expect(err).NotTo(HaveOccurred())
	var ipConf types020.IPConfig
	if ipVersion(expAddress) == "4" {
		ipConf = *result.IP4
	} else {
		ipConf = *result.IP6
	}
	Expect(ipConf.IP.IP).To(Equal(expAddress))
	Expect(ipConf.Gateway).To(Equal(expGateway))

	netDir := "mynet" + ipVersion(expAddress)
	test.ipFilePath = filepath.Join(tmpDir, netDir, expAddress.String())
	contents, err := ioutil.ReadFile(test.ipFilePath)
	Expect(err).NotTo(HaveOccurred())
	Expect(string(contents)).To(Equal("dummy"))

	lastFilePath := filepath.Join(tmpDir, netDir, "last_reserved_ip")
	contents, err = ioutil.ReadFile(lastFilePath)
	Expect(err).NotTo(HaveOccurred())
	Expect(string(contents)).To(Equal(expAddress.String()))

	// Check DNS server addresses. CNI Versions 0.2.0 or earlier
	// support only a single DNS server address.
	if tc.dnsAddrs != nil {
		Expect(result.DNS).To(Equal(types.DNS{Nameservers: []string{tc.dnsAddrs[0]}}))
	}
}

func (test *cniTestV01or2x) cmdDelTest() {
	// Release the IP(s)
	err := testutils.CmdDelWithResult(nspath, ifname, func() error {
		return cmdDel(test.args)
	})
	Expect(err).NotTo(HaveOccurred())

	_, err = os.Stat(test.ipFilePath)
	Expect(err).To(HaveOccurred())
}

func (test *cniTestV01or2x) getRawResult() []byte {
	return test.rawResult
}

func cniAddDelTest(tc testCase) {
	// Get a CNI Add/Del tester based on test case version
	tester := cniTesterByVersion(tc.cniVersion)

	// Test IP allocation
	tmpDir := createTmpDir()
	defer os.RemoveAll(tmpDir)
	tester.cmdAddTest(tc, tmpDir)

	// Test IP Release
	tester.cmdDelTest()
}

var _ = Describe("host-local Operations", func() {
	It("allocates and releases an address with ADD/DEL", func() {
		testCases := []testCase{
			{
				// IPv4 only
				cniVersion: "0.3.1",
				subnet:     "10.1.2.0/24",
				dnsAddrs:   []string{"192.0.2.3"},
			},
			{
				// IPv4 only with explicit gateway address
				cniVersion: "0.3.1",
				subnet:     "10.3.4.0/24",
				gateway:    "10.3.4.1",
				dnsAddrs:   []string{"192.0.2.3"},
			},
			{
				// IPv4 only using subnets list configuration
				cniVersion: "0.3.1",
				subnets: []subnetInfo{
					{cidr: "10.5.6.0/24", gateway: "10.5.6.1"},
				},
				dnsAddrs: []string{"192.0.2.3"},
			},
			{
				// IPv6 only
				cniVersion: "0.3.1",
				subnet:     "2001:db8::0/64",
				dnsAddrs:   []string{"2001:2::1"},
			},
			{
				// IPv6 only with explicit gateway address
				cniVersion: "0.3.1",
				subnet:     "fd00:1234::0/64",
				gateway:    "fd00:1234::1",
				dnsAddrs:   []string{"2001:2::1"},
			},
			{
				// Dual stack
				cniVersion: "0.3.1",
				subnets: []subnetInfo{
					{cidr: "192.168.0.0/24"},
					{cidr: "fd00::0/64"},
				},
				dnsAddrs: []string{"192.0.2.3", "2001:2::1"},
			},
			{
				// Dual stack with explicit gateway addresses
				cniVersion: "0.3.1",
				subnets: []subnetInfo{
					{cidr: "192.168.1.0/24", gateway: "192.168.1.254"},
					{cidr: "fd00:5678::0/64", gateway: "fd00:5678::f00d"},
				},
				dnsAddrs: []string{"192.0.2.3", "2001:2::1"},
			},
		}

		for _, tc := range testCases {
			// Test IP Allocation and Release
			cniAddDelTest(tc)
		}
	})

	It("allocates and releases an address(es) within range(s)", func() {
		testCases := []testCase{
			{
				// IPv4 only
				cniVersion: "0.3.1",
				subnets: []subnetInfo{
					{
						cidr:       "10.5.6.0/24",
						rangeStart: "10.5.6.20",
						rangeEnd:   "10.5.6.200",
						gateway:    "10.5.6.1",
					},
				},
			},
			{
				// Dual stack
				cniVersion: "0.3.1",
				subnets: []subnetInfo{
					{
						cidr:       "192.168.0.0/24",
						rangeStart: "192.168.0.100",
						rangeEnd:   "192.168.0.200",
						gateway:    "192.168.0.10",
					},
					{
						cidr:       "fd00::0/64",
						rangeStart: "fd00::20",
						rangeEnd:   "fd00::200",
						gateway:    "fd00::1",
					},
				},
			},
		}

		for _, tc := range testCases {
			// Test IP Allocation and Release
			cniAddDelTest(tc)
		}
	})

	It("allocates requested IP(s)", func() {
		testCases := []testCase{
			{
				// IP requested via CNI_ARGS environment
				cniVersion: "0.3.1",
				subnet:     "10.7.8.0/24",
				envReqIP:   "10.7.8.10",
			},
			{
				// Single IP requested via net config
				cniVersion:   "0.3.1",
				subnet:       "10.9.10.0/24",
				requestedIPs: []string{"10.9.10.100"},
			},
			{
				// Multiple IPs requested via net config
				cniVersion: "0.3.1",
				requestedIPs: []string{
					"192.168.0.150",
					"fd00::250",
				},
				subnets: []subnetInfo{
					{cidr: "192.168.0.0/24"},
					{cidr: "fd00::0/64"},
				},
			},
		}

		for _, tc := range testCases {
			// Test IP Allocation and Release
			cniAddDelTest(tc)
		}
	})

	It("doesn't error when passed an unknown ID on DEL", func() {
		tc := testCase{
			cniVersion: "0.3.0",
			subnet:     "10.1.2.0/24",
		}

		test := cniTestV03x{}
		tmpDir := createTmpDir()
		defer os.RemoveAll(tmpDir)
		var err error
		test.args, err = tc.createCmdArgs(tmpDir)
		Expect(err).NotTo(HaveOccurred())

		// Since test.cmdAddTest has not been run, the "dummy" ContainerID
		// in test.args should be an unknown container ID.
		test.cmdDelTest()
	})

	It("allocates and releases an address with ADD/DEL and 0.1.0 config", func() {
		testCases := []testCase{
			{
				// IPv4 only
				cniVersion: "0.1.0",
				subnet:     "10.1.2.0/24",
				dnsAddrs:   []string{"192.0.2.3"},
			},
			{
				// IPv6 only
				cniVersion: "0.1.0",
				subnet:     "2001:db8::0/64",
				dnsAddrs:   []string{"2001:2::1"},
			},
			// Dual stack is not supported for CNI versions 0.2.0 or earlier
			// since those versions do not support multiple IP addresses.
		}

		for _, tc := range testCases {
			// Test IP Allocation and Release
			cniAddDelTest(tc)
		}
	})

	It("ignores whitespace in disk files", func() {
		tc := testCase{
			cniVersion: "0.3.1",
			subnet:     "10.1.2.0/24",
			fault:      whiteSpaceInDiskFile,
		}
		// Test IP Allocation and Release
		cniAddDelTest(tc)
	})

	It("does not output an error message upon initial subnet creation", func() {
		tc := testCase{
			cniVersion: "0.2.0",
			subnet:     "10.1.2.0/24",
		}

		tester := cniTesterByVersion(tc.cniVersion)
		tmpDir := createTmpDir()
		defer os.RemoveAll(tmpDir)
		tester.cmdAddTest(tc, tmpDir)

		raw := tester.getRawResult()
		Expect(strings.Index(string(raw), "Error retrieving last reserved ip")).To(Equal(-1))
	})

	It("generates error for multiple subnets with version < 0.3.0", func() {
		testCases := []testCase{
			{
				cniVersion: "0.1.0",
				subnets: []subnetInfo{
					{cidr: "192.168.0.0/24"},
					{cidr: "fd00::0/64"},
				},
				expError: "does not support multiple subnets",
			},
			{
				cniVersion: "0.2.0",
				subnets: []subnetInfo{
					{cidr: "192.168.1.0/24"},
					{cidr: "fd00:5678::0/64"},
				},
				expError: "does not support multiple subnets",
			},
		}

		for _, tc := range testCases {
			tester := cniTesterByVersion(tc.cniVersion)
			tmpDir := createTmpDir()
			defer os.RemoveAll(tmpDir)
			tester.cmdAddTest(tc, tmpDir)
		}
	})
})
