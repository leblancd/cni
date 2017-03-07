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

package hwaddr_test

import (
	"net"

	"github.com/containernetworking/cni/pkg/utils/hwaddr"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("Hwaddr", func() {
	Context("Generate Hardware Address", func() {
		It("generate hardware address based on ipv4 address", func() {
			testCases := []struct {
				ip          net.IP
				prefix      []byte
				expectedMAC net.HardwareAddr
			}{
				{
					ip:          net.ParseIP("10.0.0.2"),
					prefix:      hwaddr.PrivateMACPrefix,
					expectedMAC: (net.HardwareAddr)(append(hwaddr.PrivateMACPrefix, 0x0a, 0x00, 0x00, 0x02)),
				},
				{
					ip:          net.ParseIP("10.250.0.244"),
					prefix:      hwaddr.PrivateMACPrefix,
					expectedMAC: (net.HardwareAddr)(append(hwaddr.PrivateMACPrefix, 0x0a, 0xfa, 0x00, 0xf4)),
				},
				{
					ip:          net.ParseIP("172.17.0.2"),
					prefix:      hwaddr.PrivateMACPrefix,
					expectedMAC: (net.HardwareAddr)(append(hwaddr.PrivateMACPrefix, 0xac, 0x11, 0x00, 0x02)),
				},
				//{
				//	ip:          net.IPv4(byte(172), byte(17), byte(0), byte(2)),
				//	prefix:      hwaddr.PrivateMACPrefix,
				//	expectedMAC: (net.HardwareAddr)(append(hwaddr.PrivateMACPrefix, 0xac, 0x11, 0x00, 0x02)),
				//},
				{
					ip:          net.ParseIP("fed0::1234:5678"),
					prefix:      hwaddr.PrivateMACPrefix6,
					expectedMAC: (net.HardwareAddr)(append(hwaddr.PrivateMACPrefix6, 0x12, 0x34, 0x56, 0x78)),
				},
				{
					ip:          net.ParseIP("2001:2::600d:f00d"),
					prefix:      hwaddr.PrivateMACPrefix6,
					expectedMAC: (net.HardwareAddr)(append(hwaddr.PrivateMACPrefix6, 0x60, 0x0d, 0xf0, 0x0d)),
				},
			}

			for _, tc := range testCases {
				mac, err := hwaddr.GenerateHardwareAddr(tc.ip, tc.prefix)
				Expect(err).NotTo(HaveOccurred())
				Expect(mac).To(Equal(tc.expectedMAC))
			}
		})

		It("return error if IP address is nil", func() {
			_, err := hwaddr.GenerateHardwareAddr(nil, hwaddr.PrivateMACPrefix)
			Expect(err).To(BeAssignableToTypeOf(hwaddr.InvalidIPLengthErr{}))
		})

		It("return error if IP address has invalid length", func() {
			ip4 := net.ParseIP("10.0.0.2")
			ip6 := net.ParseIP("2001:db8:0:1:1:1:1:1")
			testCases := []struct {
				ip     net.IP
				prefix []byte
			}{
				{
					ip:     ip4[:1],
					prefix: hwaddr.PrivateMACPrefix,
				},
				{
					ip:     ip6[:1],
					prefix: hwaddr.PrivateMACPrefix6,
				},
			}
			for _, tc := range testCases {
				_, err := hwaddr.GenerateHardwareAddr(tc.ip, tc.prefix)
				Expect(err).To(BeAssignableToTypeOf(hwaddr.InvalidIPLengthErr{}))
			}
		})

		It("return error if prefix is invalid", func() {
			_, err := hwaddr.GenerateHardwareAddr(net.ParseIP("10.0.0.2"), []byte{0x58})
			Expect(err).To(BeAssignableToTypeOf(hwaddr.InvalidPrefixLengthErr{}))
		})
	})
})
