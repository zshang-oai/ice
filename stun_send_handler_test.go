// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package ice

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	"github.com/pion/logging"
	"github.com/pion/stun/v4"
	"github.com/stretchr/testify/require"
)

type capturePingNoIOCand struct {
	pingNoIOCand
	lastWrite []byte
}

func (c *capturePingNoIOCand) writeTo(packet []byte, _ Candidate) (int, error) {
	c.lastWrite = append(c.lastWrite[:0], packet...)

	return len(packet), nil
}

func TestSTUNSendHandlerBindingSuccess(t *testing.T) {
	for _, mode := range []string{"default", "rewrite", "error"} {
		t.Run(mode, func(t *testing.T) {
			a := bareAgentForPing()
			a.localPwd = selectionTestPassword
			a.log = logging.NewDefaultLoggerFactory().NewLogger("test")
			a.piggyback.init()
			a.SetDtlsCallback(func([]byte, net.Addr) {})
			outgoing := fakeDtlsPacket("server flight")
			require.True(t, a.Piggyback([][]byte{outgoing}, nil))
			a.ReportDtlsPacket(fakeDtlsPacket("client flight"))
			local := &capturePingNoIOCand{pingNoIOCand: *newPingNoIOCand()}
			local.networkType = NetworkTypeUDP4
			local.setResolvedAddr(&net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 10000})
			remote := newPingNoIOCand()
			remote.networkType = NetworkTypeUDP4
			remote.setResolvedAddr(&net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 20000})
			pair := a.addPair(local, remote)
			request, err := stun.Build(stun.BindingRequest, stun.TransactionID)
			require.NoError(t, err)
			want := remote.addrPort()
			calls := 0
			if mode != "default" {
				want = netip.MustParseAddrPort("203.0.113.10:45678")
				a.stunSendHandler = func(outbound, inbound *stun.Message, gotLocal, gotRemote Candidate) error {
					calls++
					require.Same(t, request, inbound)
					require.Same(t, local, gotLocal)
					require.Same(t, remote, gotRemote)
					if mode == "error" {
						return errors.New("decline response")
					}

					return outbound.Build(inbound, stun.BindingSuccess, &stun.XORMappedAddress{
						IP: want.Addr().AsSlice(), Port: int(want.Port()),
					})
				}
			}
			a.sendBindingSuccess(request, local, remote)
			if mode == "error" {
				require.Equal(t, 1, calls)
				require.Empty(t, local.lastWrite)
				require.Zero(t, pair.ResponsesSent())

				return
			}
			response := &stun.Message{Raw: append([]byte(nil), local.lastWrite...)}
			require.NoError(t, response.Decode())
			require.Equal(t, request.TransactionID, response.TransactionID)
			require.Equal(t, stun.BindingSuccess, response.Type)
			require.NoError(t, stun.MessageIntegrity([]byte(a.localPwd)).Check(response))
			require.NoError(t, stun.Fingerprint.Check(response))
			var mapped stun.XORMappedAddress
			require.NoError(t, mapped.GetFrom(response))
			require.True(t, mapped.IP.Equal(want.Addr().AsSlice()))
			require.Equal(t, int(want.Port()), mapped.Port)
			var data DtlsInStunAttribute
			require.NoError(t, data.GetFrom(response))
			require.Equal(t, outgoing, []byte(data))
			var acks DtlsInStunAckAttribute
			require.NoError(t, acks.GetFrom(response))
			require.Len(t, acks, 1, "response rewriting must preserve SPED acknowledgments")
			require.Equal(t, uint64(1), pair.ResponsesSent())
			if mode == "rewrite" {
				require.Equal(t, 1, calls)
			}
		})
	}
}

func TestWithSTUNSendHandler(t *testing.T) {
	a, err := NewAgentWithOptions(WithSTUNSendHandler(func(_, _ *stun.Message, _, _ Candidate) error { return nil }))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, a.Close()) })
	require.NotNil(t, a.stunSendHandler)
	require.ErrorIs(t, WithSTUNSendHandler(nil)(a), ErrAgentOptionNotUpdatable)
	b, err := NewAgentWithOptions()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, b.Close()) })
	require.Nil(t, b.stunSendHandler)
}
