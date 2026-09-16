// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package ice

import (
	"bytes"
	"context"
	"hash/crc32"
	"net"
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/stun/v4"
	"github.com/stretchr/testify/require"
)

func TestSpedACKOnlyCompletionRequiresAcknowledgedFlight(t *testing.T) {
	for _, role := range []struct {
		name    string
		client  bool
		version protocol.Version
	}{
		{name: "DTLS 1.2 server", version: protocol.Version1_2},
		{name: "DTLS 1.3 client", client: true, version: protocol.Version1_3},
	} {
		for _, detach := range []bool{false, true} {
			name := role.name + "/callback attached"
			if detach {
				name = role.name + "/callback detached"
			}
			t.Run(name, func(t *testing.T) {
				agent := newPiggybackAgent(t)
				flight := [][]byte{fakeDtlsPacket("first final record"), fakeDtlsPacket("second final record")}
				firstCRC, secondCRC := crc32.ChecksumIEEE(flight[0]), crc32.ChecksumIEEE(flight[1])
				staleCRC := crc32.ChecksumIEEE(fakeDtlsPacket("previous flight"))
				require.NotEqual(t, firstCRC, staleCRC)
				require.NotEqual(t, secondCRC, staleCRC)
				require.True(t, agent.Piggyback(flight, nil))
				agent.SetDtlsHandshakeComplete(role.client, role.version)
				if detach {
					agent.SetDtlsCallback(nil)
				}

				for _, step := range []struct {
					name      string
					acks      []uint32
					remaining [][]byte
				}{
					{name: "empty ACK attribute", acks: []uint32{}, remaining: flight},
					{name: "unrelated ACK", acks: []uint32{staleCRC}, remaining: flight},
					{name: "partial ACK", acks: []uint32{firstCRC}, remaining: flight[1:]},
					{name: "duplicate ACK", acks: []uint32{firstCRC, firstCRC}, remaining: flight[1:]},
				} {
					agent.ReportPiggybacking(nil, step.acks, nil)
					require.Equal(t, PiggybackingStatePending, agent.piggyback.state, step.name)
					require.Len(t, agent.piggyback.packets, len(step.remaining), step.name)
					for _, want := range step.remaining {
						data, acks := agent.GetPiggybackDataAndAcks()
						require.Equal(t, want, data, step.name)
						require.NotNil(t, acks, step.name)
					}
				}
				agent.ReportPiggybacking(nil, []uint32{secondCRC}, nil)
				require.Equal(t, PiggybackingStateComplete, agent.piggyback.state)
				require.Empty(t, agent.piggyback.packets)
				require.Zero(t, agent.piggyback.packetsIndex)
				data, acks := agent.GetPiggybackDataAndAcks()
				require.Nil(t, data)
				require.Nil(t, acks)
			})
		}
	}
}

// The DTLS payloads are synthetic, but requests enter through real STUN decoding,
// authentication and the ICE-lite selector. A libwebrtc full client can send an
// ACK attribute without DATA while it still awaits the server's final flight.
func TestSpedLiteDelayedACKRetransmitsFinalFlight(t *testing.T) {
	agent, err := NewAgentWithOptions(WithICELite(true),
		WithCandidateTypes([]CandidateType{CandidateTypeHost}),
		WithNetworkTypes([]NetworkType{NetworkTypeUDP4}),
		WithMulticastDNSMode(MulticastDNSModeDisabled))
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, agent.Close()) })
	require.NoError(t, agent.SetRemoteCredentials("fullclient", "full-client-password-at-least-22"))
	require.False(t, agent.remoteLite)
	local, err := NewCandidateHost(&CandidateHostConfig{
		Network: "udp", Address: "192.0.2.1", Port: 10000, Component: ComponentRTP,
	})
	require.NoError(t, err)
	remote, err := NewCandidateHost(&CandidateHostConfig{
		Network: "udp", Address: "192.0.2.2", Port: 20000, Component: ComponentRTP,
	})
	require.NoError(t, err)
	capture := &mockPacketConnWithCapture{}
	local.currAgent, local.conn = agent, capture
	require.NoError(t, agent.loop.Run(agent.loop, func(context.Context) {
		agent.localCandidates[NetworkTypeUDP4] = []Candidate{local}
		agent.remoteCandidates[NetworkTypeUDP4] = []Candidate{remote}
	}))
	request := func(data []byte, acks []uint32) *stun.Message {
		attrs := []stun.Setter{stun.BindingRequest, stun.TransactionID,
			stun.NewUsername(agent.localUfrag + ":" + agent.remoteUfrag),
			AttrControlling(1), PriorityAttr(12345), DtlsInStunAckAttribute(acks)}
		if data != nil {
			attrs = append(attrs, DtlsInStunAttribute(data))
		}
		attrs = append(attrs, stun.NewShortTermIntegrity(agent.localPwd), stun.Fingerprint)
		message, err := stun.Build(attrs...)
		require.NoError(t, err)

		return message
	}
	receive := func(message *stun.Message) *stun.Message {
		before := len(capture.sentPackets)
		local.handleInboundPacket(message.Raw, remote.addrPort())
		require.Len(t, capture.sentPackets, before+1)
		response := &stun.Message{Raw: bytes.Clone(capture.sentPackets[before])}
		require.NoError(t, response.Decode())
		require.Equal(t, stun.BindingSuccess, response.Type)
		require.Equal(t, message.TransactionID, response.TransactionID)
		require.NoError(t, stun.MessageIntegrity([]byte(agent.localPwd)).Check(response))
		require.NoError(t, stun.Fingerprint.Check(response))

		return response
	}
	dataFrom := func(message *stun.Message) []byte {
		var data DtlsInStunAttribute
		require.NoError(t, data.GetFrom(message))

		return data
	}
	hello, finished := fakeDtlsPacket("client hello"), fakeDtlsPacket("client finished")
	early := [][]byte{fakeDtlsPacket("server early one"), fakeDtlsPacket("server early two")}
	final := fakeDtlsPacket("server finished")
	agent.SetDtlsCallback(func(data []byte, _ net.Addr) {
		switch {
		case bytes.Equal(data, hello):
			require.True(t, agent.Piggyback(early, nil))
		case bytes.Equal(data, finished):
			require.True(t, agent.Piggyback([][]byte{final}, nil))
			agent.SetDtlsHandshakeComplete(false, protocol.Version1_2)
			agent.SetDtlsCallback(nil)
		}
	})
	require.Equal(t, early[0], dataFrom(receive(request(hello, []uint32{}))))
	earlyACK := []uint32{crc32.ChecksumIEEE(early[0])}
	delayed := request(nil, earlyACK)
	require.False(t, delayed.Contains(stun.AttrDtlsInStun))
	require.Equal(t, early[1], dataFrom(receive(request(nil, earlyACK))))
	// Lose the first response carrying the final flight; the full client cannot
	// finish DTLS or acknowledge this flight until a subsequent check gets it.
	require.Equal(t, final, dataFrom(receive(request(finished,
		[]uint32{crc32.ChecksumIEEE(early[0]), crc32.ChecksumIEEE(early[1])}))))
	require.Nil(t, agent.getSelectedPair(), "no nominated route for plain DTLS fallback")
	require.Nil(t, agent.piggyback.dtlsCallback)
	require.Equal(t, final, dataFrom(receive(delayed)), "old ACK must not suppress retransmission")
	require.Equal(t, PiggybackingStatePending, agent.piggyback.state)
	response := receive(request(nil, []uint32{crc32.ChecksumIEEE(final)}))
	require.False(t, response.Contains(stun.AttrDtlsInStun))
	require.False(t, response.Contains(stun.AttrDtlsInStunAck))
	require.Equal(t, PiggybackingStateComplete, agent.piggyback.state)
}
