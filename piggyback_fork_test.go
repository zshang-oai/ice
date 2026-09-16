// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package ice

import (
	"bytes"
	"hash/crc32"
	"net"
	"testing"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/stretchr/testify/require"
)

func completeForkSPEDHandshake(agent *Agent) {
	agent.SetDtlsHandshakeComplete(false, protocol.Version1_2)
	agent.ReportPiggybacking(nil, nil, nil)
}

func TestSpedCallbackLifecycle(t *testing.T) {
	t.Run("clearing and replacing callback resets old handshake", func(t *testing.T) {
		agent := newPiggybackAgent(t)
		flight := [][]byte{fakeDtlsPacket("first"), fakeDtlsPacket("second")}
		require.True(t, agent.Piggyback(flight, nil))
		agent.GetPiggybackDataAndAcks()
		agent.ReportDtlsPacket(fakeDtlsPacket("old inbound"))

		agent.SetDtlsCallback(nil)
		require.Equal(t, PiggybackingStateOff, agent.piggyback.state)
		require.Nil(t, agent.piggyback.dtlsCallback)
		require.Empty(t, agent.piggyback.packets)
		require.Zero(t, agent.piggyback.packetsIndex)
		require.NotNil(t, agent.piggyback.acks)
		require.Empty(t, agent.piggyback.acks)

		received := 0
		agent.SetDtlsCallback(func([]byte, net.Addr) { received++ })
		require.Equal(t, PiggybackingStateTentative, agent.piggyback.state)
		require.True(t, agent.Piggyback(flight, nil))
		agent.GetPiggybackDataAndAcks()
		agent.ReportDtlsPacket(fakeDtlsPacket("another old inbound"))
		agent.SetDtlsCallback(func([]byte, net.Addr) { received += 10 })
		require.Empty(t, agent.piggyback.packets)
		require.Zero(t, agent.piggyback.packetsIndex)
		require.NotNil(t, agent.piggyback.acks)
		require.Empty(t, agent.piggyback.acks)
		agent.ReportPiggybacking(fakeDtlsPacket("new inbound"), nil, nil)
		require.Equal(t, 10, received)
	})

	t.Run("clearing pending callback preserves final ACKs", func(t *testing.T) {
		agent := newPiggybackAgent(t)
		inbound := fakeDtlsPacket("peer final flight")
		agent.ReportDtlsPacket(inbound)
		require.True(t, agent.Piggyback([][]byte{fakeDtlsPacket("outbound")}, nil))
		agent.SetDtlsHandshakeComplete(true, protocol.Version1_2)
		agent.SetDtlsCallback(nil)

		require.Equal(t, PiggybackingStatePending, agent.piggyback.state)
		require.Nil(t, agent.piggyback.dtlsCallback)
		data, acks := agent.GetPiggybackDataAndAcks()
		require.Nil(t, data)
		require.Equal(t, []uint32{crc32.ChecksumIEEE(inbound)}, acks)
		agent.ReportPiggybacking(nil, nil, nil)
		require.Equal(t, PiggybackingStateComplete, agent.piggyback.state)
	})

	t.Run("rearming complete controller advertises SPED again", func(t *testing.T) {
		agent := newPiggybackAgent(t)
		completeForkSPEDHandshake(agent)
		require.Nil(t, agent.piggyback.acks)
		agent.SetDtlsCallback(func([]byte, net.Addr) {})
		data, acks := agent.GetPiggybackDataAndAcks()
		require.Nil(t, data)
		require.NotNil(t, acks)
		require.Empty(t, acks)
		require.True(t, agent.isPiggybackingActive())
	})
}

func TestSpedPeerDoneDiscardsPreviousFlight(t *testing.T) {
	agent := newPiggybackAgent(t)
	require.True(t, agent.Piggyback([][]byte{fakeDtlsPacket("old one"), fakeDtlsPacket("old two")}, nil))
	agent.GetPiggybackDataAndAcks()
	completeForkSPEDHandshake(agent)
	require.Equal(t, PiggybackingStateComplete, agent.piggyback.state)
	require.Empty(t, agent.piggyback.packets)
	require.Zero(t, agent.piggyback.packetsIndex)
	require.Empty(t, agent.piggyback.flushOnConnected(), "peer-done flight must not be replayed as plain DTLS")
}

func TestSpedTerminalStateBuffersWholeFlightUntilConnected(t *testing.T) {
	for _, state := range []piggybackingState{PiggybackingStateOff, PiggybackingStateComplete} {
		t.Run(map[piggybackingState]string{PiggybackingStateOff: "off", PiggybackingStateComplete: "complete"}[state], func(t *testing.T) {
			agent := newPiggybackAgent(t)
			if state == PiggybackingStateOff {
				agent.ReportPiggybacking(nil, nil, nil)
			} else {
				completeForkSPEDHandshake(agent)
			}
			flight := [][]byte{fakeDtlsPacket("one"), fakeDtlsPacket("two")}
			want := [][]byte{bytes.Clone(flight[0]), bytes.Clone(flight[1])}
			require.True(t, agent.Piggyback(flight, nil))
			flight[0][len(flight[0])-1]++
			flight[1][len(flight[1])-1]++
			data, acks := agent.GetPiggybackDataAndAcks()
			require.Nil(t, data)
			require.Nil(t, acks)

			flushed := agent.piggyback.flushOnConnected()
			require.Len(t, flushed, 2)
			for i, packet := range flushed {
				require.Equal(t, want[i], packet.data)
				require.Equal(t, crc32.ChecksumIEEE(want[i]), packet.crc)
			}
			require.Empty(t, agent.piggyback.flushOnConnected())
			require.False(t, agent.Piggyback([][]byte{fakeDtlsPacket("plain")}, nil))
			require.Empty(t, agent.piggyback.packets, "connected terminal state must leave sending to the caller")
		})
	}
}

func TestSpedWholeFlightOwnershipAndReplacement(t *testing.T) {
	agent := newPiggybackAgent(t)
	flight := [][]byte{fakeDtlsPacket("one"), fakeDtlsPacket("two")}
	wantFirst, wantSecond := bytes.Clone(flight[0]), bytes.Clone(flight[1])
	require.True(t, agent.Piggyback(flight, nil))
	flight[0][len(flight[0])-1]++
	flight[1][len(flight[1])-1]++
	flight[0] = nil
	data, _ := agent.GetPiggybackDataAndAcks()
	require.Equal(t, wantFirst, data)
	data[len(data)-1]++
	data, _ = agent.GetPiggybackDataAndAcks()
	require.Equal(t, wantSecond, data)
	data, _ = agent.GetPiggybackDataAndAcks()
	require.Equal(t, wantFirst, data)

	inbound := fakeDtlsPacket("inbound")
	agent.ReportDtlsPacket(inbound)
	_, acks := agent.GetPiggybackDataAndAcks()
	acks[0]++
	_, acks = agent.GetPiggybackDataAndAcks()
	require.Equal(t, []uint32{crc32.ChecksumIEEE(inbound)}, acks)

	// The cursor is currently at 1. Replacing a multi-record flight with a
	// single record must reset it, and must not retain either previous record.
	next := fakeDtlsPacket("next flight")
	require.True(t, agent.Piggyback([][]byte{next}, nil))
	for range 2 {
		data, _ = agent.GetPiggybackDataAndAcks()
		require.Equal(t, next, data)
	}
}

func TestSpedWholeFlightValidationIsAtomic(t *testing.T) {
	for _, invalidIndex := range []int{0, 1, 2} {
		t.Run(string(rune('0'+invalidIndex)), func(t *testing.T) {
			agent := newPiggybackAgent(t)
			previous := [][]byte{fakeDtlsPacket("old first"), fakeDtlsPacket("old second")}
			require.True(t, agent.Piggyback(previous, nil))
			agent.GetPiggybackDataAndAcks()
			invalid := [][]byte{fakeDtlsPacket("new first"), fakeDtlsPacket("new second"), fakeDtlsPacket("new third")}
			invalid[invalidIndex] = []byte("invalid")
			require.False(t, agent.Piggyback(invalid, nil))
			data, _ := agent.GetPiggybackDataAndAcks()
			require.Equal(t, previous[1], data, "a rejected flight must not reset the cursor or replace any packet")
			data, _ = agent.GetPiggybackDataAndAcks()
			require.Equal(t, previous[0], data)
		})
	}
}

func TestSpedEmptyBatchDoesNotSignalCompletion(t *testing.T) {
	agent := newPiggybackAgent(t)
	flight := fakeDtlsPacket("active flight")
	require.True(t, agent.Piggyback([][]byte{flight}, nil))
	for _, empty := range [][][]byte{nil, {}} {
		require.True(t, agent.Piggyback(empty, nil))
		require.Equal(t, PiggybackingStateTentative, agent.piggyback.state)
		data, _ := agent.GetPiggybackDataAndAcks()
		require.Equal(t, flight, data)
	}
}

func TestSpedOutOfOrderACKRetainsCursor(t *testing.T) {
	agent := newPiggybackAgent(t)
	flight := [][]byte{fakeDtlsPacket("first"), fakeDtlsPacket("second"), fakeDtlsPacket("third")}
	require.True(t, agent.Piggyback(flight, nil))
	data, _ := agent.GetPiggybackDataAndAcks()
	require.Equal(t, flight[0], data)
	// An ACK for a later packet must not rewind the next outgoing slot to the
	// packet just sent. This retains the published fork's cursor policy.
	agent.ReportPiggybacking([]byte{}, []uint32{crc32.ChecksumIEEE(flight[2])}, nil)
	data, _ = agent.GetPiggybackDataAndAcks()
	require.Equal(t, flight[1], data)
	data, _ = agent.GetPiggybackDataAndAcks()
	require.Equal(t, flight[0], data)
	agent.ReportPiggybacking([]byte{}, []uint32{crc32.ChecksumIEEE(flight[0])}, nil)
	data, _ = agent.GetPiggybackDataAndAcks()
	require.Equal(t, flight[1], data)
	agent.ReportPiggybacking([]byte{}, []uint32{crc32.ChecksumIEEE(flight[1])}, nil)
	data, _ = agent.GetPiggybackDataAndAcks()
	require.Empty(t, data)
	require.Zero(t, agent.piggyback.packetsIndex)
}

func TestSpedDuplicateInboundHasOneACK(t *testing.T) {
	agent := newPiggybackAgent(t)
	inbound := fakeDtlsPacket("duplicate")
	count := 0
	agent.SetDtlsCallback(func([]byte, net.Addr) { count++ })
	agent.ReportPiggybacking(inbound, nil, nil)
	agent.ReportPiggybacking(inbound, nil, nil)
	_, acks := agent.GetPiggybackDataAndAcks()
	require.Equal(t, []uint32{crc32.ChecksumIEEE(inbound)}, acks)
	require.Equal(t, 2, count, "DTLS still receives retransmissions")
}

func TestSpedCallbackDetachPreservesCompletionFlightDecision(t *testing.T) {
	for _, tc := range []struct {
		name     string
		client   bool
		version  protocol.Version
		retained bool
	}{
		{name: "DTLS 1.2 client", client: true, version: protocol.Version1_2},
		{name: "DTLS 1.2 server", version: protocol.Version1_2, retained: true},
		{name: "DTLS 1.3 client", client: true, version: protocol.Version1_3, retained: true},
		{name: "DTLS 1.3 server", version: protocol.Version1_3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agent := newPiggybackAgent(t)
			flight := [][]byte{fakeDtlsPacket("final first"), fakeDtlsPacket("final second")}
			require.True(t, agent.Piggyback(flight, nil))
			agent.GetPiggybackDataAndAcks()
			inbound := fakeDtlsPacket("peer flight")
			agent.ReportDtlsPacket(inbound)
			agent.SetDtlsHandshakeComplete(tc.client, tc.version)
			agent.SetDtlsCallback(nil)
			require.Nil(t, agent.piggyback.dtlsCallback)
			require.Equal(t, PiggybackingStatePending, agent.piggyback.state)
			data, acks := agent.GetPiggybackDataAndAcks()
			require.Equal(t, []uint32{crc32.ChecksumIEEE(inbound)}, acks)
			if tc.retained {
				require.Equal(t, flight[1], data, "detaching receive callback must preserve the retained flight and cursor")
				agent.ReportPiggybacking(nil, []uint32{
					crc32.ChecksumIEEE(flight[0]), crc32.ChecksumIEEE(flight[1]),
				}, nil)
			} else {
				require.Nil(t, data)
				agent.ReportPiggybacking(nil, nil, nil)
			}
			require.Equal(t, PiggybackingStateComplete, agent.piggyback.state)
			require.Empty(t, agent.piggyback.packets)
		})
	}
}
