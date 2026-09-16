// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package ice

import (
	"context"
	"net"
	"testing"

	"github.com/stretchr/testify/require"
)

func newSpedRouteTestAgent(t *testing.T) *Agent {
	t.Helper()

	agent, err := NewAgent(&AgentConfig{
		NetworkTypes:     []NetworkType{NetworkTypeUDP4},
		MulticastDNSMode: MulticastDNSModeDisabled,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, agent.Close()) })

	return agent
}

func installSpedTestRoute(t *testing.T, agent *Agent) *mockPacketConnWithCapture {
	t.Helper()

	local, err := NewCandidateHost(&CandidateHostConfig{
		Network: "udp", Address: "127.0.0.1", Port: 12345, Component: 1,
	})
	require.NoError(t, err)
	remote, err := NewCandidateHost(&CandidateHostConfig{
		Network: "udp", Address: "127.0.0.1", Port: 54321, Component: 1,
	})
	require.NoError(t, err)
	capture := &mockPacketConnWithCapture{}
	local.conn = capture
	require.NoError(t, agent.loop.Run(agent.loop, func(context.Context) {
		agent.setSelectedPair(agent.addPair(local, remote))
	}))

	return capture
}

func TestSpedRouteDiscardResumesWholeFlightBuffering(t *testing.T) {
	for _, state := range []string{"off", "complete"} {
		for _, transition := range []string{"restart", "failed"} {
			t.Run(state+"/"+transition, func(t *testing.T) {
				agent := newSpedRouteTestAgent(t)
				if state == "complete" {
					agent.SetDtlsCallback(func([]byte, net.Addr) {})
					completeForkSPEDHandshake(agent)
				}
				installSpedTestRoute(t, agent)
				flight := [][]byte{fakeDtlsPacket("new first"), fakeDtlsPacket("new second")}
				require.False(t, agent.Piggyback(flight, nil))
				require.Empty(t, agent.piggyback.packets)

				if transition == "restart" {
					require.NoError(t, agent.Restart("", ""))
				} else {
					require.NoError(t, agent.loop.Run(agent.loop, func(context.Context) {
						agent.updateConnectionState(ConnectionStateFailed)
					}))
				}
				require.Nil(t, agent.getSelectedPair())
				conn := &Conn{agent: agent}
				n, err := conn.Write(flight[0])
				require.Zero(t, n)
				require.ErrorIs(t, err, ErrNoCandidatePairs)
				require.True(t, agent.Piggyback(flight, nil), "a discarded route cannot carry plain DTLS")
				capture := installSpedTestRoute(t, agent)
				require.Equal(t, flight, capture.sentPackets, "the next route must flush every buffered datagram")
				require.Empty(t, agent.piggyback.packets)
				require.False(t, agent.Piggyback(flight, nil))
			})
		}
	}
}

func TestSpedRetainedRouteKeepsPlainWriteAvailable(t *testing.T) {
	for _, transition := range []string{"disconnected", "rejected restart", "callback rearm", "dtls failed"} {
		t.Run(transition, func(t *testing.T) {
			agent := newSpedRouteTestAgent(t)
			capture := installSpedTestRoute(t, agent)
			switch transition {
			case "disconnected":
				require.NoError(t, agent.loop.Run(agent.loop, func(context.Context) {
					agent.updateConnectionState(ConnectionStateDisconnected)
				}))
			case "rejected restart":
				require.ErrorIs(t, agent.Restart("x", "y"), ErrLocalUfragInsufficientBits)
			case "callback rearm":
				agent.SetDtlsCallback(func([]byte, net.Addr) {})
			case "dtls failed":
				agent.SetDtlsFailed()
			}

			packet := fakeDtlsPacket("still writable")
			require.False(t, agent.Piggyback([][]byte{packet}, nil))
			conn := &Conn{agent: agent}
			n, err := conn.Write(packet)
			require.NoError(t, err)
			require.Equal(t, len(packet), n)
			require.Equal(t, [][]byte{packet}, capture.sentPackets)
		})
	}
}
