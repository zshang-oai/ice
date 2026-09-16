// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package ice

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/pion/stun/v4"
	"github.com/stretchr/testify/require"
)

func newWritabilityTestAgent(t *testing.T, lite bool) *Agent {
	t.Helper()
	agent, err := NewAgent(&AgentConfig{
		NetworkTypes:     []NetworkType{NetworkTypeUDP4},
		CandidateTypes:   []CandidateType{CandidateTypeHost},
		MulticastDNSMode: MulticastDNSModeDisabled,
		Lite:             lite,
	})
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, agent.Close()) })

	return agent
}

type writabilityCaptureCandidate struct {
	Candidate
	mu     sync.Mutex
	writes [][]byte
}

func (c *writabilityCaptureCandidate) writeTo(packet []byte, _ Candidate) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes = append(c.writes, append([]byte(nil), packet...))

	return len(packet), nil
}

func (c *writabilityCaptureCandidate) capturedWrites() [][]byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	packets := make([][]byte, len(c.writes))
	for i, packet := range c.writes {
		packets[i] = append([]byte(nil), packet...)
	}

	return packets
}

func newWritabilityCandidates(t *testing.T, localPort int) (*writabilityCaptureCandidate, Candidate) {
	t.Helper()
	local, err := NewCandidateHost(&CandidateHostConfig{
		Network: "udp", Address: "192.0.2.1", Port: localPort, Component: ComponentRTP,
	})
	require.NoError(t, err)
	remote, err := NewCandidateHost(&CandidateHostConfig{
		Network: "udp", Address: "192.0.2.2", Port: 20000, Component: ComponentRTP,
	})
	require.NoError(t, err)

	return &writabilityCaptureCandidate{Candidate: local}, remote
}

// A real authenticated SPED request must publish readiness before delivering
// its DTLS payload. The callback runs on the ICE loop, so CanWrite must not
// submit another blocking task to that same loop.
func TestConnCanWriteFromAuthenticatedDTLSCallback(t *testing.T) {
	agent := newWritabilityTestAgent(t, true)
	local, remote := newWritabilityCandidates(t, 10000)
	conn := &Conn{agent: agent}
	require.NoError(t, agent.SetRemoteCredentials("remoteufrag", "remote-password-at-least-22"))
	require.NoError(t, agent.SetRemoteICELite(false))
	require.NoError(t, agent.loop.Run(agent.loop, func(context.Context) {
		agent.localCandidates[local.NetworkType()] = []Candidate{local}
		agent.remoteCandidates[remote.NetworkType()] = []Candidate{remote}
	}))
	type callbackResult struct {
		writable, valid, unselected, queued bool
		requests                            uint64
		packet                              []byte
	}
	results := make(chan callbackResult, 1)
	serverFlight := [][]byte{fakeDtlsPacket("server-flight")}
	agent.SetDtlsCallback(func(packet []byte, _ net.Addr) {
		pair := agent.findPair(local, remote)
		result := callbackResult{
			writable: conn.CanWrite(), unselected: agent.getSelectedPair() == nil,
			queued: agent.Piggyback(serverFlight, nil), packet: append([]byte(nil), packet...),
		}
		if pair != nil {
			result.valid = pair.state == CandidatePairStateSucceeded
			result.requests = pair.RequestsReceived()
		}
		results <- result
	})
	clientFlight := fakeDtlsPacket("client-flight")
	request, err := stun.Build(stun.BindingRequest, stun.TransactionID,
		stun.NewUsername(agent.localUfrag+":"+agent.remoteUfrag), AttrControlling(1),
		DtlsInStunAckAttribute([]uint32{}), DtlsInStunAttribute(clientFlight),
		stun.NewShortTermIntegrity(agent.localPwd), stun.Fingerprint)
	require.NoError(t, err)
	runDone := make(chan error, 1)
	go func() {
		runDone <- agent.loop.Run(agent.loop, func(context.Context) {
			agent.handleInbound(request, local, remote.addrPort())
		})
	}()
	select {
	case result := <-results:
		require.True(t, result.writable)
		require.True(t, result.valid)
		require.True(t, result.unselected)
		require.True(t, result.queued)
		require.Equal(t, uint64(1), result.requests)
		require.Equal(t, clientFlight, result.packet)
	case <-time.After(time.Second):
		// Closing cancels a mistakenly reintroduced nested loop.Run, allowing
		// this regression to fail without leaving the test deadlocked.
		require.NoError(t, agent.Close())
		t.Fatal("CanWrite blocked the DTLS callback on the ICE task loop")
	}
	select {
	case err = <-runDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		require.NoError(t, agent.Close())
		t.Fatal("authenticated Binding request did not finish")
	}

	writes := local.capturedWrites()
	require.Len(t, writes, 1)
	response := &stun.Message{Raw: writes[0]}
	require.NoError(t, response.Decode())
	require.Equal(t, stun.BindingSuccess, response.Type)
	var embedded DtlsInStunAttribute
	require.NoError(t, embedded.GetFrom(response))
	require.Equal(t, serverFlight[0], []byte(embedded))
}

// Upstream role-conflict handling can return an already valid pair to Waiting.
// CanWrite must agree with the route that ordinary Conn.Write will actually use.
func TestConnCanWriteAfterRoleConflictDemotesValidPair(t *testing.T) {
	for _, tc := range []struct {
		name     string
		spare    bool
		selected bool
		canWrite bool
	}{
		{name: "last unselected valid pair"},
		{name: "another valid pair survives", spare: true, canWrite: true},
		{name: "selected pair still follows Write semantics", selected: true, canWrite: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			agent := newWritabilityTestAgent(t, false)
			local, remote := newWritabilityCandidates(t, 10000)
			spareLocal, _ := newWritabilityCandidates(t, 10001)
			conn := &Conn{agent: agent}
			const remotePassword = "remote-password-at-least-22"
			require.NoError(t, agent.SetRemoteCredentials("remoteufrag", remotePassword))

			request, err := stun.Build(stun.BindingRequest, stun.TransactionID,
				stun.NewUsername(agent.remoteUfrag+":"+agent.localUfrag), AttrControlling(1),
				stun.NewShortTermIntegrity(remotePassword), stun.Fingerprint)
			require.NoError(t, err)
			response, err := stun.Build(stun.BindingError,
				stun.NewTransactionIDSetter(request.TransactionID),
				&stun.ErrorCodeAttribute{Code: stun.CodeRoleConflict, Reason: []byte("Role Conflict")},
				stun.NewShortTermIntegrity(remotePassword), stun.Fingerprint)
			require.NoError(t, err)

			var pair *CandidatePair
			require.NoError(t, agent.loop.Run(agent.loop, func(context.Context) {
				agent.setRole(true)
				pair = agent.addPair(local, remote)
				agent.markPairSucceeded(pair)
				if tc.spare {
					agent.markPairSucceeded(agent.addPair(spareLocal, remote))
				}
				if tc.selected {
					agent.setSelectedPair(pair)
				}
				// Record a real outbound check and use its transaction ID in the
				// authenticated response, rather than directly demoting the pair.
				agent.sendBindingRequest(request, local, remote)
			}))
			require.True(t, conn.CanWrite())

			var handled, anotherValid bool
			var state CandidatePairState
			require.NoError(t, agent.loop.Run(agent.loop, func(context.Context) {
				handled = agent.handleInboundErrorResponse(remote, local, remote.addrPort(), response)
				state = pair.state
				anotherValid = agent.getBestValidCandidatePair() != nil
			}))
			require.True(t, handled)
			require.False(t, agent.isControlling.Load())
			require.Equal(t, CandidatePairStateWaiting, state)
			require.Equal(t, tc.spare, anotherValid)
			require.Equal(t, tc.canWrite, conn.CanWrite())

			payload := []byte("application-data-after-role-conflict")
			n, writeErr := conn.Write(payload)
			if !tc.canWrite {
				require.Zero(t, n)
				require.ErrorIs(t, writeErr, ErrNoCandidatePairs)
				require.Len(t, local.capturedWrites(), 1, "only the original STUN check was sent")
				return
			}
			require.NoError(t, writeErr)
			require.Equal(t, len(payload), n)
			if tc.selected {
				require.Same(t, pair, agent.getSelectedPair())
				require.Equal(t, payload, local.capturedWrites()[1])
			} else {
				require.Nil(t, agent.getSelectedPair())
				require.Equal(t, [][]byte{payload}, spareLocal.capturedWrites())
			}
		})
	}
}

func TestConnCanWriteClearsWhenRoutesAreDiscarded(t *testing.T) {
	for _, reason := range []string{"restart", "failed", "closed"} {
		t.Run(reason, func(t *testing.T) {
			agent := newWritabilityTestAgent(t, true)
			local, remote := newWritabilityCandidates(t, 10000)
			conn := &Conn{agent: agent}
			require.NoError(t, agent.loop.Run(agent.loop, func(context.Context) {
				agent.markPairSucceeded(agent.addPair(local, remote))
			}))
			require.True(t, conn.CanWrite())
			switch reason {
			case "restart":
				require.NoError(t, agent.Restart("", ""))
			case "failed":
				require.NoError(t, agent.loop.Run(agent.loop, func(context.Context) {
					agent.updateConnectionState(ConnectionStateFailed)
				}))
			case "closed":
				require.NoError(t, agent.Close())
			}
			require.False(t, conn.CanWrite())
			n, err := conn.Write([]byte("after-route-discard"))
			require.Zero(t, n)
			if reason == "closed" {
				require.ErrorIs(t, err, agent.loop.Err())
			} else {
				require.ErrorIs(t, err, ErrNoCandidatePairs)
			}
			require.Empty(t, local.capturedWrites())
		})
	}
}
