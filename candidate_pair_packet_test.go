// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package ice

import (
	"context"
	"testing"
	"time"

	"github.com/pion/stun/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const candidatePairPacketRemoteAddress = "1.2.3.5"

// Exercise source, selection, construction, and notification combinations.
func TestCandidatePairPacketHandler(t *testing.T) { //nolint:cyclop
	for _, tc := range []struct {
		name       string
		handler    bool
		selected   bool
		knownB     bool
		pairB      bool
		fromA      bool
		accept     bool
		config     bool
		full       bool
		wantCalls  int
		wantSwitch bool
	}{
		{name: "no handler", selected: true, knownB: true, pairB: true},
		{name: "no selected pair", handler: true, knownB: true, pairB: true},
		{name: "selected path", handler: true, selected: true, knownB: true, pairB: true, fromA: true},
		{name: "known remote without pair", handler: true, selected: true, knownB: true},
		{name: "unknown remote creates no pair", handler: true, selected: true},
		{name: "observation preserves selection", handler: true, selected: true, knownB: true, pairB: true, wantCalls: 1},
		{
			name: "option selects and notifies", handler: true, selected: true, knownB: true,
			pairB: true, accept: true, wantCalls: 1, wantSwitch: true,
		},
		{
			name: "config selects and notifies", handler: true, selected: true, knownB: true,
			pairB: true, accept: true, config: true, wantCalls: 1, wantSwitch: true,
		},
		{
			name: "full agent retains pair state", handler: true, selected: true, knownB: true,
			pairB: true, accept: true, full: true, wantCalls: 1, wantSwitch: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			packet := []byte{0x80, 0x6f, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}
			var calls int
			var gotPacket []byte
			var gotPair, gotSelected *CandidatePair
			var conn *Conn
			var callbackCanWrite bool
			var handler CandidatePairPacketHandler
			if tc.handler {
				handler = func(p []byte, pair, selected *CandidatePair) bool {
					calls++
					gotPacket = append([]byte(nil), p...)
					gotPair, gotSelected = pair, selected
					callbackCanWrite = conn.CanWrite()

					return tc.accept
				}
			}
			var agent *Agent
			var err error
			if tc.config {
				agent, err = NewAgent(&AgentConfig{
					Lite: !tc.full, CandidateTypes: []CandidateType{CandidateTypeHost},
					CandidatePairPacketHandler: handler,
				})
			} else {
				agent, err = NewAgentWithOptions(
					WithICELite(!tc.full), WithCandidateTypes([]CandidateType{CandidateTypeHost}),
					WithCandidatePairPacketHandler(handler),
				)
			}
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, agent.Close()) })
			conn = &Conn{agent: agent}
			require.False(t, agent.remoteLite, "the remote client uses full ICE")
			local := newHostLocal(t)
			local.currAgent = agent
			remoteA := newRelayRemote(t)
			remoteB, err := NewCandidatePeerReflexive(&CandidatePeerReflexiveConfig{
				Network: udp, Address: candidatePairPacketRemoteAddress, Port: 12341, Component: ComponentRTP, Priority: 1,
			})
			require.NoError(t, err)
			selectedEvents := make(chan Candidate, 2)
			require.NoError(t, agent.OnSelectedCandidatePairChange(func(_, remote Candidate) {
				selectedEvents <- remote
			}))
			var pairA, pairB *CandidatePair
			require.NoError(t, agent.loop.Run(context.Background(), func(context.Context) {
				agent.remoteCandidates[local.NetworkType()] = []Candidate{remoteA}
				if tc.knownB {
					agent.remoteCandidates[local.NetworkType()] = append(agent.remoteCandidates[local.NetworkType()], remoteB)
				}
				pairA = agent.addPair(local, remoteA)
				if tc.pairB {
					pairB = agent.addPair(local, remoteB)
				}
				if tc.selected {
					agent.setSelectedPair(pairA)
				}
			}))
			if tc.selected {
				select {
				case remote := <-selectedEvents:
					require.Same(t, remoteA, remote)
				case <-time.After(time.Second):
					require.FailNow(t, "initial selection was not notified")
				}
			}
			require.False(t, agent.hasValidPair.Load(), "the initial synthetic pairs are Waiting")
			beforePairs := len(agent.checklist)
			source := remoteB.addrPort()
			if tc.fromA {
				source = remoteA.addrPort()
			}
			local.handleInboundPacket(packet, nil, source)
			require.Equal(t, tc.wantCalls, calls)
			require.Equal(t, tc.wantSwitch && !tc.full, agent.hasValidPair.Load(),
				"lite approval must publish validity independently of selection")
			require.Len(t, agent.checklist, beforePairs, "media must not create a pair")
			if calls != 0 {
				require.Equal(t, packet, gotPacket)
				require.Same(t, pairB, gotPair)
				require.Same(t, pairA, gotSelected)
				require.True(t, callbackCanWrite, "CanWrite must be safe inside the ICE-loop callback")
			}
			switch {
			case tc.wantSwitch:
				require.Same(t, pairB, agent.getSelectedPair())
				wantState := CandidatePairStateSucceeded
				if tc.full {
					wantState = CandidatePairStateWaiting
				}
				assert.Equal(t, wantState, pairB.state)
				require.Less(t, pairB.priority(), pairA.priority(), "the custom choice must differ from priority selection")
				select {
				case remote := <-selectedEvents:
					require.Same(t, remoteB, remote)
				case <-time.After(time.Second):
					require.FailNow(t, "media-driven selection was not notified")
				}
				// A lite server with a full client must retain its custom selection
				// when the normal connectivity-check timer runs.
				if !tc.full {
					require.NoError(t, agent.loop.Run(context.Background(), func(context.Context) {
						remoteB.seen(false)
						agent.getSelector().ContactCandidates()
					}))
				}
				require.Same(t, pairB, agent.getSelectedPair())
				require.True(t, conn.CanWrite())
			case tc.selected:
				require.Same(t, pairA, agent.getSelectedPair())
				if pairB != nil {
					require.Equal(t, CandidatePairStateWaiting, pairB.state)
				}
			default:
				require.Nil(t, agent.getSelectedPair())
			}
			if tc.knownB || tc.fromA {
				require.NoError(t, agent.buf.SetReadDeadline(time.Now().Add(time.Second)))
				read := make([]byte, len(packet))
				n, _, err := agent.buf.Read(read, nil)
				require.NoError(t, err)
				require.Equal(t, packet, read[:n], "observation must preserve application delivery")
			}
		})
	}
}

func TestCandidatePairPacketHandlerOptionNotUpdatable(t *testing.T) {
	agent, err := NewAgentWithOptions(WithICELite(true), WithCandidateTypes([]CandidateType{CandidateTypeHost}))
	require.NoError(t, err)
	defer func() { require.NoError(t, agent.Close()) }()
	require.ErrorIs(t, WithCandidatePairPacketHandler(nil)(agent), ErrAgentOptionNotUpdatable)
}

// A non-nominating check leaves an established lite session's alternate pair
// Waiting. Application-approved recovery must make that selected route valid
// for both write APIs, without requiring another check from the full client.
func TestCandidatePairPacketHandlerLiteValidity(t *testing.T) { //nolint:cyclop
	const (
		acceptPolicy = "accept"
		nilPolicy    = "nil"
	)

	for _, policy := range []string{acceptPolicy, "reject", nilPolicy} {
		t.Run(policy, func(t *testing.T) {
			packet := []byte{0x80, 0x6f, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1}
			var authenticated, observed *CandidatePair
			var calls int
			var handler CandidatePairPacketHandler
			if policy != nilPolicy {
				handler = func(_ []byte, pair, _ *CandidatePair) bool {
					calls++
					observed = pair

					return policy == acceptPolicy && pair == authenticated
				}
			}
			agent, err := NewAgentWithOptions(
				WithICELite(true), WithCandidateTypes([]CandidateType{CandidateTypeHost}),
				WithNetworkTypes([]NetworkType{NetworkTypeUDP4}), WithMulticastDNSMode(MulticastDNSModeDisabled),
				WithCandidatePairPacketHandler(handler),
				WithBindingRequestHandler(func(_ *stun.Message, _, _ Candidate, pair *CandidatePair) bool {
					authenticated = pair

					return false
				}),
			)
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, agent.Close()) })
			require.NoError(t, agent.SetRemoteCredentials("fullclient", "full-client-password-at-least-22"))
			require.False(t, agent.remoteLite)
			require.False(t, agent.isPiggybackingActive())
			local, remoteA := newHostLocal(t), newRelayRemote(t)
			remoteB, err := NewCandidatePeerReflexive(&CandidatePeerReflexiveConfig{
				Network: udp, Address: candidatePairPacketRemoteAddress, Port: 12341, Component: ComponentRTP, Priority: 1,
			})
			require.NoError(t, err)
			capture := &mockPacketConnWithCapture{}
			local.currAgent, local.conn = agent, capture
			conn := &Conn{agent: agent}
			require.NoError(t, agent.loop.Run(agent.loop, func(context.Context) {
				agent.localCandidates[local.NetworkType()] = []Candidate{local}
				agent.remoteCandidates[local.NetworkType()] = []Candidate{remoteA, remoteB}
			}))
			events := make(chan Candidate, 2)
			require.NoError(t, agent.OnSelectedCandidatePairChange(func(_, remote Candidate) { events <- remote }))
			wantEvent := func(want Candidate) {
				t.Helper()
				select {
				case got := <-events:
					require.Same(t, want, got)
				case <-time.After(time.Second):
					require.FailNow(t, "selection notification missing")
				}
			}
			check := func(remote Candidate, nominate bool) {
				t.Helper()
				setters := []stun.Setter{
					stun.BindingRequest, stun.TransactionID,
					stun.NewUsername(agent.localUfrag + ":" + agent.remoteUfrag), AttrControlling(1), PriorityAttr(12345),
				}
				if nominate {
					setters = append(setters, UseCandidate())
				}
				setters = append(setters, stun.NewShortTermIntegrity(agent.localPwd), stun.Fingerprint)
				request := stun.MustBuild(setters...)
				before := len(capture.sentPackets)
				local.handleInboundPacket(request.Raw, nil, remote.addrPort())
				require.Len(t, capture.sentPackets, before+1, "lite must only answer the check")
				response := &stun.Message{Raw: append([]byte(nil), capture.sentPackets[before]...)}
				require.NoError(t, response.Decode())
				require.Equal(t, stun.BindingSuccess, response.Type)
				require.Equal(t, request.TransactionID, response.TransactionID)
				require.NoError(t, stun.NewShortTermIntegrity(agent.localPwd).Check(response))
			}
			check(remoteA, true)
			pairA := agent.getSelectedPair()
			require.NotNil(t, pairA)
			wantEvent(remoteA)
			check(remoteB, false)
			pairB := authenticated
			require.NotNil(t, pairB)
			require.Same(t, remoteB, pairB.Remote)
			require.Equal(t, CandidatePairStateWaiting, pairB.state)
			require.False(t, pairB.nominated)
			require.Less(t, pairB.priority(), pairA.priority())
			require.Zero(t, calls, "STUN must not invoke the non-STUN handler")
			local.handleInboundPacket(packet, nil, remoteB.addrPort())
			wantRemote, wantState := Candidate(remoteA), CandidatePairStateWaiting
			if policy == acceptPolicy {
				wantRemote, wantState = remoteB, CandidatePairStateSucceeded
				wantEvent(remoteB)
			}
			if policy != nilPolicy {
				require.Equal(t, 1, calls)
				require.Same(t, pairB, observed)
			}
			assert.Equal(t, wantState, pairB.state)
			require.Same(t, wantRemote, agent.getSelectedPair().Remote)
			require.True(t, conn.CanWrite())
			n, err := conn.Write(packet)
			require.NoError(t, err)
			require.Equal(t, len(packet), n)
			require.Equal(t, wantRemote.addr(), capture.sentAddrs[len(capture.sentAddrs)-1])
			n, err = conn.WriteToPair(pairB.id, packet)
			if policy == acceptPolicy {
				require.NoError(t, err)
				require.Equal(t, len(packet), n)
				require.Equal(t, remoteB.addr(), capture.sentAddrs[len(capture.sentAddrs)-1])
			} else {
				require.ErrorIs(t, err, ErrCandidatePairNotSucceeded)
				require.Zero(t, n)
			}
			found := false
			for _, info := range conn.GetCandidatePairsInfo() {
				if info.ID == pairB.id {
					found = true
					require.Equal(t, wantState, info.State)
				}
			}
			require.True(t, found, "the public snapshot must include the alternate pair")
			// Delayed, non-nominating traffic and timer ticks must not replace
			// an approved lower-priority path with the old nominated route.
			check(remoteA, false)
			require.NoError(t, agent.loop.Run(agent.loop, func(context.Context) {
				for range 3 {
					agent.getSelector().ContactCandidates()
				}
			}))
			require.Same(t, wantRemote, agent.getSelectedPair().Remote)
			require.Empty(t, events)
			require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))
			read := make([]byte, len(packet))
			n, err = conn.Read(read)
			require.NoError(t, err)
			require.Equal(t, packet, read[:n])
		})
	}
}
