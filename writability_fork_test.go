// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package ice

import (
	"context"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pion/logging"
	"github.com/pion/stun/v4"
	"github.com/pion/transport/v5/test"
	"github.com/pion/transport/v5/vnet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These checks retain the pre-nomination behavior introduced by e1f057f and
// the retransmission/multiple-interface coverage added by c677c36.
func TestLiteControlledSelector_SpedInboundCheckMakesPairWritableBeforeNomination(t *testing.T) {
	agent := bareAgentForPing()
	agent.log = logging.NewDefaultLoggerFactory().NewLogger("test")
	agent.remoteUfrag = selectionTestRemoteUfrag
	agent.localUfrag = selectionTestLocalUfrag
	agent.remotePwd = selectionTestPassword
	agent.localPwd = selectionTestPassword
	agent.tieBreaker = 1
	agent.lite = true
	agent.isControlling.Store(false)
	agent.onConnected = make(chan struct{})
	agent.SetDtlsCallback(func([]byte, net.Addr) {})
	agent.setSelector()

	liteSelector, ok := agent.getSelector().(*liteSelector)
	require.True(t, ok, "expected liteSelector")
	selector, ok := liteSelector.pairCandidateSelector.(*controlledSelector)
	require.True(t, ok, "expected controlledSelector")

	local := newPingNoIOCand()
	local.candidateBase.networkType = NetworkTypeUDP4
	local.candidateBase.resolvedAddr = &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 10000}

	remote := newPingNoIOCand()
	remote.candidateBase.networkType = NetworkTypeUDP4
	remote.candidateBase.resolvedAddr = &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 20000}

	msg, err := stun.Build(stun.BindingRequest,
		stun.TransactionID,
		stun.NewUsername(agent.localUfrag+":"+agent.remoteUfrag),
		DtlsInStunAckAttribute([]uint32{}),
		stun.NewShortTermIntegrity(agent.localPwd),
		stun.Fingerprint,
	)
	require.NoError(t, err)

	selector.HandleBindingRequest(msg, local, remote)

	pair := agent.findPair(local, remote)
	require.NotNil(t, pair)
	assert.Equal(t, CandidatePairStateSucceeded, pair.state)
	assert.Nil(t, agent.getSelectedPair(), "pair should be valid before it is nominated")
	assert.Same(t, pair, agent.getBestValidCandidatePair())
}

func TestLiteControlledSelector_SpedRetransmittedInboundCheckStaysWritableBeforeNomination(t *testing.T) {
	agent := bareAgentForPing()
	agent.log = logging.NewDefaultLoggerFactory().NewLogger("test")
	agent.remoteUfrag = selectionTestRemoteUfrag
	agent.localUfrag = selectionTestLocalUfrag
	agent.remotePwd = selectionTestPassword
	agent.localPwd = selectionTestPassword
	agent.tieBreaker = 1
	agent.lite = true
	agent.isControlling.Store(false)
	agent.onConnected = make(chan struct{})
	agent.SetDtlsCallback(func([]byte, net.Addr) {})
	agent.setSelector()

	liteSelector, ok := agent.getSelector().(*liteSelector)
	require.True(t, ok, "expected liteSelector")
	selector, ok := liteSelector.pairCandidateSelector.(*controlledSelector)
	require.True(t, ok, "expected controlledSelector")

	local := newPingNoIOCand()
	local.candidateBase.networkType = NetworkTypeUDP4
	local.candidateBase.resolvedAddr = &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 10000}

	remote := newPingNoIOCand()
	remote.candidateBase.networkType = NetworkTypeUDP4
	remote.candidateBase.resolvedAddr = &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 20000}

	msg, err := stun.Build(stun.BindingRequest,
		stun.TransactionID,
		stun.NewUsername(agent.localUfrag+":"+agent.remoteUfrag),
		DtlsInStunAckAttribute([]uint32{}),
		stun.NewShortTermIntegrity(agent.localPwd),
		stun.Fingerprint,
	)
	require.NoError(t, err)

	selector.HandleBindingRequest(msg, local, remote)
	selector.HandleBindingRequest(msg, local, remote)

	pair := agent.findPair(local, remote)
	require.NotNil(t, pair)
	assert.Equal(t, CandidatePairStateSucceeded, pair.state)
	assert.Equal(t, uint64(2), pair.RequestsReceived())
	assert.Nil(t, agent.getSelectedPair(), "retransmission should not imply nomination")
	assert.Same(t, pair, agent.getBestValidCandidatePair())
}

func TestLiteControlledSelector_NonSpedInboundCheckDoesNotMakePairWritableBeforeNomination(t *testing.T) {
	agent := bareAgentForPing()
	agent.log = logging.NewDefaultLoggerFactory().NewLogger("test")
	agent.remoteUfrag = selectionTestRemoteUfrag
	agent.localUfrag = selectionTestLocalUfrag
	agent.remotePwd = selectionTestPassword
	agent.localPwd = selectionTestPassword
	agent.tieBreaker = 1
	agent.lite = true
	agent.isControlling.Store(false)
	agent.onConnected = make(chan struct{})
	agent.setSelector()

	liteSelector, ok := agent.getSelector().(*liteSelector)
	require.True(t, ok, "expected liteSelector")
	selector, ok := liteSelector.pairCandidateSelector.(*controlledSelector)
	require.True(t, ok, "expected controlledSelector")

	local := newPingNoIOCand()
	local.candidateBase.networkType = NetworkTypeUDP4
	local.candidateBase.resolvedAddr = &net.UDPAddr{IP: net.ParseIP("192.168.1.1"), Port: 10000}

	remote := newPingNoIOCand()
	remote.candidateBase.networkType = NetworkTypeUDP4
	remote.candidateBase.resolvedAddr = &net.UDPAddr{IP: net.ParseIP("192.168.1.2"), Port: 20000}

	msg, err := stun.Build(stun.BindingRequest,
		stun.TransactionID,
		stun.NewUsername(agent.localUfrag+":"+agent.remoteUfrag),
		stun.NewShortTermIntegrity(agent.localPwd),
		stun.Fingerprint,
	)
	require.NoError(t, err)

	selector.HandleBindingRequest(msg, local, remote)

	pair := agent.findPair(local, remote)
	require.NotNil(t, pair)
	assert.Equal(t, CandidatePairStateWaiting, pair.state)
	assert.Nil(t, agent.getBestValidCandidatePair())
}

func TestConn_CanWriteUsesBestValidPair(t *testing.T) {
	defer test.CheckRoutines(t)()

	cfg := &AgentConfig{
		NetworkTypes: []NetworkType{NetworkTypeUDP4},
	}
	agent, err := NewAgent(cfg)
	require.NoError(t, err)
	defer func() {
		_ = agent.Close()
	}()

	conn := &Conn{agent: agent}
	require.False(t, conn.CanWrite())

	local, err := NewCandidateHost(&CandidateHostConfig{
		Network:   "udp",
		Address:   "192.168.1.1",
		Port:      1234,
		Component: ComponentRTP,
	})
	require.NoError(t, err)
	remote, err := NewCandidateHost(&CandidateHostConfig{
		Network:   "udp",
		Address:   "192.168.1.2",
		Port:      5678,
		Component: ComponentRTP,
	})
	require.NoError(t, err)

	require.NoError(t, agent.loop.Run(agent.loop, func(_ context.Context) {
		pair := agent.addPair(local, remote)
		agent.markPairSucceeded(pair)
	}))

	require.True(t, conn.CanWrite())
}

func TestSpedLiteWriteUsesBestValidPairAcrossMultipleInterfacesBeforeNomination(t *testing.T) {
	defer test.CheckRoutines(t)()

	defer test.TimeOut(time.Second * 10).Stop()

	loggerFactory := logging.NewDefaultLoggerFactory()
	wan, err := vnet.NewRouter(&vnet.RouterConfig{
		CIDR:          "0.0.0.0/0",
		LoggerFactory: loggerFactory,
	})
	require.NoError(t, err)

	var useCandidateRequests atomic.Uint64
	wan.AddChunkFilter(func(c vnet.Chunk) bool {
		if !stun.IsMessage(c.UserData()) {
			return true
		}

		m := &stun.Message{Raw: c.UserData()}
		if decErr := m.Decode(); decErr != nil {
			return false
		}
		if m.Contains(stun.AttrUseCandidate) {
			useCandidateRequests.Add(1)

			return false
		}

		return true
	})

	fullNet, err := vnet.NewNet(&vnet.NetConfig{
		StaticIPs: []string{"192.168.0.1", "192.168.0.3"},
	})
	require.NoError(t, err)
	require.NoError(t, wan.AddNet(fullNet))

	liteNet, err := vnet.NewNet(&vnet.NetConfig{
		StaticIPs: []string{"192.168.0.2", "192.168.0.4"},
	})
	require.NoError(t, err)
	require.NoError(t, wan.AddNet(liteNet))

	require.NoError(t, wan.Start())
	defer func() {
		require.NoError(t, wan.Stop())
	}()

	checkInterval := 10 * time.Millisecond
	fullAgent, err := NewAgent(&AgentConfig{
		NetworkTypes:      supportedNetworkTypes(),
		MulticastDNSMode:  MulticastDNSModeDisabled,
		Net:               fullNet,
		CheckInterval:     &checkInterval,
		KeepaliveInterval: &checkInterval,
	})
	require.NoError(t, err)
	defer func() {
		require.NoError(t, fullAgent.Close())
	}()

	liteAgent, err := NewAgent(&AgentConfig{
		NetworkTypes:      supportedNetworkTypes(),
		CandidateTypes:    []CandidateType{CandidateTypeHost},
		MulticastDNSMode:  MulticastDNSModeDisabled,
		Net:               liteNet,
		Lite:              true,
		CheckInterval:     &checkInterval,
		KeepaliveInterval: &checkInterval,
	})
	require.NoError(t, err)
	defer func() {
		require.NoError(t, liteAgent.Close())
	}()

	fullAgent.SetDtlsCallback(func([]byte, net.Addr) {})
	liteAgent.SetDtlsCallback(func([]byte, net.Addr) {})
	require.True(t, fullAgent.Piggyback([][]byte{fakeDtlsPacket("client-hello")}, nil))
	require.NoError(t, fullAgent.SetRemoteICELite(true))
	require.NoError(t, liteAgent.SetRemoteICELite(false))

	gatherAndExchangeCandidates(t, fullAgent, liteAgent)

	fullUfrag, fullPwd, err := fullAgent.GetLocalUserCredentials()
	require.NoError(t, err)
	liteUfrag, litePwd, err := liteAgent.GetLocalUserCredentials()
	require.NoError(t, err)

	liteConn, err := liteAgent.StartAccept(fullUfrag, fullPwd)
	require.NoError(t, err)
	fullConn, err := fullAgent.StartDial(liteUfrag, litePwd)
	require.NoError(t, err)

	require.Eventually(t, liteConn.CanWrite, 2*time.Second, 10*time.Millisecond)
	require.Eventually(t, fullConn.CanWrite, 2*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool {
		return useCandidateRequests.Load() > 0
	}, 2*time.Second, 10*time.Millisecond)
	require.Nil(t, liteAgent.getSelectedPair())
	require.Nil(t, fullAgent.getSelectedPair())

	expected := []byte("server-data-before-nomination")
	writeDone := make(chan error, 1)
	go func() {
		_, writeErr := liteConn.Write(expected)
		writeDone <- writeErr
	}()

	readDone := make(chan []byte, 1)
	readErr := make(chan error, 1)
	go func() {
		buf := make([]byte, len(expected))
		n, readErrValue := fullConn.Read(buf)
		if readErrValue != nil {
			readErr <- readErrValue

			return
		}
		readDone <- buf[:n]
	}()

	select {
	case err = <-writeDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timed out writing over best valid pair before nomination")
	}
	select {
	case err = <-readErr:
		require.NoError(t, err)
	case actual := <-readDone:
		require.Equal(t, expected, actual)
	case <-time.After(time.Second):
		t.Fatal("timed out reading over best valid pair before nomination")
	}
}
