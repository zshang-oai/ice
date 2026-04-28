// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

//go:build !js

package ice

import (
	"context"
	"net"
	"testing"

	"github.com/pion/transport/v4/test"
	"github.com/stretchr/testify/require"
)

func TestSped(t *testing.T) {
	defer test.CheckRoutines(t)()

	newSPEDTestAgent := func(t *testing.T) *Agent {
		t.Helper()

		agent, err := NewAgent(&AgentConfig{
			NetworkTypes: supportedNetworkTypes(),
		})
		require.NoError(t, err)

		return agent
	}

	remoteAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3478}

	t.Run("Basic embedding", func(t *testing.T) {
		aNotifier, aConnected := onConnected()
		aAgent, err := NewAgent(&AgentConfig{
			NetworkTypes: supportedNetworkTypes(),
		})
		require.NoError(t, err)
		require.NoError(t, aAgent.OnConnectionStateChange(aNotifier))

		var toA string
		fromA := "Hello from A"
		aAgent.SetDtlsCallback(func(packet []byte, rAddr net.Addr) {
			toA = string(packet)
		})
		require.True(t, aAgent.Piggyback([]byte(fromA), true))

		bNotifier, bConnected := onConnected()
		bAgent, err := NewAgent(&AgentConfig{
			NetworkTypes: supportedNetworkTypes(),
		})
		require.NoError(t, err)
		require.NoError(t, bAgent.OnConnectionStateChange(bNotifier))

		var toB string
		fromB := "Hello from B"
		bAgent.SetDtlsCallback(func(packet []byte, rAddr net.Addr) {
			toB = string(packet)
		})
		require.True(t, bAgent.Piggyback([]byte(fromB), true))

		gatherAndExchangeCandidates(t, aAgent, bAgent)
		go func() {
			bUfrag, bPwd, err := bAgent.GetLocalUserCredentials()
			require.NoError(t, err)
			_, err = aAgent.Accept(context.TODO(), bUfrag, bPwd)
			require.NoError(t, err)
		}()

		go func() {
			aUfrag, aPwd, err := aAgent.GetLocalUserCredentials()
			require.NoError(t, err)
			_, err = bAgent.Dial(context.TODO(), aUfrag, aPwd)
			require.NoError(t, err)
		}()

		<-aConnected
		<-bConnected
		require.NoError(t, aAgent.Close())
		require.NoError(t, bAgent.Close())

		require.Equal(t, toA, fromB)
		require.Equal(t, toB, fromA)
	})

	t.Run("Confirmed ignores empty non-SPED messages", func(t *testing.T) {
		agent := newSPEDTestAgent(t)
		defer func() {
			require.NoError(t, agent.Close())
		}()

		fromAgent := []byte("Hello from agent")
		agent.SetDtlsCallback(func([]byte, net.Addr) {})
		require.True(t, agent.Piggyback(fromAgent, true))

		agent.ReportPiggybacking([]byte("Hello from remote"), nil, remoteAddr)
		agent.ReportPiggybacking(nil, nil, remoteAddr)

		agent.piggyback.mu.Lock()
		require.Equal(t, piggybackingState(PiggybackingStateConfirmed), agent.piggyback.state)
		agent.piggyback.mu.Unlock()

		packet, acks := agent.GetPiggybackDataAndAcks()
		require.Equal(t, fromAgent, packet)
		require.NotNil(t, acks)
	})

	t.Run("Pending completes on empty non-SPED messages", func(t *testing.T) {
		agent := newSPEDTestAgent(t)
		defer func() {
			require.NoError(t, agent.Close())
		}()

		agent.SetDtlsCallback(func([]byte, net.Addr) {})
		require.True(t, agent.Piggyback([]byte("Hello from agent"), true))
		agent.ReportPiggybacking([]byte("Hello from remote"), nil, remoteAddr)

		require.True(t, agent.Piggyback(nil, true))
		agent.ReportPiggybacking(nil, nil, remoteAddr)

		agent.piggyback.mu.Lock()
		require.Equal(t, piggybackingState(PiggybackingStateComplete), agent.piggyback.state)
		agent.piggyback.mu.Unlock()
	})
}
