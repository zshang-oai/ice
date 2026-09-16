// SPDX-FileCopyrightText: 2026 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

// Package ice implements the Interactive Connectivity Establishment (ICE)
// protocol defined in rfc5245.
package ice

import (
	"bytes"
	"errors"
	"hash/crc32"
	"net"
	"slices"
	"sync"

	"github.com/pion/dtls/v3/pkg/protocol"
	"github.com/pion/stun/v4"
)

type packetWithCrc struct {
	data []byte
	crc  uint32
}

const dtlsRecordHeaderLen = 13

// isDtlsPacket determines whether the payload is a DTLS record.
func isDtlsPacket(payload []byte) bool {
	return len(payload) >= dtlsRecordHeaderLen && payload[0] > 19 && payload[0] < 64
}

type piggybackingState int

const (
	PiggybackingStateTentative piggybackingState = iota
	PiggybackingStateConfirmed
	PiggybackingStatePending
	PiggybackingStateComplete
	PiggybackingStateOff
)

// DTLS-in-STUN controller.
type piggybackingController struct {
	mu           sync.Mutex
	state        piggybackingState
	packets      []packetWithCrc
	packetsIndex int
	acks         []uint32
	dtlsCallback func(packet []byte, rAddr net.Addr)
	connected    bool
}

// init sets the controller to its initial off state. SetDtlsCallback flips it
// to tentative when piggybacking is enabled.
func (p *piggybackingController) init() {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.acks = []uint32{}
	p.state = PiggybackingStateOff
}

// flushOnConnected returns any pending packets that need to be sent as plain
// DTLS once the ICE connection is established with piggybacking disabled or complete.
func (p *piggybackingController) flushOnConnected() []packetWithCrc {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.connected = true
	if p.state != PiggybackingStateOff && p.state != PiggybackingStateComplete {
		return nil
	}
	packets := p.packets
	p.packets = []packetWithCrc{}
	p.packetsIndex = 0

	return packets
}

func (p *piggybackingController) resetLocked(state piggybackingState, cb func(packet []byte, rAddr net.Addr)) {
	p.state = state
	p.packets = []packetWithCrc{}
	p.packetsIndex = 0
	p.acks = []uint32{}
	p.dtlsCallback = cb
}

func (p *piggybackingController) finishLocked() {
	p.state = PiggybackingStatePending
	// SetDtlsHandshakeComplete already decided whether this role must retain
	// its final flight. Detaching the receive callback must preserve that choice.
	if p.acks == nil {
		p.acks = []uint32{}
	}
	p.dtlsCallback = nil
}

// SetDtlsCallback sets the callback for DTLS packets. Setting this callback
// initializes state of the piggybacking state machine to "tentative", i.e.
// expecting embedded packets. Clearing the callback resets the controller,
// except after local completion, when ACKs and any retained final flight remain
// available to finish the exchange.
func (a *Agent) SetDtlsCallback(cb func(packet []byte, rAddr net.Addr)) {
	a.piggyback.mu.Lock()
	defer a.piggyback.mu.Unlock()
	if cb != nil {
		a.piggyback.resetLocked(PiggybackingStateTentative, cb)

		return
	}
	if a.piggyback.state == PiggybackingStatePending {
		a.piggyback.finishLocked()

		return
	}
	a.piggyback.resetLocked(PiggybackingStateOff, nil)
}

func (a *Agent) isPiggybackingActive() bool {
	a.piggyback.mu.Lock()
	defer a.piggyback.mu.Unlock()

	return a.piggyback.dtlsCallback != nil &&
		a.piggyback.state != PiggybackingStateOff &&
		a.piggyback.state != PiggybackingStateComplete
}

// SetDtlsFailed disables piggybacking after the DTLS handshake failed.
func (a *Agent) SetDtlsFailed() {
	a.piggyback.mu.Lock()
	defer a.piggyback.mu.Unlock()
	if a.piggyback.state != PiggybackingStateComplete && a.piggyback.state != PiggybackingStateOff {
		a.log.Info("DTLS failed during negotiation, disabling piggybacking")
	}
	a.piggyback.state = PiggybackingStateOff
}

// SetDtlsHandshakeComplete signals that the local DTLS handshake completed and
// carries the negotiated DTLS role and version. The party that sends the last
// flight has to keep it around until it gets acknowledged; that is the server
// in DTLS 1.2 and the client in DTLS 1.3. The other party has nothing more to
// send and drops its outgoing packets.
func (a *Agent) SetDtlsHandshakeComplete(isClient bool, version protocol.Version) {
	a.piggyback.mu.Lock()
	defer a.piggyback.mu.Unlock()
	if a.piggyback.state == PiggybackingStateOff || a.piggyback.state == PiggybackingStateComplete {
		return
	}
	if isClient != (version == protocol.Version1_3) {
		a.piggyback.packets = []packetWithCrc{}
		a.piggyback.packetsIndex = 0
	}
	a.piggyback.state = PiggybackingStatePending
}

// Piggyback stores the datagrams of one DTLS flight, to be picked in a
// round-robin fashion. Returns `true` if the flight is to be consumed.
func (a *Agent) Piggyback(datagrams [][]byte, _ net.Addr) bool {
	a.piggyback.mu.Lock()
	defer a.piggyback.mu.Unlock()
	if (a.piggyback.state == PiggybackingStateOff || a.piggyback.state == PiggybackingStateComplete) &&
		a.piggyback.connected {
		return false
	}

	if len(datagrams) > 0 {
		// Refuse the whole flight rather than embed it in part.
		for _, datagram := range datagrams {
			if !isDtlsPacket(datagram) {
				return false
			}
		}
		// A new flight replaces the outgoing list.
		a.piggyback.packets = a.piggyback.packets[:0]
		a.piggyback.packetsIndex = 0
		for _, datagram := range datagrams {
			// Copy the datagram as the caller may reuse the underlying buffer.
			a.piggyback.packets = append(a.piggyback.packets,
				packetWithCrc{bytes.Clone(datagram), crc32.ChecksumIEEE(datagram)})
		}
	}
	// If we are connected also send DTLS plain.
	return !a.piggyback.connected
}

// GetPiggybackDataAndAcks returns a packet from the stored list in a round-robin fashion and a list of acks.
func (a *Agent) GetPiggybackDataAndAcks() ([]byte, []uint32) {
	a.piggyback.mu.Lock()
	defer a.piggyback.mu.Unlock()

	if a.piggyback.state == PiggybackingStateOff || a.piggyback.state == PiggybackingStateComplete {
		return nil, nil
	}
	if len(a.piggyback.packets) == 0 {
		// An empty data attribute tells the peer we support this but have
		// nothing to send, which is not the same as being done.
		if a.piggyback.state == PiggybackingStateConfirmed {
			return []byte{}, slices.Clone(a.piggyback.acks)
		}

		return nil, slices.Clone(a.piggyback.acks)
	}

	packet := a.piggyback.packets[a.piggyback.packetsIndex]
	a.piggyback.packetsIndex = (a.piggyback.packetsIndex + 1) % len(a.piggyback.packets)

	// Return copies to prevent external modification of the internal buffers.
	result := make([]byte, len(packet.data))
	copy(result, packet.data)

	return result, slices.Clone(a.piggyback.acks)
}

func (a *Agent) ReportPiggybacking(packet []byte, acks []uint32, rAddr net.Addr) { //nolint:cyclop
	a.piggyback.mu.Lock()

	if a.piggyback.state == PiggybackingStateComplete || a.piggyback.state == PiggybackingStateOff {
		a.piggyback.mu.Unlock()

		return
	}
	if packet == nil && acks == nil && a.piggyback.state == PiggybackingStateTentative {
		// Any pending packets will be flushed later when the ICE connection gets established.
		a.log.Infof("Piggybacking discovered as not supported, falling back to normal state")
		a.piggyback.dtlsCallback = nil
		a.piggyback.state = PiggybackingStateOff
		a.piggyback.mu.Unlock()

		return
	}
	// The peer may have stopped sending acks when it moved to the complete
	// state. Move to the same state.
	if packet == nil && acks == nil && a.piggyback.state == PiggybackingStatePending {
		a.log.Info("Done with the SPED handshake")
		a.piggyback.acks = nil
		a.piggyback.state = PiggybackingStateComplete
		a.piggyback.packets = []packetWithCrc{}
		a.piggyback.packetsIndex = 0
		a.piggyback.mu.Unlock()

		return
	}
	if a.piggyback.state == PiggybackingStateTentative {
		a.piggyback.state = PiggybackingStateConfirmed
	}
	// Handle incoming acks.
	if size := len(acks); size > 0 {
		a.piggyback.packets = slices.DeleteFunc(a.piggyback.packets, func(p packetWithCrc) bool {
			// Remove packets that were acknowledged.
			return slices.Contains(acks, p.crc)
		})
		if len(a.piggyback.packets) == 0 {
			a.piggyback.packetsIndex = 0
		} else if a.piggyback.packetsIndex >= len(a.piggyback.packets) {
			a.piggyback.packetsIndex %= len(a.piggyback.packets)
		}
	}
	// An ACK-only message can be delayed or acknowledge only part of the final
	// flight. Stop retransmitting only after all outgoing packets are acknowledged.
	if packet == nil && acks != nil && a.piggyback.state == PiggybackingStatePending &&
		len(a.piggyback.packets) == 0 {
		a.log.Info("Done with the SPED handshake")
		a.piggyback.acks = nil
		a.piggyback.state = PiggybackingStateComplete
		a.piggyback.mu.Unlock()

		return
	}
	if len(packet) > 0 && !isDtlsPacket(packet) {
		a.log.Warn("Dropping non-DTLS data")
		a.piggyback.mu.Unlock()

		return
	}

	var dtlsCallback func(packet []byte, rAddr net.Addr)
	// Handle the incoming packet. Calculate and store the crc32 of the packet
	// for acks, then notify the DTLS packet.
	if a.piggyback.dtlsCallback != nil && len(packet) > 0 {
		crc := crc32.ChecksumIEEE(packet)
		if !slices.Contains(a.piggyback.acks, crc) {
			a.piggyback.acks = append(a.piggyback.acks, crc)
			if len(a.piggyback.acks) > 4 {
				a.piggyback.acks = a.piggyback.acks[1:]
			}
		}
		dtlsCallback = a.piggyback.dtlsCallback
	}

	a.piggyback.mu.Unlock()

	if dtlsCallback != nil {
		dtlsCallback(packet, rAddr)
	}
}

// appendPiggybackAttributes appends DTLS-in-STUN and ACK attributes (when
// available) to the given setter slice. It is the single place that knows
// the wire-order of those attributes in outgoing STUN messages.
func (a *Agent) appendPiggybackAttributes(attrs []stun.Setter) []stun.Setter {
	packet, acks := a.GetPiggybackDataAndAcks()
	if acks == nil {
		return attrs
	}
	attrs = append(attrs, DtlsInStunAckAttribute(acks))
	if packet != nil {
		attrs = append(attrs, DtlsInStunAttribute(packet))
	}

	return attrs
}

// reportPiggybackingFromMessage extracts the DTLS-in-STUN payload and ACK list
// from a STUN message and forwards them to the controller.
func (a *Agent) reportPiggybackingFromMessage(message *stun.Message, remote Candidate) {
	var dtls DtlsInStunAttribute
	_ = dtls.GetFrom(message)
	var ack DtlsInStunAckAttribute
	// A malformed attribute must not be treated like an absent one which signals
	// a peer without piggybacking support, drop the message instead.
	if err := ack.GetFrom(message); err != nil && !errors.Is(err, stun.ErrAttributeNotFound) {
		a.log.Warnf("Discarding malformed DTLS-in-STUN ack attribute: %v", err)

		return
	}
	a.ReportPiggybacking(dtls, ack, remote.addr())
}

func (a *Agent) ReportDtlsPacket(packet []byte) {
	a.piggyback.mu.Lock()

	if a.piggyback.state == PiggybackingStateComplete || a.piggyback.state == PiggybackingStateOff {
		a.piggyback.mu.Unlock()

		return
	}
	crc := crc32.ChecksumIEEE(packet)
	if !slices.Contains(a.piggyback.acks, crc) {
		a.piggyback.acks = append(a.piggyback.acks, crc)
		if len(a.piggyback.acks) > 4 {
			a.piggyback.acks = a.piggyback.acks[1:]
		}
	}
	a.piggyback.mu.Unlock()
}
