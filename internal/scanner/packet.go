package scanner

import (
    "fmt"
    "math/rand"
    "net"

    "github.com/google/gopacket/layers"
)

// PacketCrafter handles raw packet creation
type PacketCrafter struct {
    srcIP   net.IP
    dstIP   net.IP
    srcPort uint16
}

// NewPacketCrafter creates a new packet crafter
func NewPacketCrafter(dstIP string) (*PacketCrafter, error) {
    ip := net.ParseIP(dstIP)
    if ip == nil {
        return nil, fmt.Errorf("invalid IP address: %s", dstIP)
    }

    return &PacketCrafter{
        dstIP:   ip,
        srcIP:   getLocalIP(),
        srcPort: uint16(rand.Intn(65536-1024) + 1024),
    }, nil
}

// CreateSYNPacket creates a SYN packet
func (pc *PacketCrafter) CreateSYNPacket(dstPort uint16) *layers.TCP {
    return &layers.TCP{
        SrcPort: layers.TCPPort(pc.srcPort),
        DstPort: layers.TCPPort(dstPort),
        Seq:     rand.Uint32(),
        SYN:     true,
        Window:  64240,
    }
}

// CreateACKPacket creates an ACK packet
func (pc *PacketCrafter) CreateACKPacket(dstPort uint16, seq uint32) *layers.TCP {
    return &layers.TCP{
        SrcPort: layers.TCPPort(pc.srcPort),
        DstPort: layers.TCPPort(dstPort),
        Seq:     rand.Uint32(),
        Ack:     seq,
        ACK:     true,
        Window:  64240,
    }
}

// CreateFINPacket creates a FIN packet
func (pc *PacketCrafter) CreateFINPacket(dstPort uint16) *layers.TCP {
    return &layers.TCP{
        SrcPort: layers.TCPPort(pc.srcPort),
        DstPort: layers.TCPPort(dstPort),
        Seq:     rand.Uint32(),
        FIN:     true,
        Window:  64240,
    }
}

// CreateNULLPacket creates a NULL packet (no flags)
func (pc *PacketCrafter) CreateNULLPacket(dstPort uint16) *layers.TCP {
    return &layers.TCP{
        SrcPort: layers.TCPPort(pc.srcPort),
        DstPort: layers.TCPPort(dstPort),
        Seq:     rand.Uint32(),
        Window:  64240,
    }
}

// CreateXmasPacket creates an Xmas packet (FIN, PSH, URG)
func (pc *PacketCrafter) CreateXmasPacket(dstPort uint16) *layers.TCP {
    return &layers.TCP{
        SrcPort: layers.TCPPort(pc.srcPort),
        DstPort: layers.TCPPort(dstPort),
        Seq:     rand.Uint32(),
        FIN:     true,
        PSH:     true,
        URG:     true,
        Window:  64240,
    }
}

// CreateUDPPacket creates a UDP packet
func (pc *PacketCrafter) CreateUDPPacket(dstPort uint16, data []byte) *layers.UDP {
    return &layers.UDP{
        SrcPort: layers.UDPPort(pc.srcPort),
        DstPort: layers.UDPPort(dstPort),
    }
}

// Helper function
func getLocalIP() net.IP {
    conn, err := net.Dial("udp", "8.8.8.8:80")
    if err != nil {
        return net.ParseIP("127.0.0.1")
    }
    defer conn.Close()

    localAddr := conn.LocalAddr().(*net.UDPAddr)
    return localAddr.IP
}