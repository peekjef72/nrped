package common

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
	"os"
)

// define states
const (
	STATE_OK       = 0
	STATE_WARNING  = 1
	STATE_CRITICAL = 2
	STATE_UNKNOWN  = 3
)

func MessageState(state int) string {

	message_state := []string{
		"STATE_OK",
		"STATE_WARNING",
		"STATE_CRITICAL",
		"STATE_UNKNOWN",
	}
	if state < STATE_OK || state > STATE_UNKNOWN {
		state = STATE_UNKNOWN
	}
	return message_state[state]
}

// packet type
const (
	QUERY_PACKET    = 1
	RESPONSE_PACKET = 2
)

// packet version
const (
	NRPE_PACKET_VERSION_1 = 1
	NRPE_PACKET_VERSION_2 = 2
	NRPE_PACKET_VERSION_3 = 3
	NRPE_PACKET_VERSION_4 = 4 /* packet version identifier */
)

// max buffer size
const MAX_PACKETBUFFER_V2_LENGTH = 1024
const MAX_PACKETBUFFER_V3_LENGTH = 1024 * 64

const HELLO_COMMAND = "version"
const EMPTY_COMMAND = "_NRPE_CHECK"

const PROGRAM_VERSION = "0.02"

type NrpePacket interface {
	Version() int16
	Type() int16
	GetCommandBuffer() string
	GetCRC32() uint32
	ResultCode() int

	SetType(pkt_type int16)
	SetResultCode(result int16)
	SetCommand(cmd string)

	DoCRC32() (uint32, error)
	Encode() []byte

	PrepareToSend(pkt_type int16) error
	SendPacket(conn net.Conn) error
}

type nrpePacketCommonHeader struct {
	PacketVersion int16
	PacketType    int16
	CRC32Value    uint32
	ResultCode    int16
}

type nrpePacketV2Header struct {
	Common        nrpePacketCommonHeader
	CommandBuffer [MAX_PACKETBUFFER_V2_LENGTH]byte
	Trailer       int16
}

type nrpePacketV2 struct {
	Header   nrpePacketV2Header
	AllBytes []byte
}

type nrpePacketV3Header struct {
	Common       nrpePacketCommonHeader
	Alignment    int16
	BufferLength uint32
}

type nrpePacketV3 struct {
	Header        nrpePacketV3Header
	CommandBuffer []byte
	AllBytes      []byte
}

// **********************************************************************************************
//
// packetV3 implements NrepPacket
//
// **********************************************************************************************
func (pkt *nrpePacketV3) Version() int16 {
	return pkt.Header.Common.PacketVersion
}

func (pkt *nrpePacketV3) Type() int16 {
	return pkt.Header.Common.PacketType
}

func (pkt *nrpePacketV3) ResultCode() int {
	return int(pkt.Header.Common.ResultCode)
}

func (pkt *nrpePacketV3) GetCommandBuffer() string {
	// return string(pkt.CommandBuffer[:])
	// remove last \x00 char
	return string(bytes.Trim(pkt.CommandBuffer[:], "\x00"))
}

func (pkt *nrpePacketV3) GetCRC32() uint32 {
	return pkt.Header.Common.CRC32Value
}

func (pkt *nrpePacketV3) SetType(pkt_type int16) {
	pkt.Header.Common.PacketType = pkt_type
}

func (pkt *nrpePacketV3) SetResultCode(result int16) {
	pkt.Header.Common.ResultCode = result
}

func (pkt *nrpePacketV3) SetCommand(cmd string) {
	copy(pkt.CommandBuffer[:], cmd)
}

func (pkt *nrpePacketV3) SendPacket(conn net.Conn) error {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, &pkt.AllBytes); err != nil {
		fmt.Println(err)
	}
	if _, err := conn.Write([]byte(buf.Bytes())); err != nil {
		return err
	}
	return nil
}

func (pkt *nrpePacketV3) DoCRC32() (uint32, error) {
	var err error
	pkt.Header.Common.CRC32Value = 0
	// build a temporary []byte without crc32 value
	pkt.AllBytes = pkt.Encode()

	pkt.Header.Common.CRC32Value = crc32.ChecksumIEEE(pkt.AllBytes)
	if pkt.Header.Common.CRC32Value == 0 {
		err = fmt.Errorf("invalid CRC32")
	}
	// now we have crc32 value, we can build the final []byte
	pkt.AllBytes = pkt.Encode()

	return pkt.Header.Common.CRC32Value, err
}

func (pkt *nrpePacketV3) Encode() []byte {
	writer := new(bytes.Buffer)
	binary.Write(writer, binary.BigEndian, pkt.Header.Common.PacketVersion)
	binary.Write(writer, binary.BigEndian, pkt.Header.Common.PacketType)
	binary.Write(writer, binary.BigEndian, pkt.Header.Common.CRC32Value)
	binary.Write(writer, binary.BigEndian, pkt.Header.Common.ResultCode)
	binary.Write(writer, binary.BigEndian, pkt.Header.Alignment)
	binary.Write(writer, binary.BigEndian, pkt.Header.BufferLength)
	writer.Write([]byte(pkt.CommandBuffer[:]))

	return writer.Bytes()
}

func (pkt *nrpePacketV3) PrepareToSend(pkt_type int16) error {

	pkt.SetType(pkt_type)

	if _, err := pkt.DoCRC32(); err != nil {
		return err
	}

	return nil
}

// todo return error as well
func ReceivePacketV3(conn net.Conn, pkt_std *nrpePacketCommonHeader) (NrpePacket, error) {
	pkt_recv := new(nrpePacketV3)
	pkt_recv.Header.Common.PacketVersion = pkt_std.PacketVersion
	pkt_recv.Header.Common.PacketType = pkt_std.PacketType
	pkt_recv.Header.Common.CRC32Value = pkt_std.CRC32Value
	pkt_recv.Header.Common.ResultCode = pkt_std.ResultCode
	if err := binary.Read(conn, binary.BigEndian, &pkt_recv.Header.Alignment); err != nil {
		return pkt_recv, err
	}
	if err := binary.Read(conn, binary.BigEndian, &pkt_recv.Header.BufferLength); err != nil {
		return pkt_recv, err
	}

	pkt_recv.CommandBuffer = make([]byte, pkt_recv.Header.BufferLength)
	if err := binary.Read(conn, binary.BigEndian, &pkt_recv.CommandBuffer); err != nil {
		return pkt_recv, err
	}

	return pkt_recv, nil
}

// **********************************************************************************************
//
// packetV2 implements NrepPacket
//
// **********************************************************************************************
func (pkt *nrpePacketV2) Version() int16 {
	return pkt.Header.Common.PacketVersion
}

func (pkt *nrpePacketV2) Type() int16 {
	return pkt.Header.Common.PacketType
}

func (pkt *nrpePacketV2) ResultCode() int {
	return int(pkt.Header.Common.ResultCode)
}

func (pkt *nrpePacketV2) GetCommandBuffer() string {
	// remove all last \x00 runes
	return string(bytes.Trim(pkt.Header.CommandBuffer[:], "\x00"))
}
func (pkt *nrpePacketV2) GetCRC32() uint32 {
	return pkt.Header.Common.CRC32Value
}

func (pkt *nrpePacketV2) SetType(pkt_type int16) {
	pkt.Header.Common.PacketType = pkt_type
}

func (pkt *nrpePacketV2) SetResultCode(result int16) {
	pkt.Header.Common.ResultCode = result
}

func (pkt *nrpePacketV2) SetCommand(cmd string) {
	copy(pkt.Header.CommandBuffer[:], cmd)
}

func (pkt *nrpePacketV2) SendPacket(conn net.Conn) error {
	buf := new(bytes.Buffer)
	if err := binary.Write(buf, binary.BigEndian, &pkt.AllBytes); err != nil {
		fmt.Println(err)
	}
	if _, err := conn.Write([]byte(buf.Bytes())); err != nil {
		return err
	}
	return nil
}

func (pkt *nrpePacketV2) DoCRC32() (uint32, error) {
	var err error
	pkt.Header.Common.CRC32Value = 0
	// build a temporary []byte without crc32 value
	pkt.AllBytes = pkt.Encode()

	pkt.Header.Common.CRC32Value = crc32.ChecksumIEEE(pkt.AllBytes)
	if pkt.Header.Common.CRC32Value == 0 {
		err = fmt.Errorf("invalid CRC32")
	}
	// now we have crc32 value, we can build the final []byte
	pkt.AllBytes = pkt.Encode()

	return pkt.Header.Common.CRC32Value, err
}

func (pkt *nrpePacketV2) Encode() []byte {
	writer := new(bytes.Buffer)
	binary.Write(writer, binary.BigEndian, pkt.Header.Common.PacketVersion)
	binary.Write(writer, binary.BigEndian, pkt.Header.Common.PacketType)
	binary.Write(writer, binary.BigEndian, pkt.Header.Common.CRC32Value)
	binary.Write(writer, binary.BigEndian, pkt.Header.Common.ResultCode)
	writer.Write([]byte(pkt.Header.CommandBuffer[:]))
	binary.Write(writer, binary.BigEndian, pkt.Header.Trailer)
	pkt.AllBytes = writer.Bytes()
	return pkt.AllBytes
}

func (pkt *nrpePacketV2) PrepareToSend(pkt_type int16) error {

	pkt.SetType(pkt_type)
	// pkt.SetResultCode(STATE_OK)
	// if pkt_type == RESPONSE_PACKET && cmd == HELLO_COMMAND { //its a response
	// 	pkt.SetCommand(PROGRAM_VERSION)
	// } else { // Query Packet
	// 	pkt.SetCommand(cmd)
	// }

	if _, err := pkt.DoCRC32(); err != nil {
		return err
	}

	return nil
}

// todo return error as well
func ReceivePacketV2(conn net.Conn, pkt_std *nrpePacketCommonHeader) (NrpePacket, error) {
	pkt_recv := new(nrpePacketV2)
	pkt_recv.Header.Common.PacketVersion = pkt_std.PacketVersion
	pkt_recv.Header.Common.PacketType = pkt_std.PacketType
	pkt_recv.Header.Common.CRC32Value = pkt_std.CRC32Value
	pkt_recv.Header.Common.ResultCode = pkt_std.ResultCode
	if err := binary.Read(conn, binary.BigEndian, &pkt_recv.Header.CommandBuffer); err != nil {
		return pkt_recv, err
	}
	if err := binary.Read(conn, binary.BigEndian, &pkt_recv.Header.Trailer); err != nil {
		return pkt_recv, err
	}

	return pkt_recv, nil
}

// ************************************************************************************
func MakeNrpePacket(cmd string, pkt_type int16, pkt_version int) (NrpePacket, error) {
	var pkt NrpePacket

	if pkt_version == NRPE_PACKET_VERSION_3 || pkt_version == NRPE_PACKET_VERSION_4 {
		length := len(cmd)
		dataLen := length

		if length >= MAX_PACKETBUFFER_V3_LENGTH {
			length = MAX_PACKETBUFFER_V3_LENGTH - 1
			dataLen = length
		} else if length < MAX_PACKETBUFFER_V2_LENGTH {
			dataLen = MAX_PACKETBUFFER_V2_LENGTH
		}
		// pktLen := int(reflect.TypeOf(pkt.Packet).Size())
		// pkt.All = make([]byte, pktLen + dataLen)
		commandBuffer := make([]byte, dataLen)

		pkt_v3 := new(nrpePacketV3)
		pkt_v3.Header.Common.PacketVersion = NRPE_PACKET_VERSION_4
		pkt_v3.Header.Common.CRC32Value = 0
		pkt_v3.Header.Common.ResultCode = STATE_UNKNOWN
		pkt_v3.Header.Alignment = 0
		pkt_v3.Header.BufferLength = uint32(dataLen)

		pkt_v3.CommandBuffer = commandBuffer
		for i := range pkt_v3.CommandBuffer {
			pkt_v3.CommandBuffer[i] = '\x00'
		}
		pkt = pkt_v3
	} else {
		pkt_v2 := new(nrpePacketV2)
		pkt_v2.Encode()

		// can't imagine what usage it has ?
		// set random data into the packet field, then set each field to a value or \x00...
		// so directly set each field to their value ?!
		// char := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
		// rand.Seed(time.Now().UTC().UnixNano())
		// for i := 0; i < len(pkt_v2.AllBytes); i++ {
		// 	pkt_v2.AllBytes[i] = char[rand.Intn(len(char)-1)]
		// }
		// if err := binary.Read(bytes.NewReader(pkt_v2.AllBytes), binary.BigEndian, pkt_v2.Header); err != nil {
		// 	return pkt_v2, err
		// }

		for i := range pkt_v2.Header.CommandBuffer {
			pkt_v2.Header.CommandBuffer[i] = '\x00'
		}

		pkt_v2.Header.Common.PacketVersion = NRPE_PACKET_VERSION_2
		pkt_v2.Header.Common.CRC32Value = 0
		pkt_v2.Header.Common.ResultCode = STATE_UNKNOWN
		pkt_v2.Header.Trailer = 0
		pkt = pkt_v2
	}

	pkt.SetType(QUERY_PACKET)
	pkt.SetResultCode(STATE_OK)

	if pkt_type == RESPONSE_PACKET && (cmd == HELLO_COMMAND || cmd == EMPTY_COMMAND) { //its a response
		pkt.SetCommand(PROGRAM_VERSION)
	} else if cmd != "" { // Query Packet
		pkt.SetCommand(cmd)
	}

	return pkt, nil
}

func ReceivePacket(conn net.Conn) (NrpePacket, error) {
	var pkt_recv NrpePacket
	pkt_std := new(nrpePacketCommonHeader)
	if err := binary.Read(conn, binary.BigEndian, pkt_std); err != nil {
		return pkt_recv, err
	}

	if pkt_std.PacketVersion == NRPE_PACKET_VERSION_2 {
		return ReceivePacketV2(conn, pkt_std)
	} else if pkt_std.PacketVersion == NRPE_PACKET_VERSION_3 || pkt_std.PacketVersion == NRPE_PACKET_VERSION_4 {
		return ReceivePacketV3(conn, pkt_std)
	} else {
		return pkt_recv, fmt.Errorf("invalid nrpe packet version %d", pkt_std.PacketVersion)
	}
}

func CheckError(err error) {
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}
