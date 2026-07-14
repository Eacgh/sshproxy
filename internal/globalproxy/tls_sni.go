package globalproxy

import (
	"encoding/binary"
	"io"
	"net"
	"strings"
	"time"
)

const (
	tlsClientHelloTimeout = time.Second
	maxTLSRecordPayload   = (16 << 10) + 2048
)

// sniffTLSServerName 只读取并保留第一个 TLS 记录，从 ClientHello 中取得 SNI。
// 返回的 initial 必须原样写给远端；此过程不解密 TLS，也不修改用户数据。
func sniffTLSServerName(connection net.Conn) (initial []byte, serverName string, err error) {
	if err := connection.SetReadDeadline(time.Now().Add(tlsClientHelloTimeout)); err != nil {
		return nil, "", err
	}
	defer connection.SetReadDeadline(time.Time{})

	header := make([]byte, 5)
	read, err := io.ReadFull(connection, header)
	initial = append(initial, header[:read]...)
	if err != nil {
		return initial, "", err
	}
	if header[0] != 22 {
		return initial, "", nil
	}
	length := int(binary.BigEndian.Uint16(header[3:5]))
	if length < 4 || length > maxTLSRecordPayload {
		return initial, "", nil
	}
	payload := make([]byte, length)
	read, err = io.ReadFull(connection, payload)
	initial = append(initial, payload[:read]...)
	if err != nil {
		return initial, "", err
	}
	return initial, parseTLSServerName(payload), nil
}

func parseTLSServerName(clientHello []byte) string {
	if len(clientHello) < 4 || clientHello[0] != 1 {
		return ""
	}
	helloLength := int(clientHello[1])<<16 | int(clientHello[2])<<8 | int(clientHello[3])
	if helloLength > len(clientHello)-4 {
		return ""
	}
	data := clientHello[4 : 4+helloLength]
	position := 2 + 32 // legacy_version 和 random
	if position >= len(data) {
		return ""
	}
	position, ok := skipLength8(data, position)
	if !ok {
		return ""
	}
	position, ok = skipLength16(data, position)
	if !ok {
		return ""
	}
	position, ok = skipLength8(data, position)
	if !ok || position+2 > len(data) {
		return ""
	}
	extensionsLength := int(binary.BigEndian.Uint16(data[position : position+2]))
	position += 2
	if extensionsLength > len(data)-position {
		return ""
	}
	end := position + extensionsLength
	for position+4 <= end {
		extensionType := binary.BigEndian.Uint16(data[position : position+2])
		extensionLength := int(binary.BigEndian.Uint16(data[position+2 : position+4]))
		position += 4
		if extensionLength > end-position {
			return ""
		}
		if extensionType == 0 {
			return parseServerNameExtension(data[position : position+extensionLength])
		}
		position += extensionLength
	}
	return ""
}

func skipLength8(data []byte, position int) (int, bool) {
	if position >= len(data) {
		return 0, false
	}
	length := int(data[position])
	position++
	if length > len(data)-position {
		return 0, false
	}
	return position + length, true
}

func skipLength16(data []byte, position int) (int, bool) {
	if position+2 > len(data) {
		return 0, false
	}
	length := int(binary.BigEndian.Uint16(data[position : position+2]))
	position += 2
	if length > len(data)-position {
		return 0, false
	}
	return position + length, true
}

func parseServerNameExtension(extension []byte) string {
	if len(extension) < 2 {
		return ""
	}
	listLength := int(binary.BigEndian.Uint16(extension[:2]))
	if listLength > len(extension)-2 {
		return ""
	}
	position, end := 2, 2+listLength
	for position+3 <= end {
		nameType := extension[position]
		nameLength := int(binary.BigEndian.Uint16(extension[position+1 : position+3]))
		position += 3
		if nameLength > end-position {
			return ""
		}
		if nameType == 0 {
			name := strings.TrimSuffix(string(extension[position:position+nameLength]), ".")
			if validServerName(name) {
				return name
			}
		}
		position += nameLength
	}
	return ""
}

func validServerName(name string) bool {
	return name != "" && len(name) <= 253 && net.ParseIP(name) == nil &&
		!strings.ContainsAny(name, "\x00 /\\")
}
