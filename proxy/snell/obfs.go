package snell

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// obfs 混淆层(忠实移植自 sing-snell obfs.go,保证与 Surge/mihomo/sing-box 互通)。
// 它是 record 层之下的透明 net.Conn 包装:
//   - http:  首个 Write 伪装成 WebSocket 升级 GET 请求(payload 放 body);读端剥离 HTTP 头
//   - tls:   首个 Write 伪装成 TLS ClientHello(payload 塞 session_ticket 扩展,≤0x400);
//            后续 Write 包成 TLS application-data 记录(0x17 0x03 0x03|len|data)
// 混淆是传输层、与 PSK 无关,故必须在派生 key / 试解之前套上。

type obfsMode int

const (
	obfsModeNone obfsMode = iota
	obfsModeHTTP
	obfsModeTLS
)

const (
	defaultObfsHost    = "bing.com"
	defaultTLSObfsHost = "cloudfront.net"

	tlsObfsFirstClientPayloadLen = 0x400
	tlsObfsRecordPayloadLen      = 0x4000
)

func parseObfsMode(name string) (obfsMode, error) {
	switch strings.ToLower(name) {
	case "", "none":
		return obfsModeNone, nil
	case "http":
		return obfsModeHTTP, nil
	case "tls":
		return obfsModeTLS, nil
	default:
		return 0, errors.New("snell: unknown obfs mode: ", name)
	}
}

var (
	httpObfsClientFingerprintOnce sync.Once
	httpObfsClientFingerprintErr  error
	httpObfsClientKey             string
	httpObfsClientUserAgent       string

	httpObfsServerResponseOnce sync.Once
	httpObfsServerResponseErr  error
	httpObfsServerResponse     []byte
)

type obfsConfig struct {
	mode obfsMode
	host string
}

func (c obfsConfig) clientConn(conn net.Conn) net.Conn {
	switch c.mode {
	case obfsModeHTTP:
		return &httpObfsClientConn{Conn: conn, config: c}
	case obfsModeTLS:
		return &tlsObfsClientConn{Conn: conn, config: c, firstResponse: true}
	default:
		return conn
	}
}

func (c obfsConfig) serverConn(conn net.Conn) net.Conn {
	switch c.mode {
	case obfsModeHTTP:
		return &httpObfsServerConn{Conn: conn, config: c}
	case obfsModeTLS:
		return &tlsObfsServerConn{Conn: conn, config: c, firstRequest: true, firstResponse: true}
	default:
		return conn
	}
}

func (c obfsConfig) writeClientRequestWithPayload(w io.Writer, payload []byte) error {
	switch c.mode {
	case obfsModeHTTP:
		httpObfsClientFingerprintOnce.Do(func() {
			var keyBytes [16]byte
			if _, readErr := io.ReadFull(rand.Reader, keyBytes[:]); readErr != nil {
				httpObfsClientFingerprintErr = errors.New("generate http obfs websocket key").Base(readErr)
				return
			}
			osMinorDelta, randomErr := rand.Int(rand.Reader, big.NewInt(6))
			if randomErr != nil {
				httpObfsClientFingerprintErr = errors.New("generate http obfs user agent").Base(randomErr)
				return
			}
			firefoxVersionDelta, randomErr := rand.Int(rand.Reader, big.NewInt(43))
			if randomErr != nil {
				httpObfsClientFingerprintErr = errors.New("generate http obfs user agent").Base(randomErr)
				return
			}
			httpObfsClientKey = base64.StdEncoding.EncodeToString(keyBytes[:])
			httpObfsClientUserAgent = fmt.Sprintf("Mozilla/5.0 (Macintosh; Intel Mac OS X 10.%d; rv:64.0) Gecko/20100101 Firefox/%d.0", int(osMinorDelta.Int64())+9, int(firefoxVersionDelta.Int64())+22)
		})
		if httpObfsClientFingerprintErr != nil {
			return httpObfsClientFingerprintErr
		}
		host := c.host
		if host == "" {
			host = defaultObfsHost
		}
		var request []byte
		if len(payload) == 0 {
			request = fmt.Appendf(request, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: %s\r\n\r\n", host, httpObfsClientUserAgent, httpObfsClientKey)
		} else {
			request = fmt.Appendf(request, "GET / HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nContent-Length: %d\r\nSec-WebSocket-Key: %s\r\n\r\n", host, httpObfsClientUserAgent, len(payload), httpObfsClientKey)
			request = append(request, payload...)
		}
		if _, err := w.Write(request); err != nil {
			return errors.New("write http obfs request").Base(err)
		}
		return nil
	case obfsModeTLS:
		host := c.host
		if host == "" {
			host = defaultTLSObfsHost
		}
		firstPayload := payload
		if len(firstPayload) > tlsObfsFirstClientPayloadLen {
			firstPayload = payload[:tlsObfsFirstClientPayloadLen]
		}
		random := make([]byte, 28)
		if _, err := io.ReadFull(rand.Reader, random); err != nil {
			return err
		}
		sessionID := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, sessionID); err != nil {
			return err
		}
		out := make([]byte, 0, 0xd9+len(firstPayload)+len(host))
		out = append(out, 0x16, 0x03, 0x01)
		out = binary.BigEndian.AppendUint16(out, uint16(212+len(firstPayload)+len(host)))
		out = append(out, 0x01, 0x00)
		out = binary.BigEndian.AppendUint16(out, uint16(208+len(firstPayload)+len(host)))
		out = append(out, 0x03, 0x03)
		out = binary.BigEndian.AppendUint32(out, uint32(time.Now().Unix()))
		out = append(out, random...)
		out = append(out, 0x20)
		out = append(out, sessionID...)
		out = binary.BigEndian.AppendUint16(out, 0x0038)
		out = append(out,
			0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0, 0x2f,
			0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67, 0xc0, 0x0a,
			0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00, 0x9c, 0x00, 0x3d,
			0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
		)
		out = append(out, 0x01, 0x00)
		out = binary.BigEndian.AppendUint16(out, uint16(79+len(firstPayload)+len(host)))
		out = binary.BigEndian.AppendUint16(out, 0x0023)
		out = binary.BigEndian.AppendUint16(out, uint16(len(firstPayload)))
		out = append(out, firstPayload...)
		out = binary.BigEndian.AppendUint16(out, 0x0000)
		out = binary.BigEndian.AppendUint16(out, uint16(len(host)+5))
		out = binary.BigEndian.AppendUint16(out, uint16(len(host)+3))
		out = append(out, 0x00)
		out = binary.BigEndian.AppendUint16(out, uint16(len(host)))
		out = append(out, host...)
		out = append(out,
			0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02,
			0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
			0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e, 0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05,
			0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04, 0x02, 0x04, 0x03, 0x03, 0x01,
			0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
			0x00, 0x16, 0x00, 0x00,
			0x00, 0x17, 0x00, 0x00,
		)
		if _, err := w.Write(out); err != nil {
			return errors.New("write tls obfs request").Base(err)
		}
		for payload = payload[len(firstPayload):]; len(payload) > 0; {
			payloadLen := min(len(payload), tlsObfsRecordPayloadLen)
			record := make([]byte, 0, 5+payloadLen)
			record = append(record, 0x17, 0x03, 0x03)
			record = binary.BigEndian.AppendUint16(record, uint16(payloadLen))
			record = append(record, payload[:payloadLen]...)
			if _, err := w.Write(record); err != nil {
				return errors.New("write tls obfs request payload").Base(err)
			}
			payload = payload[payloadLen:]
		}
		return nil
	default:
		if len(payload) == 0 {
			return nil
		}
		if _, err := w.Write(payload); err != nil {
			return errors.New("write obfs payload").Base(err)
		}
		return nil
	}
}

func readUntilHTTPHeaderEnd(r io.Reader) (io.Reader, error) {
	reader := bufio.NewReader(r)
	terminator := [4]byte{'\r', '\n', '\r', '\n'}
	matched := 0
	for {
		value, err := reader.ReadByte()
		if err != nil {
			return nil, errors.New("read http obfs header").Base(err)
		}
		if value == terminator[matched] {
			matched++
			if matched == len(terminator) {
				return reader, nil
			}
			continue
		}
		if value == terminator[0] {
			matched = 1
		} else {
			matched = 0
		}
	}
}

func (c obfsConfig) writeServerResponseWithPayload(w io.Writer, payload []byte) error {
	switch c.mode {
	case obfsModeHTTP:
		httpObfsServerResponseOnce.Do(func() {
			var acceptBytes [16]byte
			if _, readErr := io.ReadFull(rand.Reader, acceptBytes[:]); readErr != nil {
				httpObfsServerResponseErr = errors.New("generate http obfs accept").Base(readErr)
				return
			}
			versionMinorDelta, randomErr := rand.Int(rand.Reader, big.NewInt(14))
			if randomErr != nil {
				httpObfsServerResponseErr = errors.New("generate http obfs server version").Base(randomErr)
				return
			}
			versionPatchDelta, randomErr := rand.Int(rand.Reader, big.NewInt(12))
			if randomErr != nil {
				httpObfsServerResponseErr = errors.New("generate http obfs server version").Base(randomErr)
				return
			}
			accept := base64.StdEncoding.EncodeToString(acceptBytes[:])
			httpObfsServerResponse = fmt.Appendf(nil, "HTTP/1.1 101 Switching Protocols\r\nServer: nginx/1.%d.%d\r\nDate: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\n\r\n", int(versionMinorDelta.Int64()), int(versionPatchDelta.Int64()), time.Now().Format("Mon, 02 Jan 2006 15:04:05 GMT"), accept)
		})
		if httpObfsServerResponseErr != nil {
			return httpObfsServerResponseErr
		}
		response := append([]byte(nil), httpObfsServerResponse...)
		if len(payload) > 0 {
			response = append(response, payload...)
		}
		if _, err := w.Write(response); err != nil {
			return errors.New("write http obfs response").Base(err)
		}
		return nil
	case obfsModeTLS:
		random := make([]byte, 28)
		if _, err := io.ReadFull(rand.Reader, random); err != nil {
			return err
		}
		sessionID := make([]byte, 32)
		if _, err := io.ReadFull(rand.Reader, sessionID); err != nil {
			return err
		}
		firstPayload := payload
		if len(firstPayload) > tlsObfsRecordPayloadLen {
			firstPayload = payload[:tlsObfsRecordPayloadLen]
		}
		out := make([]byte, 0, 107+len(firstPayload))
		out = append(out, 0x16, 0x03, 0x01)
		out = binary.BigEndian.AppendUint16(out, 91)
		out = append(out, 0x02, 0x00, 0x00, 0x57, 0x03, 0x03)
		out = binary.BigEndian.AppendUint32(out, uint32(time.Now().Unix()))
		out = append(out, random...)
		out = append(out, 0x20)
		out = append(out, sessionID...)
		out = append(out,
			0xcc, 0xa8, 0x00,
			0x00, 0x00,
			0xff, 0x01, 0x00, 0x01, 0x00,
			0x00, 0x17, 0x00, 0x00,
			0x00, 0x0b, 0x00, 0x02, 0x01, 0x00,
			0x14, 0x03, 0x03, 0x00, 0x01, 0x01,
			0x16, 0x03, 0x03,
		)
		out = binary.BigEndian.AppendUint16(out, uint16(len(firstPayload)))
		out = append(out, firstPayload...)
		if _, err := w.Write(out); err != nil {
			return errors.New("write tls obfs response").Base(err)
		}
		for payload = payload[len(firstPayload):]; len(payload) > 0; {
			payloadLen := min(len(payload), tlsObfsRecordPayloadLen)
			record := make([]byte, 0, 5+payloadLen)
			record = append(record, 0x17, 0x03, 0x03)
			record = binary.BigEndian.AppendUint16(record, uint16(payloadLen))
			record = append(record, payload[:payloadLen]...)
			if _, err := w.Write(record); err != nil {
				return errors.New("write tls obfs response payload").Base(err)
			}
			payload = payload[payloadLen:]
		}
		return nil
	default:
		if len(payload) == 0 {
			return nil
		}
		if _, err := w.Write(payload); err != nil {
			return errors.New("write obfs payload").Base(err)
		}
		return nil
	}
}

// ===== HTTP obfs conn =====

type httpObfsClientConn struct {
	net.Conn
	config obfsConfig

	readAccess  sync.Mutex
	writeAccess sync.Mutex
	reader      io.Reader
	wrote       bool
}

func (c *httpObfsClientConn) Read(p []byte) (int, error) {
	c.readAccess.Lock()
	if c.reader == nil {
		reader, err := readUntilHTTPHeaderEnd(c.Conn)
		if err != nil {
			c.readAccess.Unlock()
			return 0, err
		}
		c.reader = reader
	}
	reader := c.reader
	c.readAccess.Unlock()
	return reader.Read(p)
}

func (c *httpObfsClientConn) Write(p []byte) (int, error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if !c.wrote {
		c.wrote = true
		if err := c.config.writeClientRequestWithPayload(c.Conn, p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return c.Conn.Write(p)
}

type httpObfsServerConn struct {
	net.Conn
	config obfsConfig

	readAccess  sync.Mutex
	writeAccess sync.Mutex
	reader      io.Reader
	wrote       bool
}

func (c *httpObfsServerConn) Read(p []byte) (int, error) {
	c.readAccess.Lock()
	if c.reader == nil {
		reader, err := readUntilHTTPHeaderEnd(c.Conn)
		if err != nil {
			c.readAccess.Unlock()
			return 0, err
		}
		c.reader = reader
	}
	reader := c.reader
	c.readAccess.Unlock()
	return reader.Read(p)
}

func (c *httpObfsServerConn) Write(p []byte) (int, error) {
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	if !c.wrote {
		c.wrote = true
		if err := c.config.writeServerResponseWithPayload(c.Conn, p); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return c.Conn.Write(p)
}

// ===== TLS obfs conn =====

type tlsObfsClientConn struct {
	net.Conn
	config obfsConfig

	readAccess    sync.Mutex
	writeAccess   sync.Mutex
	readRemaining int
	firstResponse bool
	wrote         bool
}

func (c *tlsObfsClientConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	if c.readRemaining > 0 {
		payloadLen := min(c.readRemaining, len(p))
		n, err := io.ReadFull(c.Conn, p[:payloadLen])
		c.readRemaining -= n
		return n, err
	}
	if c.firstResponse {
		c.firstResponse = false
		return c.readRecordPayload(p, 105)
	}
	return c.readRecordPayload(p, 3)
}

func (c *tlsObfsClientConn) readRecordPayload(p []byte, discardLen int) (int, error) {
	if _, err := io.CopyN(io.Discard, c.Conn, int64(discardLen)); err != nil {
		return 0, err
	}
	var lengthBytes [2]byte
	if _, err := io.ReadFull(c.Conn, lengthBytes[:]); err != nil {
		return 0, err
	}
	payloadLen := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if payloadLen == 0 {
		return 0, nil
	}
	if payloadLen > len(p) {
		n, err := io.ReadFull(c.Conn, p)
		c.readRemaining = payloadLen - n
		return n, err
	}
	return io.ReadFull(c.Conn, p[:payloadLen])
}

func (c *tlsObfsClientConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	written := 0
	if !c.wrote {
		c.wrote = true
		firstPayload := p
		if len(firstPayload) > tlsObfsFirstClientPayloadLen {
			firstPayload = p[:tlsObfsFirstClientPayloadLen]
		}
		if err := c.config.writeClientRequestWithPayload(c.Conn, firstPayload); err != nil {
			return 0, err
		}
		written += len(firstPayload)
		p = p[len(firstPayload):]
	}
	for len(p) > 0 {
		payloadLen := min(len(p), tlsObfsRecordPayloadLen)
		record := make([]byte, 0, 5+payloadLen)
		record = append(record, 0x17, 0x03, 0x03)
		record = binary.BigEndian.AppendUint16(record, uint16(payloadLen))
		record = append(record, p[:payloadLen]...)
		if _, err := c.Conn.Write(record); err != nil {
			return written, errors.New("write tls obfs payload").Base(err)
		}
		written += payloadLen
		p = p[payloadLen:]
	}
	return written, nil
}

type tlsObfsServerConn struct {
	net.Conn
	config obfsConfig

	readAccess        sync.Mutex
	writeAccess       sync.Mutex
	readRemaining     int
	firstRequest      bool
	sessionTicketDone bool
	firstResponse     bool
}

func (c *tlsObfsServerConn) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.readAccess.Lock()
	defer c.readAccess.Unlock()
	if c.readRemaining > 0 {
		payloadLen := min(c.readRemaining, len(p))
		n, err := io.ReadFull(c.Conn, p[:payloadLen])
		c.readRemaining -= n
		return n, err
	}
	if c.firstRequest {
		c.firstRequest = false
		return c.readRecordPayload(p, 9*16-4)
	}
	if !c.sessionTicketDone {
		c.sessionTicketDone = true
		if _, err := io.CopyN(io.Discard, c.Conn, 7); err != nil {
			return 0, err
		}
		var lengthBytes [2]byte
		if _, err := io.ReadFull(c.Conn, lengthBytes[:]); err != nil {
			return 0, err
		}
		if _, err := io.CopyN(io.Discard, c.Conn, int64(binary.BigEndian.Uint16(lengthBytes[:]))); err != nil {
			return 0, err
		}
		if _, err := io.CopyN(io.Discard, c.Conn, 4*16+2); err != nil {
			return 0, err
		}
	}
	return c.readRecordPayload(p, 3)
}

func (c *tlsObfsServerConn) readRecordPayload(p []byte, discardLen int) (int, error) {
	if _, err := io.CopyN(io.Discard, c.Conn, int64(discardLen)); err != nil {
		return 0, err
	}
	var lengthBytes [2]byte
	if _, err := io.ReadFull(c.Conn, lengthBytes[:]); err != nil {
		return 0, err
	}
	payloadLen := int(binary.BigEndian.Uint16(lengthBytes[:]))
	if payloadLen == 0 {
		return 0, nil
	}
	if payloadLen > len(p) {
		n, err := io.ReadFull(c.Conn, p)
		c.readRemaining = payloadLen - n
		return n, err
	}
	return io.ReadFull(c.Conn, p[:payloadLen])
}

func (c *tlsObfsServerConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	c.writeAccess.Lock()
	defer c.writeAccess.Unlock()
	written := 0
	if c.firstResponse {
		c.firstResponse = false
		firstPayload := p
		if len(firstPayload) > tlsObfsRecordPayloadLen {
			firstPayload = p[:tlsObfsRecordPayloadLen]
		}
		if err := c.config.writeServerResponseWithPayload(c.Conn, firstPayload); err != nil {
			return 0, err
		}
		written += len(firstPayload)
		p = p[len(firstPayload):]
	}
	for len(p) > 0 {
		payloadLen := min(len(p), tlsObfsRecordPayloadLen)
		record := make([]byte, 0, 5+payloadLen)
		record = append(record, 0x17, 0x03, 0x03)
		record = binary.BigEndian.AppendUint16(record, uint16(payloadLen))
		record = append(record, p[:payloadLen]...)
		if _, err := c.Conn.Write(record); err != nil {
			return written, errors.New("write tls obfs payload").Base(err)
		}
		written += payloadLen
		p = p[payloadLen:]
	}
	return written, nil
}
