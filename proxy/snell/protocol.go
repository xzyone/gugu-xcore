package snell

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"math/big"

	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"golang.org/x/crypto/argon2"
)

// Snell 协议常量(对齐 sing-snell / Surge 6.7)。
const (
	protocolVersionDefault = 4

	headerVersion   = 0x04
	headerPlainLen  = 7
	aeadTagLen      = 16
	headerCipherLen = headerPlainLen + aeadTagLen // 23
	saltLen         = 16
	nonceLen        = 12
	maxPayloadLen   = 0x3fff

	requestVersion = 0x01

	commandPing      = 0x00
	commandConnect   = 0x01
	commandConnectV2 = 0x05
	commandUDP       = 0x06

	replyTunnel = 0x00
	replyPong   = 0x01
	replyError  = 0x02

	addressTypeIPv4 = 0x04
	addressTypeIPv6 = 0x06

	// 首个 record 强制随机 padding,长度 ∈ [0x100, 0x1FF]。
	initialPaddingMin  = 0x100
	initialPaddingSpan = 0x100
)

// deriveKey 用 Argon2id 从 PSK+salt 派生 16 字节 AES-128 key(Surge 参数:t=3, m=8, p=1)。
func deriveKey(psk, salt []byte) []byte {
	return argon2.IDKey(psk, salt, 3, 8, 1, 32)[:16]
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// increaseNonce 把 12 字节 nonce 当小端计数器 +1(nonce = u64le(counter) || 0x00000000)。
func increaseNonce(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

func randIntn(span int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(span)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}

// ===== 地址编码:Snell CONNECT 目标用 host-string(即使字面 IP),后跟 2 字节大端端口 =====

func writeConnectAddress(w io.Writer, dest net.Destination) error {
	host := dest.Address.String()
	if len(host) > 255 {
		return errors.New("snell: host too long: ", host)
	}
	buf := make([]byte, 0, 1+len(host)+2)
	buf = append(buf, byte(len(host)))
	buf = append(buf, host...)
	buf = binary.BigEndian.AppendUint16(buf, uint16(dest.Port))
	_, err := w.Write(buf)
	return err
}

func readConnectAddress(r io.Reader) (net.Destination, error) {
	var lenByte [1]byte
	if _, err := io.ReadFull(r, lenByte[:]); err != nil {
		return net.Destination{}, err
	}
	host := make([]byte, lenByte[0])
	if _, err := io.ReadFull(r, host); err != nil {
		return net.Destination{}, err
	}
	var portBytes [2]byte
	if _, err := io.ReadFull(r, portBytes[:]); err != nil {
		return net.Destination{}, err
	}
	addr := net.ParseAddress(string(host))
	port := net.Port(binary.BigEndian.Uint16(portBytes[:]))
	return net.TCPDestination(addr, port), nil
}

// ===== 握手请求:version(0x01) | command | clientIDLen | clientID | [CONNECT 时的地址] =====

type request struct {
	command     byte
	clientID    []byte
	destination net.Destination
}

func (req request) writeTo(w io.Writer) error {
	if len(req.clientID) > 255 {
		return errors.New("snell: client id too long")
	}
	prefix := []byte{requestVersion, req.command, byte(len(req.clientID))}
	if _, err := w.Write(prefix); err != nil {
		return err
	}
	if len(req.clientID) > 0 {
		if _, err := w.Write(req.clientID); err != nil {
			return err
		}
	}
	switch req.command {
	case commandConnect, commandConnectV2:
		return writeConnectAddress(w, req.destination)
	case commandPing, commandUDP:
		return nil
	default:
		return errors.New("snell: unsupported command ", req.command)
	}
}

func readRequest(r io.Reader) (request, error) {
	prefix := make([]byte, 3)
	if _, err := io.ReadFull(r, prefix); err != nil {
		return request{}, err
	}
	if prefix[0] != requestVersion {
		return request{}, errors.New("snell: bad request version ", prefix[0])
	}
	req := request{command: prefix[1]}
	if clientIDLen := int(prefix[2]); clientIDLen > 0 {
		req.clientID = make([]byte, clientIDLen)
		if _, err := io.ReadFull(r, req.clientID); err != nil {
			return request{}, err
		}
	}
	switch req.command {
	case commandConnect, commandConnectV2:
		dest, err := readConnectAddress(r)
		if err != nil {
			return request{}, err
		}
		req.destination = dest
	case commandPing, commandUDP:
	default:
		return request{}, errors.New("snell: unsupported command ", req.command)
	}
	return req, nil
}

// ===== AEAD record 流:首个 record 前置 16B salt;每 record = 23B 密文头 | padding | 密文体。
// padding 与密文体按偶数下标 swap(可逆混淆),接收方 swap 回来后再解密。payloadLen==0 表示 EOF。=====

type recordReader struct {
	reader  *bufio.Reader
	psk     []byte
	aead    cipher.AEAD
	nonce   []byte
	pending []byte
}

func newRecordReader(r io.Reader, psk []byte) *recordReader {
	return &recordReader{reader: bufio.NewReader(r), psk: psk}
}

// newRecordReaderResume 用已派生好的 aead 构造 reader(server 端多用户试解后复用)。
// 不再读 salt;nonce 从 0 开始,首个 readRecord 会读并解密首个 header。
func newRecordReaderResume(br *bufio.Reader, aead cipher.AEAD) *recordReader {
	return &recordReader{reader: br, aead: aead, nonce: make([]byte, nonceLen)}
}

// readServerReply 读取 server 回程首字节:0x00=Tunnel(隧道建立),0x02=Error。
// 兼容 CommandConnect / ConnectV2 —— 两者首个响应格式相同。
func readServerReply(r io.Reader) error {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return err
	}
	switch b[0] {
	case replyTunnel:
		return nil
	case replyError:
		return errors.New("snell: server returned error reply")
	default:
		return errors.New("snell: unexpected reply ", b[0])
	}
}

func (r *recordReader) initialize() error {
	if r.aead != nil {
		return nil
	}
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(r.reader, salt); err != nil {
		return err
	}
	aead, err := newAEAD(deriveKey(r.psk, salt))
	if err != nil {
		return err
	}
	r.aead = aead
	r.nonce = make([]byte, nonceLen)
	return nil
}

func (r *recordReader) readRecord() ([]byte, error) {
	if err := r.initialize(); err != nil {
		return nil, err
	}
	headerCipher := make([]byte, headerCipherLen)
	if _, err := io.ReadFull(r.reader, headerCipher); err != nil {
		return nil, err
	}
	header, err := r.aead.Open(headerCipher[:0], r.nonce, headerCipher, nil)
	if err != nil {
		return nil, errors.New("snell: open record header").Base(err)
	}
	increaseNonce(r.nonce)
	if header[0] != headerVersion {
		return nil, errors.New("snell: bad record version ", header[0])
	}
	paddingLen := int(binary.BigEndian.Uint16(header[3:5]))
	payloadLen := int(binary.BigEndian.Uint16(header[5:7]))
	if payloadLen == 0 {
		// payloadLen==0 即 EOF 标记。不校验 bufio 是否还有缓冲数据:与真实
		// 复用对端(reuse)对接时,zero chunk 之后可能紧跟下一请求,缓冲>0 是正常的。
		return nil, io.EOF
	}

	var padding []byte
	if paddingLen > 0 {
		padding = make([]byte, paddingLen)
		if _, err := io.ReadFull(r.reader, padding); err != nil {
			return nil, err
		}
	}
	body := make([]byte, payloadLen+aeadTagLen)
	if _, err := io.ReadFull(r.reader, body); err != nil {
		return nil, err
	}
	if padding != nil {
		limit := paddingLen
		if len(body) < limit {
			limit = len(body)
		}
		for i := 0; i < limit; i += 2 {
			padding[i], body[i] = body[i], padding[i]
		}
	}
	payload, err := r.aead.Open(body[:0], r.nonce, body, nil)
	if err != nil {
		return nil, errors.New("snell: open record payload").Base(err)
	}
	increaseNonce(r.nonce)
	return payload, nil
}

func (r *recordReader) Read(p []byte) (int, error) {
	for len(r.pending) == 0 {
		payload, err := r.readRecord()
		if err != nil {
			return 0, err
		}
		r.pending = payload
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

// nextRecord 返回一个完整 record 的明文(UDP 模式:每 record = 一个数据报)。
// 若握手后 pending 有残留则先返回它,避免丢包。
func (r *recordReader) nextRecord() ([]byte, error) {
	if len(r.pending) > 0 {
		p := r.pending
		r.pending = nil
		return p, nil
	}
	return r.readRecord()
}

type recordWriter struct {
	writer      io.Writer
	psk         []byte
	aead        cipher.AEAD
	nonce       []byte
	firstRecord bool
}

func newRecordWriter(w io.Writer, psk []byte) *recordWriter {
	return &recordWriter{writer: w, psk: psk, firstRecord: true}
}

func (w *recordWriter) initialize() error {
	if w.aead != nil {
		return nil
	}
	salt := make([]byte, saltLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	aead, err := newAEAD(deriveKey(w.psk, salt))
	if err != nil {
		return err
	}
	if _, err := w.writer.Write(salt); err != nil {
		return err
	}
	w.aead = aead
	w.nonce = make([]byte, nonceLen)
	return nil
}

func (w *recordWriter) writeRecord(payload []byte) error {
	if err := w.initialize(); err != nil {
		return err
	}
	paddingLen := 0
	if w.firstRecord {
		n, err := randIntn(initialPaddingSpan)
		if err != nil {
			return err
		}
		paddingLen = initialPaddingMin + n
		w.firstRecord = false
	}

	header := make([]byte, headerPlainLen)
	header[0] = headerVersion
	binary.BigEndian.PutUint16(header[3:5], uint16(paddingLen))
	binary.BigEndian.PutUint16(header[5:7], uint16(len(payload)))
	headerCipher := w.aead.Seal(nil, w.nonce, header, nil)
	increaseNonce(w.nonce)

	bodyCipher := w.aead.Seal(nil, w.nonce, payload, nil)
	increaseNonce(w.nonce)

	var padding []byte
	if paddingLen > 0 {
		padding = make([]byte, paddingLen)
		if _, err := rand.Read(padding); err != nil {
			return err
		}
		limit := paddingLen
		if len(bodyCipher) < limit {
			limit = len(bodyCipher)
		}
		for i := 0; i < limit; i += 2 {
			padding[i], bodyCipher[i] = bodyCipher[i], padding[i]
		}
	}

	if _, err := w.writer.Write(headerCipher); err != nil {
		return err
	}
	if padding != nil {
		if _, err := w.writer.Write(padding); err != nil {
			return err
		}
	}
	_, err := w.writer.Write(bodyCipher)
	return err
}

func (w *recordWriter) Write(p []byte) (int, error) {
	total := 0
	for len(p) > 0 {
		chunk := len(p)
		if chunk > maxPayloadLen {
			chunk = maxPayloadLen
		}
		if err := w.writeRecord(p[:chunk]); err != nil {
			return total, err
		}
		p = p[chunk:]
		total += chunk
	}
	return total, nil
}

// writeZeroChunk 写 EOF 标记(payloadLen==0 的 record)。
func (w *recordWriter) writeZeroChunk() error {
	if err := w.initialize(); err != nil {
		return err
	}
	header := make([]byte, headerPlainLen)
	header[0] = headerVersion
	headerCipher := w.aead.Seal(nil, w.nonce, header, nil)
	increaseNonce(w.nonce)
	_, err := w.writer.Write(headerCipher)
	return err
}

// writeDatagram 写单个 record(UDP:一数据报=一 record),满足 snellWriter 接口。
func (w *recordWriter) writeDatagram(payload []byte) error {
	if len(payload) > maxPayloadLen {
		return errors.New("snell: udp datagram too large ", len(payload))
	}
	return w.writeRecord(payload)
}
