package snell

import (
	"bufio"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"io"
	"sync"
	"time"

	"github.com/xtls/xray-core/common/errors"
)

// v6_record.go:把 sing-snell snellv6/{shaped,record,handshake}.go 的帧逻辑港到 xray plain-io 风格
// (plain io.Reader/Writer + []byte,丢弃 sing 的 buf/vectorised/readWait 性能封装,shaping 数学原样保留)。
// 三模式:default(shaped,saltBlock+prefix-AAD+padding-AAD+mix)、unshaped(salt+AEAD 无整形)、unsafe-raw(明文)。
// EOF 统一由 payloadLen==0 的 record 表示。

var (
	errV6BadVersion      = errors.New("snell v6: bad record version")
	errV6Reserved        = errors.New("snell v6: reserved header octet non-zero")
	errV6Padding         = errors.New("snell v6: unexpected padding in non-default record")
	errV6PayloadTooLarge = errors.New("snell v6: payload exceeds maximum")
)

// snellWriter/snellReader 统一 v4/v5 与 v6 的收发接口,供 server/client relay 复用。
type snellWriter interface {
	io.Writer
	writeZeroChunk() error
	writeDatagram(payload []byte) error // 一个数据报 = 一个 record(UDP 用)
}

type snellReader interface {
	io.Reader
	nextRecord() ([]byte, error)
}

func putHeader(header []byte, paddingLen, payloadLen int) {
	header[0] = headerVersion
	header[1] = 0
	header[2] = 0
	binary.BigEndian.PutUint16(header[3:5], uint16(paddingLen))
	binary.BigEndian.PutUint16(header[5:7], uint16(payloadLen))
}

func parseHeader(header []byte) (paddingLen, payloadLen int, err error) {
	if header[0] != headerVersion {
		return 0, 0, errV6BadVersion
	}
	if header[1] != 0 || header[2] != 0 {
		return 0, 0, errV6Reserved
	}
	return int(binary.BigEndian.Uint16(header[3:5])), int(binary.BigEndian.Uint16(header[5:7])), nil
}

// ===== 工厂:按 mode 建 writer/reader =====
// writer 侧生成 salt(default/unshaped);reader 侧 default 用 profile 提取隐藏 salt、unshaped 读明文 salt。

func newV6Writer(w io.Writer, mode Mode, psk []byte, profile *Profile) (snellWriter, error) {
	switch mode {
	case ModeUnsafeRaw:
		return &v6RawWriter{w: w}, nil
	case ModeUnshaped:
		salt := make([]byte, saltLen)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
		aead, err := newAEAD(deriveKey(psk, salt))
		if err != nil {
			return nil, err
		}
		return &v6UnshapedWriter{w: w, salt: salt, aead: aead, nonce: make([]byte, nonceLen)}, nil
	default:
		salt := make([]byte, saltLen)
		if _, err := io.ReadFull(rand.Reader, salt); err != nil {
			return nil, err
		}
		aead, err := newAEAD(deriveKey(psk, salt))
		if err != nil {
			return nil, err
		}
		return &v6ShapedWriter{w: w, profile: profile, salt: salt, aead: aead, nonce: make([]byte, nonceLen)}, nil
	}
}

func newV6Reader(r io.Reader, mode Mode, psk []byte, profile *Profile) snellReader {
	switch mode {
	case ModeUnsafeRaw:
		return &v6RawReader{br: bufio.NewReader(r)}
	case ModeUnshaped:
		return &v6UnshapedReader{br: bufio.NewReader(r), psk: psk, nonce: make([]byte, nonceLen)}
	default:
		return &v6ShapedReader{br: bufio.NewReader(r), psk: psk, profile: profile, nonce: make([]byte, nonceLen)}
	}
}

// ===== default: shaped =====

type v6ShapedWriter struct {
	w             io.Writer
	profile       *Profile
	salt          []byte
	aead          cipher.AEAD
	nonce         []byte
	seq           uint32
	saltSent      bool
	chunkSize     int
	lastWriteUnix int64
	mu            sync.Mutex
}

// makeSliceRecord 对应 sing-snell shaped.go makeSliceRecord:
// [saltBlock(仅首个)] [prefix(header AAD)] [header(sealed,AAD=prefix)] [padding(payload AAD)] [payloadCipher]
// padding 与 payloadCipher 经 mixPaddingPayload 混淆。
func (w *v6ShapedWriter) makeSliceRecord(payload []byte) []byte {
	prefixLen := w.profile.recordPrefixLen(w.seq)
	saltBlockLen := 0
	saltPrefixLen := 0
	if !w.saltSent {
		saltBlockLen = w.profile.saltBlockLen
		saltPrefixLen = saltBlockLen - saltLen
	}
	paddingLen := w.profile.paddingLen(w.seq, len(payload), prefixLen, saltPrefixLen, saltBlockLen)
	payloadCipherLen := 0
	if len(payload) > 0 {
		payloadCipherLen = len(payload) + aeadTagLen
	}
	out := make([]byte, 0, saltBlockLen+prefixLen+headerCipherLen+paddingLen+payloadCipherLen)

	if saltBlockLen > 0 {
		block := make([]byte, saltBlockLen)
		// 首个 record 的 saltBlock:哨兵 seq 0xffffffff 填充整形 padding,再把 salt 织入置换位置。
		w.profile.fillPadding(0xffffffff, block)
		w.profile.writeSaltBlock(w.salt, block)
		out = append(out, block...)
		w.saltSent = true
	}

	prefix := make([]byte, prefixLen)
	w.profile.fillPadding(w.seq, prefix)
	out = append(out, prefix...)

	header := make([]byte, headerCipherLen)
	putHeader(header, paddingLen, len(payload))
	w.aead.Seal(header[:0], w.nonce, header[:headerPlainLen], prefix)
	increaseNonce(w.nonce)
	out = append(out, header...)

	padding := make([]byte, paddingLen)
	w.profile.fillPadding(w.seq, padding)
	if len(payload) > 0 {
		region := make([]byte, len(payload)+aeadTagLen)
		copy(region, payload)
		w.aead.Seal(region[:0], w.nonce, region[:len(payload)], padding)
		increaseNonce(w.nonce)
		w.profile.mixPaddingPayload(w.seq, padding, region)
		out = append(out, padding...)
		out = append(out, region...)
	} else {
		out = append(out, padding...)
	}
	w.seq++
	return out
}

func (w *v6ShapedWriter) payloadLimitFor(now time.Time) int {
	nowUnix := now.Unix()
	if w.lastWriteUnix == 0 || nowUnix-w.lastWriteUnix > int64(w.profile.idleResetSec) {
		w.chunkSize = w.profile.chunkInitial
	}
	if w.chunkSize == 0 {
		w.chunkSize = w.profile.chunkInitial
	}
	payloadLimit := w.profile.chunkPayloadLimit(w.seq, w.chunkSize)
	if w.seq == 0 {
		payloadLimit = min(payloadLimit, w.profile.firstRecordCap)
	}
	w.chunkSize = w.profile.nextChunkSize(w.chunkSize)
	w.lastWriteUnix = nowUnix
	return max(1, min(payloadLimit, maxPayloadV6))
}

func (w *v6ShapedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	total := len(p)
	for len(p) > 0 {
		limit := w.payloadLimitFor(time.Now())
		recordLen := min(len(p), limit)
		if _, err := w.w.Write(w.makeSliceRecord(p[:recordLen])); err != nil {
			return 0, err
		}
		p = p[recordLen:]
	}
	return total, nil
}

func (w *v6ShapedWriter) writeZeroChunk() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.payloadLimitFor(time.Now())
	_, err := w.w.Write(w.makeSliceRecord(nil))
	return err
}

func (w *v6ShapedWriter) writeDatagram(payload []byte) error {
	if len(payload) > maxPayloadV6 {
		return errV6PayloadTooLarge
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.payloadLimitFor(time.Now())
	_, err := w.w.Write(w.makeSliceRecord(payload))
	return err
}

type v6ShapedReader struct {
	br      *bufio.Reader
	psk     []byte
	profile *Profile
	aead    cipher.AEAD
	nonce   []byte
	seq     uint32
	pending []byte
}

func (r *v6ShapedReader) readRecord() ([]byte, error) {
	if r.aead == nil {
		block := make([]byte, r.profile.saltBlockLen)
		if _, err := io.ReadFull(r.br, block); err != nil {
			return nil, err
		}
		salt := r.profile.extractSalt(block)
		aead, err := newAEAD(deriveKey(r.psk, salt[:]))
		if err != nil {
			return nil, err
		}
		r.aead = aead
	}

	prefixLen := r.profile.recordPrefixLen(r.seq)
	head := make([]byte, prefixLen+headerCipherLen)
	if _, err := io.ReadFull(r.br, head); err != nil {
		return nil, err
	}
	prefix := head[:prefixLen]
	headerCipher := head[prefixLen:]
	if _, err := r.aead.Open(headerCipher[:0], r.nonce, headerCipher, prefix); err != nil {
		return nil, errors.New("snell v6: open shaped header").Base(err)
	}
	increaseNonce(r.nonce)
	if headerCipher[0] != headerVersion {
		return nil, errV6BadVersion
	}
	paddingLen := int(binary.BigEndian.Uint16(headerCipher[3:5]))
	payloadLen := int(binary.BigEndian.Uint16(headerCipher[5:7]))
	seq := r.seq
	r.seq++

	if payloadLen == 0 {
		if paddingLen > 0 {
			if _, err := io.CopyN(io.Discard, r.br, int64(paddingLen)); err != nil {
				return nil, err
			}
		}
		return nil, io.EOF
	}

	var padding []byte
	if paddingLen > 0 {
		padding = make([]byte, paddingLen)
		if _, err := io.ReadFull(r.br, padding); err != nil {
			return nil, err
		}
	}
	body := make([]byte, payloadLen+aeadTagLen)
	if _, err := io.ReadFull(r.br, body); err != nil {
		return nil, err
	}
	r.profile.mixPaddingPayload(seq, padding, body)
	if _, err := r.aead.Open(body[:0], r.nonce, body, padding); err != nil {
		return nil, errors.New("snell v6: open shaped payload").Base(err)
	}
	increaseNonce(r.nonce)
	return body[:payloadLen], nil
}

func (r *v6ShapedReader) Read(p []byte) (int, error)      { return snellStreamRead(&r.pending, r.readRecord, p) }
func (r *v6ShapedReader) nextRecord() ([]byte, error)     { return snellNextRecord(&r.pending, r.readRecord) }

// ===== unshaped: salt(明文) + AEAD,无整形/padding =====

type v6UnshapedWriter struct {
	w        io.Writer
	salt     []byte
	aead     cipher.AEAD
	nonce    []byte
	saltSent bool
	mu       sync.Mutex
}

func (w *v6UnshapedWriter) makeRecord(payload []byte) []byte {
	saltPart := 0
	if !w.saltSent {
		saltPart = saltLen
	}
	out := make([]byte, saltPart+headerCipherLen+len(payload)+condTag(len(payload)))
	off := 0
	if saltPart > 0 {
		copy(out[:saltLen], w.salt)
		off = saltLen
		w.saltSent = true
	}
	header := out[off : off+headerCipherLen]
	putHeader(header, 0, len(payload))
	w.aead.Seal(header[:0], w.nonce, header[:headerPlainLen], nil)
	increaseNonce(w.nonce)
	if len(payload) > 0 {
		region := out[off+headerCipherLen:]
		copy(region, payload)
		w.aead.Seal(region[:0], w.nonce, region[:len(payload)], nil)
		increaseNonce(w.nonce)
	}
	return out
}

func (w *v6UnshapedWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	total := len(p)
	for len(p) > 0 {
		recordLen := min(len(p), maxPayloadV6)
		if _, err := w.w.Write(w.makeRecord(p[:recordLen])); err != nil {
			return 0, err
		}
		p = p[recordLen:]
	}
	return total, nil
}

func (w *v6UnshapedWriter) writeZeroChunk() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.w.Write(w.makeRecord(nil))
	return err
}

func (w *v6UnshapedWriter) writeDatagram(payload []byte) error {
	if len(payload) > maxPayloadV6 {
		return errV6PayloadTooLarge
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.w.Write(w.makeRecord(payload))
	return err
}

type v6UnshapedReader struct {
	br      *bufio.Reader
	psk     []byte
	aead    cipher.AEAD
	nonce   []byte
	pending []byte
}

func (r *v6UnshapedReader) readRecord() ([]byte, error) {
	if r.aead == nil {
		salt := make([]byte, saltLen)
		if _, err := io.ReadFull(r.br, salt); err != nil {
			return nil, err
		}
		aead, err := newAEAD(deriveKey(r.psk, salt))
		if err != nil {
			return nil, err
		}
		r.aead = aead
	}
	header := make([]byte, headerCipherLen)
	if _, err := io.ReadFull(r.br, header); err != nil {
		return nil, err
	}
	if _, err := r.aead.Open(header[:0], r.nonce, header, nil); err != nil {
		return nil, errors.New("snell v6: open unshaped header").Base(err)
	}
	increaseNonce(r.nonce)
	paddingLen, payloadLen, err := parseHeader(header[:headerPlainLen])
	if err != nil {
		return nil, err
	}
	if paddingLen != 0 {
		return nil, errV6Padding
	}
	if payloadLen == 0 {
		return nil, io.EOF
	}
	body := make([]byte, payloadLen+aeadTagLen)
	if _, err := io.ReadFull(r.br, body); err != nil {
		return nil, err
	}
	if _, err := r.aead.Open(body[:0], r.nonce, body, nil); err != nil {
		return nil, errors.New("snell v6: open unshaped payload").Base(err)
	}
	increaseNonce(r.nonce)
	return body[:payloadLen], nil
}

func (r *v6UnshapedReader) Read(p []byte) (int, error)  { return snellStreamRead(&r.pending, r.readRecord, p) }
func (r *v6UnshapedReader) nextRecord() ([]byte, error) { return snellNextRecord(&r.pending, r.readRecord) }

// ===== unsafe-raw: 明文分帧,无 salt/AEAD =====

type v6RawWriter struct {
	w  io.Writer
	mu sync.Mutex
}

func (w *v6RawWriter) makeRecord(payload []byte) []byte {
	out := make([]byte, headerPlainLen+len(payload))
	putHeader(out[:headerPlainLen], 0, len(payload))
	copy(out[headerPlainLen:], payload)
	return out
}

func (w *v6RawWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	total := len(p)
	for len(p) > 0 {
		recordLen := min(len(p), maxPayloadV6)
		if _, err := w.w.Write(w.makeRecord(p[:recordLen])); err != nil {
			return 0, err
		}
		p = p[recordLen:]
	}
	return total, nil
}

func (w *v6RawWriter) writeZeroChunk() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.w.Write(w.makeRecord(nil))
	return err
}

func (w *v6RawWriter) writeDatagram(payload []byte) error {
	if len(payload) > maxPayloadV6 {
		return errV6PayloadTooLarge
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	_, err := w.w.Write(w.makeRecord(payload))
	return err
}

type v6RawReader struct {
	br      *bufio.Reader
	pending []byte
}

func (r *v6RawReader) readRecord() ([]byte, error) {
	header := make([]byte, headerPlainLen)
	if _, err := io.ReadFull(r.br, header); err != nil {
		return nil, err
	}
	paddingLen, payloadLen, err := parseHeader(header)
	if err != nil {
		return nil, err
	}
	if paddingLen != 0 {
		return nil, errV6Padding
	}
	if payloadLen == 0 {
		return nil, io.EOF
	}
	body := make([]byte, payloadLen)
	if _, err := io.ReadFull(r.br, body); err != nil {
		return nil, err
	}
	return body, nil
}

func (r *v6RawReader) Read(p []byte) (int, error)  { return snellStreamRead(&r.pending, r.readRecord, p) }
func (r *v6RawReader) nextRecord() ([]byte, error) { return snellNextRecord(&r.pending, r.readRecord) }

// ===== 共用 Read/nextRecord 逻辑 =====

func condTag(payloadLen int) int {
	if payloadLen > 0 {
		return aeadTagLen
	}
	return 0
}

func snellStreamRead(pending *[]byte, readRecord func() ([]byte, error), p []byte) (int, error) {
	for len(*pending) == 0 {
		rec, err := readRecord()
		if err != nil {
			return 0, err
		}
		*pending = rec
	}
	n := copy(p, *pending)
	*pending = (*pending)[n:]
	return n, nil
}

func snellNextRecord(pending *[]byte, readRecord func() ([]byte, error)) ([]byte, error) {
	if len(*pending) > 0 {
		rec := *pending
		*pending = nil
		return rec, nil
	}
	return readRecord()
}
