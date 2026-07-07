package snell

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/xtls/xray-core/common/net"
)

func TestDeriveKey(t *testing.T) {
	psk := []byte("test-psk")
	salt := make([]byte, saltLen)
	k1 := deriveKey(psk, salt)
	if len(k1) != 16 {
		t.Fatalf("key len = %d, want 16", len(k1))
	}
	if !bytes.Equal(k1, deriveKey(psk, salt)) {
		t.Fatal("deriveKey not deterministic")
	}
	salt2 := make([]byte, saltLen)
	salt2[0] = 1
	if bytes.Equal(k1, deriveKey(psk, salt2)) {
		t.Fatal("different salt should give different key")
	}
}

// TestRecordRoundTrip 验证 record 层:salt + AEAD + 首record随机padding + swap 混淆 + 多record分块 + 零chunk EOF。
func TestRecordRoundTrip(t *testing.T) {
	psk := []byte("snell-psk-123")
	var conn bytes.Buffer

	big := make([]byte, 40000) // > maxPayloadLen,强制多 record
	rand.Read(big)
	payloads := [][]byte{
		[]byte("hello snell"),
		bytes.Repeat([]byte("A"), 100),
		big,
		[]byte("tail"),
	}

	w := newRecordWriter(&conn, psk)
	for _, p := range payloads {
		if _, err := w.Write(p); err != nil {
			t.Fatalf("write: %v", err)
		}
	}
	if err := w.writeZeroChunk(); err != nil {
		t.Fatalf("zero chunk: %v", err)
	}

	r := newRecordReader(&conn, psk)
	want := bytes.Join(payloads, nil)
	got := make([]byte, 0, len(want))
	buf := make([]byte, 4096)
	for {
		n, err := r.Read(buf)
		got = append(got, buf[:n]...)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read: %v", err)
		}
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("round trip mismatch: got %d bytes, want %d", len(got), len(want))
	}
}

func TestRecordWrongPSK(t *testing.T) {
	var conn bytes.Buffer
	w := newRecordWriter(&conn, []byte("psk-a"))
	if _, err := w.Write([]byte("secret")); err != nil {
		t.Fatal(err)
	}
	r := newRecordReader(&conn, []byte("psk-b"))
	if _, err := r.Read(make([]byte, 64)); err == nil {
		t.Fatal("expected AEAD failure with wrong PSK")
	}
}

func TestRequestRoundTrip(t *testing.T) {
	cases := []net.Destination{
		net.TCPDestination(net.ParseAddress("1.2.3.4"), 443),
		net.TCPDestination(net.ParseAddress("example.com"), 8080),
		net.TCPDestination(net.ParseAddress("2001:db8::1"), 22),
	}
	for _, dest := range cases {
		var b bytes.Buffer
		req := request{command: commandConnect, clientID: []byte("uid"), destination: dest}
		if err := req.writeTo(&b); err != nil {
			t.Fatalf("writeTo: %v", err)
		}
		got, err := readRequest(&b)
		if err != nil {
			t.Fatalf("readRequest: %v", err)
		}
		if got.command != commandConnect {
			t.Errorf("command mismatch: %d", got.command)
		}
		if got.destination.Address.String() != dest.Address.String() || got.destination.Port != dest.Port {
			t.Errorf("dest mismatch: got %v want %v", got.destination, dest)
		}
		if !bytes.Equal(got.clientID, []byte("uid")) {
			t.Errorf("clientID mismatch")
		}
	}
}

// TestFullHandshakeThenPayload 模拟 client→server:首record 写 request,随后写 payload;
// server 端用 readRequest 读握手,再读剩余 payload —— 验证握手与数据在同一 record 流里正确切分。
func TestFullHandshakeThenPayload(t *testing.T) {
	psk := []byte("psk-xyz")
	dest := net.TCPDestination(net.ParseAddress("example.com"), 443)
	appData := bytes.Repeat([]byte("payload-"), 5000) // 多 record

	var conn bytes.Buffer
	w := newRecordWriter(&conn, psk)
	var reqBuf bytes.Buffer
	if err := (request{command: commandConnect, destination: dest}).writeTo(&reqBuf); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(reqBuf.Bytes()); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(appData); err != nil {
		t.Fatal(err)
	}

	r := newRecordReader(&conn, psk)
	req, err := readRequest(r) // 从解密流里读握手
	if err != nil {
		t.Fatalf("server readRequest: %v", err)
	}
	if req.destination.Address.String() != "example.com" || req.destination.Port != 443 {
		t.Fatalf("dest mismatch: %v", req.destination)
	}
	rest, err := io.ReadAll(r) // 剩余即 app 数据
	if err != nil {
		t.Fatalf("read rest: %v", err)
	}
	if !bytes.Equal(rest, appData) {
		t.Fatalf("payload mismatch: got %d want %d", len(rest), len(appData))
	}
}
