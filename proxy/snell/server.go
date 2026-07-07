package snell

import (
	"bufio"
	"context"
	"io"
	"time"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	xnet "github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/protocol"
	udp_proto "github.com/xtls/xray-core/common/protocol/udp"
	"github.com/xtls/xray-core/common/session"
	"github.com/xtls/xray-core/common/signal"
	"github.com/xtls/xray-core/common/task"
	"github.com/xtls/xray-core/core"
	"github.com/xtls/xray-core/features/policy"
	"github.com/xtls/xray-core/features/routing"
	"github.com/xtls/xray-core/transport/internet/stat"
	"github.com/xtls/xray-core/transport/internet/udp"
)

// Server 是 Snell inbound。v4/v5:per-user PSK 试解 + obfs;v6:shared PSK 派生 profile + clientID 区分用户。
type Server struct {
	policyManager policy.Manager
	users         []*protocol.MemoryUser
	obfs          obfsConfig

	// v6 专用(version==6 时生效)
	version       uint32
	v6Mode        Mode
	sharedPSK     []byte
	profile       *Profile
	clientIDUsers map[string]*protocol.MemoryUser
}

func NewServer(ctx context.Context, config *ServerConfig) (*Server, error) {
	v := core.MustFromContext(ctx)
	s := &Server{
		policyManager: v.GetFeature(policy.ManagerType()).(policy.Manager),
	}
	for _, u := range config.Users {
		mu, err := u.ToMemoryUser()
		if err != nil {
			return nil, errors.New("snell: parse user").Base(err)
		}
		if _, ok := mu.Account.(*MemoryAccount); !ok {
			return nil, errors.New("snell: invalid account type")
		}
		s.users = append(s.users, mu)
	}
	if len(s.users) == 0 {
		return nil, errors.New("snell: no users configured")
	}
	acc0 := s.users[0].Account.(*MemoryAccount)
	s.version = acc0.Version

	if s.version == 6 {
		// v6:整个 inbound 共享一个 PSK(服务器密码),派生一个 profile;各用户用 clientID 区分。
		if len(acc0.PSK) < 12 || len(acc0.PSK) > 255 {
			return nil, errors.New("snell: v6 psk length must be 12..255 bytes")
		}
		mode, err := ParseMode(acc0.V6Mode)
		if err != nil {
			return nil, err
		}
		s.v6Mode = mode
		s.sharedPSK = acc0.PSK
		if mode == ModeDefault {
			s.profile = NewProfile(acc0.PSK)
		}
		s.clientIDUsers = make(map[string]*protocol.MemoryUser)
		for _, u := range s.users {
			acc := u.Account.(*MemoryAccount)
			if len(acc.ClientID) > 0 {
				s.clientIDUsers[string(acc.ClientID)] = u
			}
		}
		return s, nil
	}

	// v4/v5:obfs 是传输层设置(与 PSK/用户无关),取首个用户的配置作为该 inbound 的混淆模式。
	mode, err := parseObfsMode(acc0.ObfsMode)
	if err != nil {
		return nil, err
	}
	s.obfs = obfsConfig{mode: mode, host: acc0.ObfsHost}
	return s, nil
}

// lookupV6User 按 clientID 查用户;单用户(无 clientID 配置)时直接用 users[0]。
func (s *Server) lookupV6User(clientID []byte) *protocol.MemoryUser {
	if u, ok := s.clientIDUsers[string(clientID)]; ok {
		return u
	}
	if len(s.clientIDUsers) == 0 {
		return s.users[0]
	}
	return nil
}

func (s *Server) Network() []xnet.Network {
	return []xnet.Network{xnet.Network_TCP}
}

// handshake 读取 salt,用每个用户的 PSK 试解首个 record header(GCM tag 即认证),
// 返回定位到首个 record 的 reader 与匹配用户。兼容单/多用户,兼容标准单-PSK 客户端。
func (s *Server) handshake(conn xnet.Conn) (*recordReader, *protocol.MemoryUser, error) {
	br := bufio.NewReader(conn)
	salt := make([]byte, saltLen)
	if _, err := io.ReadFull(br, salt); err != nil {
		return nil, nil, err
	}
	headerCipher, err := br.Peek(headerCipherLen)
	if err != nil {
		return nil, nil, err
	}
	for _, u := range s.users {
		acc, ok := u.Account.(*MemoryAccount)
		if !ok {
			continue
		}
		aead, err := newAEAD(deriveKey(acc.PSK, salt))
		if err != nil {
			continue
		}
		nonce := make([]byte, nonceLen)
		if _, err := aead.Open(nil, nonce, headerCipher, nil); err == nil {
			// tag 验证通过即认证成功(伪造在计算上不可行),不消费 header,交给 readRecord 复读。
			return newRecordReaderResume(br, aead), u, nil
		}
	}
	return nil, nil, errors.New("snell: no user matched handshake")
}

func (s *Server) Process(ctx context.Context, network xnet.Network, conn stat.Connection, dispatcher routing.Dispatcher) error {
	sessPolicy := s.policyManager.ForLevel(0)
	_ = conn.SetReadDeadline(time.Now().Add(sessPolicy.Timeouts.Handshake))

	if s.version == 6 {
		return s.processV6(ctx, conn, dispatcher, sessPolicy)
	}

	// v4/v5:obfs 在 record 层之下,先套混淆包装;再逐 PSK 试解握手。
	oconn := s.obfs.serverConn(conn)
	reader, user, err := s.handshake(oconn)
	if err != nil {
		return errors.New("snell: handshake").Base(err)
	}
	account := user.Account.(*MemoryAccount)

	req, err := readRequest(reader)
	if err != nil {
		return errors.New("snell: read request").Base(err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	s.setInbound(ctx, user)
	writer := newRecordWriter(oconn, account.PSK)
	return s.serve(ctx, req, reader, writer, dispatcher, sessPolicy)
}

// processV6:共享 PSK 派生 profile,shaped/unshaped/raw reader 读握手,按 clientID 查用户。
func (s *Server) processV6(ctx context.Context, conn stat.Connection, dispatcher routing.Dispatcher, sessPolicy policy.Session) error {
	// v6 无 obfs(整形本身即混淆)。
	reader := newV6Reader(conn, s.v6Mode, s.sharedPSK, s.profile)
	req, err := readRequest(reader)
	if err != nil {
		return errors.New("snell v6: read request").Base(err)
	}
	_ = conn.SetReadDeadline(time.Time{})

	user := s.lookupV6User(req.clientID)
	if user == nil {
		return errors.New("snell v6: unknown clientID")
	}
	s.setInbound(ctx, user)
	writer, err := newV6Writer(conn, s.v6Mode, s.sharedPSK, s.profile)
	if err != nil {
		return errors.New("snell v6: create writer").Base(err)
	}
	return s.serve(ctx, req, reader, writer, dispatcher, sessPolicy)
}

func (s *Server) setInbound(ctx context.Context, user *protocol.MemoryUser) {
	inbound := session.InboundFromContext(ctx)
	inbound.Name = "snell"
	inbound.User = user
	inbound.CanSpliceCopy = 3
}

// serve 按 command 分 TCP/UDP。reader/writer 已按版本建好,以下逻辑版本无关。
// CommandConnect(0x01)与 ConnectV2(0x05)首个响应格式相同,均按非复用 TCP 处理。
func (s *Server) serve(ctx context.Context, req request, reader snellReader, writer snellWriter, dispatcher routing.Dispatcher, sessPolicy policy.Session) error {
	switch req.command {
	case commandConnect, commandConnectV2:
		return s.serveTCP(ctx, req.destination, reader, writer, dispatcher, sessPolicy)
	case commandUDP:
		return s.handleUDP(ctx, reader, writer, dispatcher, sessPolicy)
	default:
		return errors.New("snell: unsupported command ", req.command)
	}
}

func (s *Server) serveTCP(ctx context.Context, destination xnet.Destination, reader snellReader, writer snellWriter, dispatcher routing.Dispatcher, sessPolicy policy.Session) error {
	link, err := dispatcher.Dispatch(ctx, destination)
	if err != nil {
		return errors.New("snell: dispatch").Base(err)
	}

	// 回程首字节必须是 ReplyTunnel(0x00),客户端据此确认隧道建立。
	if _, err := writer.Write([]byte{replyTunnel}); err != nil {
		return errors.New("snell: write tunnel reply").Base(err)
	}

	ctx, cancel := context.WithCancel(ctx)
	timer := signal.CancelAfterInactivity(ctx, cancel, sessPolicy.Timeouts.ConnectionIdle)

	requestDone := func() error {
		if err := buf.Copy(buf.NewReader(reader), link.Writer, buf.UpdateActivity(timer)); err != nil {
			return errors.New("snell: transport request").Base(err)
		}
		return nil
	}
	responseDone := func() error {
		if err := buf.Copy(link.Reader, buf.NewWriter(writer), buf.UpdateActivity(timer)); err != nil {
			return errors.New("snell: transport response").Base(err)
		}
		return nil
	}

	requestDoneAndCloseWriter := task.OnSuccess(requestDone, task.Close(link.Writer))
	if err := task.Run(ctx, requestDoneAndCloseWriter, responseDone); err != nil {
		common.Interrupt(link.Reader)
		common.Interrupt(link.Writer)
		return errors.New("snell: connection ends").Base(err)
	}
	return nil
}

// handleUDP 处理 CommandUDP:每个 record = 一个数据报(client→server: 0x01|地址|payload)。
// 用 udp.Dispatcher 把每个数据报按各自目标转发(全锥),响应回程编码为 地址|payload record。
func (s *Server) handleUDP(ctx context.Context, reader snellReader, writer snellWriter, dispatcher routing.Dispatcher, sessPolicy policy.Session) error {
	// 回程首个 record 为 ReplyTunnel(0x00),表示 UDP 隧道建立。
	if _, err := writer.Write([]byte{replyTunnel}); err != nil {
		return errors.New("snell: write udp reply").Base(err)
	}
	packetWriter := &udpPacketWriter{writer: writer, response: true}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	timer := signal.CancelAfterInactivity(ctx, cancel, sessPolicy.Timeouts.ConnectionIdle)
	defer timer.SetTimeout(0)

	udpServer := udp.NewDispatcher(dispatcher, func(ctx context.Context, packet *udp_proto.Packet) {
		payload := packet.Payload
		if payload == nil {
			return
		}
		if err := packetWriter.writePacket(payload.Bytes(), packet.Source); err != nil {
			errors.LogWarningInner(ctx, err, "snell: write udp response")
			payload.Release()
			cancel()
			return
		}
		payload.Release()
		timer.Update()
	})
	defer udpServer.RemoveRay()

	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}
		record, err := reader.nextRecord()
		if err != nil {
			if err == io.EOF {
				return nil
			}
			return errors.New("snell: read udp datagram").Base(err)
		}
		if len(record) < 1 || record[0] != udpCommandForward {
			continue
		}
		dest, payload, err := readUDPRequestAddress(record[1:])
		if err != nil {
			return errors.New("snell: parse udp request").Base(err)
		}
		timer.Update()
		b := buf.New()
		if _, err := b.Write(payload); err != nil {
			b.Release()
			return err
		}
		udpServer.Dispatch(ctx, dest, b)
	}
}
