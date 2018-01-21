package zmtp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	ZmtpSecurityNull int = iota
)

const (
	zmtpFlagsNone    byte = 0
	zmtpFlagsMore         = 1 << 0
	zmtpFlagsLong         = 1 << 1
	zmtpFlagsCommand      = 1 << 2
)

const (
	zmtpStateIdle int = iota
	zmtpStateConnecting
	zmtpStateListening
	zmtpStateSetup
	zmtpStateConnected
	zmtpStateError
)

var (
	EBUSY = errors.New(syscall.EBUSY.Error())
	ECONNREFUSED = errors.New(syscall.ECONNREFUSED.Error())
	EINVAL = errors.New(syscall.EINVAL.Error())
	EIO = errors.New(syscall.EIO.Error())
	EMSGSIZE = errors.New(syscall.EMSGSIZE.Error())
	ENOBUFS = errors.New(syscall.ENOBUFS.Error())
	ENOLINK = errors.New(syscall.ENOLINK.Error())
	ENOTCONN = errors.New(syscall.ENOTCONN.Error())
	ENOTSUP = errors.New(syscall.ENOTSUP.Error())
	EOPNOTSUPP = errors.New(syscall.EOPNOTSUPP.Error())
	EPROTO = errors.New(syscall.EPROTO.Error())
	ESOCKTNOSUPPORT = errors.New(syscall.ESOCKTNOSUPPORT.Error())
)

type ZmtpSession struct {
	state    int
	asserver int
	security int
	network  string
	address  string
	socktype string
	readable bool
	writable bool
	// TODO locking for usage between goroutines
	mutex sync.Mutex
	// generic connection interface for transports
	trans net.Conn
}

type ZmtpMsg struct {
	FlagHasMore bool
	Data        []byte
}

func zmqCheckSocketWritable(sock string) bool {
	switch sock {
	case "REQ", "REP", "PUB", "PUSH", "PAIR":
		return true
	case "SUB", "PULL":
		return false
	default:
		return false
	}
}

func zmqCheckSocketReadable(sock string) bool {
	switch sock {
	case "REQ", "REP", "SUB", "PULL", "PAIR":
		return true
	case "PUB", "PUSH":
		return false
	default:
		return false
	}
}

func zmqCheckSocketType(sock string) bool {
	switch sock {
	case "REQ", "REP", "PUB", "SUB", "PUSH", "PULL", "PAIR":
		return true
	default:
		return false
	}
}

func zmqCheckRemoteSocketType(current, check string) bool {
	switch current {
	case "REQ":
		return (check == "REP")
	case "REP":
		return (check == "REQ")
	case "PUB":
		return (check == "SUB")
	case "SUB":
		return (check == "PUB")
	case "PUSH":
		return (check == "PULL")
	case "PULL":
		return (check == "PUSH")
	case "PAIR":
		return (check == "PAIR")
	default:
		return false
	}
}

func decodeRemote(remote string) (scheme, host string, err error) {
	u, err := url.Parse(remote)
	if err != nil {
		err = EINVAL
		return
	}

	if u.Scheme == "tcp" {
		if len(u.Host) == 0 {
			err = EINVAL
		} else {
			scheme = u.Scheme
			host = u.Host
			err = nil
		}
	} else if u.Scheme == "unix" {
		if len(u.Host) != 0 {
			// abstract namespace
			scheme = u.Scheme
			host = u.Host
			err = nil
		} else if len(u.Path) != 0 {
			// socket path in filesystem
			scheme = u.Scheme
			host = u.Path
			err = nil
		} else {
			err = EINVAL
		}
	} else {
		err = EINVAL
	}

	return
}

func sessionConnectTCP(network, host string) (net.Conn, error) {
	d := net.Dialer{
		Timeout: 5 * time.Second,
		KeepAlive: 5 * time.Second,
	}

	conn, err := d.Dial(network, host)
	if err != nil {
		if strings.Contains(err.Error(), "connection refused") {
			err = ECONNREFUSED
		}
		return nil, err
	}

	return conn, nil
}

func sendGreeting(conn net.Conn) error {
	greeting := make([]byte, 64)

	greeting[0] = 0xFF
	greeting[9] = 0x7F
	greeting[10] = 0x03
	greeting[11] = 0x00

	// server not implemented yet
	greeting[32] = 0x00

	// default NULL now
	copy(greeting[12:], []byte("NULL"))

	n, err := conn.Write(greeting)
	if err != nil {
		conn.Close()
		return err
	} else if n != 64 {
		conn.Close()
		return EIO
	}

	return nil
}

func recvGreeting(conn net.Conn) error {
	greeting := make([]byte, 64)

	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	defer conn.SetReadDeadline(time.Time{})

	_, err := io.ReadFull(conn, greeting)
	if err != nil {
		conn.Close()
		return err
	}

	if greeting[0] != 0xFF || greeting[9] != 0x7F || greeting[10] < 0x03 {
		conn.Close()
		return EPROTO
	}

	security := strings.TrimRight(string(greeting[12:31]), "\x00")

	// default NULL now
	if security != "NULL" {
		//XXX s.sendErrorCommand("Mechanism mismatch")
		conn.Close()
		return EPROTO
	}

	return nil
}

func (s *ZmtpSession) exchangeGreetings() error {
	var err error

	err = sendGreeting(s.trans)
	if err != nil {
		return err
	}

	err = recvGreeting(s.trans)
	if err != nil {
		return err
	}

	return nil
}

func serializeMetadata(md map[string]string) []byte {
	var blen int
	var i int

	for k, v := range md {
		blen += 5 + len(k) + len(v)
	}

	buf := make([]byte, blen)

	for k, v := range md {
		buf[i] = byte(len(k))
		copy(buf[i+1:], []byte(k))
		binary.BigEndian.PutUint32(buf[i+1+len(k):], uint32(len(v)))
		copy(buf[i+5+len(k):], []byte(v))
		i += 5 + len(k) + len(v)
	}

	return buf
}

func deserializeMetadata(buffer []byte) (md map[string]string, err error) {
	md = map[string]string{}

	for len(buffer) > 0 {
		if len(buffer) < 5 {
			err = EPROTO
			return
		}

		kLen := uint32(buffer[0])
		if uint32(len(buffer)) < kLen+5 {
			err = EPROTO
			return
		}

		k := buffer[1 : 1+kLen]
		vLen := binary.BigEndian.Uint32(buffer[1+kLen:])
		if uint32(len(buffer)) < kLen+5+vLen {
			err = EPROTO
			return
		}

		v := buffer[5+kLen : 5+kLen+vLen]
		md[string(k)] = string(v)
		buffer = buffer[5+kLen+vLen:]
	}

	return
}

func serializeCommand(cmdName string, cmdData []byte) ([]byte, error) {
	if len(cmdName) > 255 {
		return nil, EMSGSIZE
	}

	buf := make([]byte, 1+len(cmdName)+len(cmdData))
	buf[0] = byte(len(cmdName))
	copy(buf[1:], []byte(cmdName))
	copy(buf[1+len(cmdName):], cmdData)

	return buf, nil
}

func deserializeCommand(d []byte) (cmdName string, cmdData []byte, err error) {
	if len(d) == 0 {
		err = EINVAL
		return
	}

	cmdNameLen := int(d[0])
	if cmdNameLen+1 > len(d) {
		err = EPROTO
		return
	}

	cmdName = string(d[1 : 1+cmdNameLen])
	cmdData = d[1+cmdNameLen:]

	return
}

func sendHandshake(conn net.Conn, md map[string]string) error {
	var buf [1][]byte
	var err error

	buf[0], err = serializeCommand("READY", serializeMetadata(md))
	if err != nil {
		return err
	}

	err = sendFrame(conn, buf[:], true)
	if err != nil {
		return err
	}

	return nil
}

func recvHandshake(conn net.Conn) (map[string]string, error) {
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	defer conn.SetReadDeadline(time.Time{})

	data, _, isCommand, err := receiveFrame(conn, 0)
	if err != nil {
		return nil, err
	}

	if !isCommand {
		return nil, EPROTO
	}

	name, msg, err := deserializeCommand(data)
	if err != nil {
		return nil, err
	}

	if name != "READY" {
		return nil, EPROTO
	}

	md, err := deserializeMetadata(msg)
	if err != nil {
		return nil, err
	}

	return md, nil
}

func (s *ZmtpSession) exchangeHandshakes() error {
	var err error

	var md = map[string]string{
		"Socket-Type": s.socktype,
	}

	err = sendHandshake(s.trans, md)
	if err != nil {
		return err
	}

	rmd, err := recvHandshake(s.trans)
	if err != nil {
		return err
	}

	// check remote metadata
	check := zmqCheckRemoteSocketType(s.socktype, rmd["Socket-Type"])
	if !check {
		return EPROTO
	}

	return nil
}

func sendFrame(conn net.Conn, userdata [][]byte, isCommand bool) error {
	var flags byte = 0
	var hdr []byte
	var buffer []byte
	var buflen int
	var offset int
	var maxframes int

	if isCommand && len(userdata) > 1 {
		return EINVAL
	}

	for _, v := range userdata {
		if len(v) == 0 {
			buflen += 9
		} else {
			buflen += 9+len(v)+1
		}

		maxframes++
	}

	buffer = make([]byte, buflen+1)

	for i, v := range userdata {
		flags = 0
		if isCommand {
			flags |= zmtpFlagsCommand
		}

		hdr = buffer[offset:offset+10]

		if len(v) > 0xFF {
			flags |= zmtpFlagsLong
			binary.BigEndian.PutUint64(hdr[1:], uint64(len(v)))
		} else {
			hdr[1] = byte(len(v))
			hdr = hdr[0:2]
		}

		if i < maxframes-1 {
			flags |= zmtpFlagsMore
		}

		hdr[0] = byte(flags)

		copy(buffer[offset+len(hdr):], v)
		offset += len(hdr)+len(v)
	}

	buffer = buffer[0:offset]

	_, err := conn.Write(buffer)
	if err != nil {
		return err
	}

	return nil
}

func receiveFrame(conn net.Conn, maxRead uint64) (data []byte, hasMore, isCommand bool, err error) {
	var dlen uint64
	var flags byte

	hdr := make([]byte, 9)

	_, err = io.ReadFull(conn, hdr[0:2])
	if err != nil {
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			err = ENOLINK
		}
		return
	}

	flags = hdr[0]
	hasMore = bool((flags & zmtpFlagsMore) > 1)
	isCommand = bool((flags & zmtpFlagsCommand) > 1)

	if hasMore && isCommand {
		err = EINVAL
		return
	}

	// check if long frame
	if (flags & zmtpFlagsLong) != 0 {
		_, err = io.ReadFull(conn, hdr[2:9])
		if err != nil {
			return
		} else {
			dlen = binary.BigEndian.Uint64(hdr[1:])
		}
	} else {
		dlen = uint64(hdr[1])
	}

	if maxRead != 0 && dlen > maxRead {
		// TODO error mode
		err = ENOBUFS
		return
	}

	data = make([]byte, dlen)
	_, err = io.ReadFull(conn, data)

	return
}

func NewSession(security int, socktype string) (*ZmtpSession, error) {
	s := ZmtpSession{}

	if security != ZmtpSecurityNull {
		return nil, EINVAL
	}

	if !zmqCheckSocketType(socktype) {
		return nil, ESOCKTNOSUPPORT
	} else {
		s.socktype = socktype
	}

	s.writable = zmqCheckSocketWritable(socktype)
	s.readable = zmqCheckSocketReadable(socktype)

	return &s, nil
}

func (s *ZmtpSession) Connect(remote string) error {
	if s.state != 0 {
		return EBUSY
	}

	scheme, host, err := decodeRemote(remote)
	if err != nil {
		return err
	}

	if scheme != "tcp" {
		return ENOTSUP
	}

	s.trans, err = sessionConnectTCP(scheme, host)
	if err != nil {
		return err
	}

	s.state = zmtpStateSetup
	s.network = scheme
	s.address = host

	err = s.exchangeGreetings()
	if err != nil {
		s.state = zmtpStateError
		return err
	}

	err = s.exchangeHandshakes()
	if err != nil {
		s.state = zmtpStateError
		return err
	}

	s.state = zmtpStateConnected

	return nil
}

func (s *ZmtpSession) Bind(remote string) error {
	if s.state != 0 {
		return ENOTCONN
	}

	return ENOTSUP
}

func (s *ZmtpSession) ListenAndAccept(remote string) (*ZmtpSession, error) {
	if s.state != 0 {
		return nil, ENOTCONN
	}

	return nil, ENOTSUP
}

func (s *ZmtpSession) Write(buf [][]byte) error {
	if s.state != zmtpStateConnected {
		return ENOTCONN
	}

	if !s.writable {
		return EOPNOTSUPP
	}

	err := sendFrame(s.trans, buf, false)
	if err != nil {
		return err
	}

	return nil
}

func (s *ZmtpSession) Read() ([]byte, bool, error) {
	if s.state != zmtpStateConnected {
		return nil, false, ENOTCONN
	}

	if !s.readable {
		return nil, false, EOPNOTSUPP
	}

	data, hasMore, isCommand, err := receiveFrame(s.trans, 0)
	if err != nil {
		return nil, false, err
	} else if isCommand {
		// TODO fix and re-loop
		return nil, false, fmt.Errorf("recv cmd frame")
	}

	return data, hasMore, nil
}

func (s *ZmtpSession) Subscribe(topic string) error {
	return ENOTSUP
}

func (s *ZmtpSession) Publish(topic string) error {
	return ENOTSUP
}

func (s *ZmtpSession) SetConnection(transport net.Conn) error {
	var err error

	s.trans = transport
	s.state = zmtpStateSetup
	//s.network = scheme
	//s.address = host

	err = s.exchangeGreetings()
	if err != nil {
		s.state = zmtpStateError
		return err
	}

	err = s.exchangeHandshakes()
	if err != nil {
		s.state = zmtpStateError
		return err
	}

	s.state = zmtpStateConnected

	return nil
}
