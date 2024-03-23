package tap

import (
	"io"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

type Interface struct {
	io.ReadWriteCloser

	f *os.File

	fd   uintptr
	name string

	hdrBuf [virtioNetHdrLen]byte
}

func Open(name string) (*Interface, error) {
	fd, err := unix.Open(
		"/dev/net/tun", os.O_RDWR|syscall.O_NONBLOCK, 0)

	if err != nil {
		return nil, err
	}

	name, err = setupFd(uintptr(fd), name)
	if err != nil {
		return nil, err
	}

	f := os.NewFile(uintptr(fd), "tun")

	return &Interface{
		fd:              uintptr(fd),
		f:               f,
		ReadWriteCloser: f,
		name:            name,
	}, nil

}

const (
	cIFFTUN        = 0x0001
	cIFFTAP        = 0x0002
	cIFFNOPI       = 0x1000
	cIFFMULTIQUEUE = 0x0100
)

func ioctl(fd uintptr, request uintptr, argp uintptr) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(request), argp)
	if errno != 0 {
		return os.NewSyscallError("ioctl", errno)
	}
	return nil
}

func createInterface(fd uintptr, ifName string, flags uint16) (string, error) {
	req, err := unix.NewIfreq(ifName)
	if err != nil {
		return "", err
	}

	req.SetUint16(flags)

	err = unix.IoctlIfreq(int(fd), unix.TUNSETIFF, req)
	if err != nil {
		return "", err
	}

	return req.Name(), nil
}

func setupFd(fd uintptr, name string) (string, error) {
	var flags uint16 = unix.IFF_NO_PI | unix.IFF_TAP

	name, err := createInterface(fd, name, flags)
	if err != nil {
		return "", err
	}

	err = ioctl(fd, syscall.TUNSETPERSIST, uintptr(1))
	if err != nil {
		return "", err
	}

	return name, nil
}

func (i *Interface) ReadWithVirtioHeader(buf []byte) (virtioNetHdr, []byte, error) {
	var hdr virtioNetHdr

	n, err := i.f.Read(buf)
	if err != nil {
		return hdr, nil, err
	}

	buf = buf[:n]

	err = hdr.decode(buf)
	if err != nil {
		return hdr, nil, err
	}

	return hdr, buf[virtioNetHdrLen:], nil
}

func (i *Interface) WriteWithVirtioHeader(buf []byte) (int, error) {
	var hdr virtioNetHdr
	err := hdr.encode(i.hdrBuf[:])
	if err != nil {
		return 0, err
	}

	iovs := [][]byte{i.hdrBuf[:], buf}

	return unix.Writev(int(i.fd), iovs)
}

func (i *Interface) Close() error {
	return i.f.Close()
}
