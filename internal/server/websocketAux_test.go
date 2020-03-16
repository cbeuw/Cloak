package server

import (
	"bytes"
	"github.com/cbeuw/Cloak/internal/util"
	"testing"
)

func TestFirstBuffedConn_Read(t *testing.T) {
	mockConn, writingEnd := util.GetMockConn()

	expectedFirstPacket := []byte{1, 2, 3}
	firstBuffedConn := &firstBuffedConn{
		Conn:        mockConn,
		firstRead:   false,
		firstPacket: expectedFirstPacket,
	}

	buf := make([]byte, 1024)
	n ,err :=firstBuffedConn.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}
	if !bytes.Equal(expectedFirstPacket, buf[:n]){
		t.Error("first read doesn't produce given packet")
		return
	}

	expectedSecondPacket := []byte{4,5,6,7}
	writingEnd <- expectedSecondPacket
	n ,err =firstBuffedConn.Read(buf)
	if err != nil {
		t.Error(err)
		return
	}
	if !bytes.Equal(expectedSecondPacket, buf[:n]){
		t.Error("second read doesn't produce subsequently written packet")
		return
	}
}

func TestWsAcceptor(t *testing.T){
	mockConn, _ := util.GetMockConn()
	expectedFirstPacket := []byte{1, 2, 3}

	wsAcceptor:=newWsAcceptor(mockConn, expectedFirstPacket)
	_,err := wsAcceptor.Accept()
	if err != nil {
		t.Error(err)
		return
	}

	_,err = wsAcceptor.Accept()
	if err == nil{
		t.Error("accepting second time doesn't return error")
	}
}