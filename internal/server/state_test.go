package server

import (
	"bytes"
	"testing"
)

func TestSSVtoJson(t *testing.T) {
	ssv := "WebServerAddr=204.79.197.200:443;PrivateKey=EN5aPEpNBO+vw+BtFQY2OnK9bQU7rvEj5qmnmgwEtUc=;AdminUID=ugDmcEmxWf0pKxfkZ/8EoP35Ht+wQnqf3L0xYgyQFlQ=;DatabasePath=userinfo.db;BackupDirPath=;"
	json := ssvToJson(ssv)
	expected := []byte(`{"WebServerAddr":"204.79.197.200:443","PrivateKey":"EN5aPEpNBO+vw+BtFQY2OnK9bQU7rvEj5qmnmgwEtUc=","AdminUID":"ugDmcEmxWf0pKxfkZ/8EoP35Ht+wQnqf3L0xYgyQFlQ=","DatabasePath":"userinfo.db","BackupDirPath":""}`)
	if !bytes.Equal(expected, json) {
		t.Error(
			"For", "ssvToJson",
			"expecting", string(expected),
			"got", string(json),
		)
	}

}
