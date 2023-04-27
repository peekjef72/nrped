package read_config

import (
	"net"
	"testing"
)

func TestReadConfigInit(t *testing.T) {
	obj := new(ReadConfig)
	obj.Init("nrpe-test.cfg")
	if obj.FileName != "nrpe-test.cfg" {
		t.Error("Init failed to set FileName")
	}
}

func TestReadConfigReadFileConfig(t *testing.T) {
	obj := new(ReadConfig)
	obj.Init("nrpe-test.cfg")
	if err := obj.ReadConfigFile(); err != nil {
		t.Error("ReadConfigFile failed to read config file")
	}
}

func TestReadConfigReadCommands(t *testing.T) {
	obj := new(ReadConfig)
	obj.Init("nrpe-test.cfg")
	obj.ReadConfigFile()
	obj.ReadCommands()
	if len(obj.AllowedCommands) == 0 {
		t.Error("ReadCommands failed to parse nrpe commands")
	}
	if _, ok := obj.AllowedCommands["check_iostat"]; ok == false {
		t.Error("ReadCommands failed to parse nrpe commands")
	}
}

func TestReadDefaultParamters(t *testing.T) {
	obj := new(ReadConfig)
	obj.Init("nrpe-test.cfg")
	obj.ReadConfigFile()
	if err := obj.ReadDefaultParamters(); err != nil {
		t.Error("ReadConfigFile failed to read config file")
	}
	if obj.Debug {
		t.Error("invalid debug value")
	}
	if obj.CommandArgs {
		t.Error("invalid dont_blame_nrpe value")
	}
	if obj.NastyMetachars != "|`&><'\\[]{};\r\n" {
		t.Error("invalid nasty_metachars value")

	}
}

func TestReadConfigIsCommandAllowed(t *testing.T) {
	obj := new(ReadConfig)
	obj.Init("nrpe-test.cfg")
	obj.ReadConfigFile()
	obj.ReadCommands()

	if _, err := obj.GetCommand("check_iostat"); err != nil {
		t.Error("IsCommandAllowed failed with check_iostat")
	}
	if _, err := obj.GetCommand("check_foobar"); err == nil {
		t.Error("IsCommandAllowed failed with check_foobar")
	}
}

func TestReadConfigGetCommand(t *testing.T) {
	obj := new(ReadConfig)
	obj.Init("nrpe-test.cfg")
	obj.ReadConfigFile()
	obj.ReadCommands()
	if _, err := obj.GetCommand("check_iostat"); err != nil {
		t.Error("GetCommand failed with check_iostat")
	}
}

func TestReadConfigReadPrivileges(t *testing.T) {
	obj := new(ReadConfig)
	obj.Init("nrpe-test.cfg")
	obj.ReadConfigFile()
	obj.ReadPrivileges()
	if obj.Nrpe_user == "" {
		t.Error("ReadPrivileges failed")
	}
	if obj.Nrpe_group == "" {
		t.Error("ReadPrivileges failed")
	}
}

func TestReadConfigAllowedHosts(t *testing.T) {
	obj := new(ReadConfig)
	obj.Init("nrpe-test.cfg")
	obj.ReadConfigFile()
	obj.ReadAllowedHosts()

	if len(obj.AllowedHosts) != 2 {
		t.Error("ReadAllowedHosts failed")
	}
	ip, _, err := net.ParseCIDR("127.0.0.1/32")
	if err != nil {
		t.Error("parse ip error!")
	}
	if !obj.AllowedHosts[0].IP.Equal(ip) {
		t.Error("ReadAllowedHosts invalid ip read")
	}
}

func TestIsHostAllowed(t *testing.T) {
	obj := new(ReadConfig)
	obj.Init("nrpe-test.cfg")
	obj.ReadConfigFile()
	obj.ReadAllowedHosts()

	ip, _, err := net.ParseCIDR("127.0.0.1/32")
	if err != nil {
		t.Error("parse ip error!")
	}
	if !obj.IsHostAllowed(ip) {
		t.Error("IsHostAllowed invalid ip read")
	}

	ip, _, err = net.ParseCIDR("::1/64")
	if err != nil {
		t.Error("parse ip error!")
	}
	if !obj.IsHostAllowed(ip) {
		t.Error("IsHostAllowed invalid ip read")
	}

	ip, _, err = net.ParseCIDR("192.168.0.127/32")
	if err != nil {
		t.Error("parse ip error!")
	}
	if obj.IsHostAllowed(ip) {
		t.Error("IsHostAllowed invalid ip read")
	}

}
