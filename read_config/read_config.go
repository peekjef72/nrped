package read_config

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/canonical/nrped/common"

	"github.com/jimlawless/cfg"
)

const (
	MAX_ALLOWED_HOSTS = 32
)

type ReadConfig struct {
	AllowedCommands map[string]*common.NrpeCommand
	FileName        string
	ServerPort      string
	TransportMode   uint16
	CommandPrefix   string
	Server          string
	AllowedHosts    []*net.IPNet
	Debug           bool
	Nrpe_user       string
	Nrpe_group      string
	PidFile         string
	ConfigMap       map[string]string
	//TODO implement everything
	CommandArgs    bool
	NastyMetachars string
}

// TODO
// design a constructor
func (rc *ReadConfig) Init(file_name string) {
	rc.AllowedCommands = make(map[string]*common.NrpeCommand)
	rc.ConfigMap = make(map[string]string)
	rc.FileName = file_name
}

func (rc *ReadConfig) ReadConfigFile() error {
	if err := cfg.Load(rc.FileName, rc.ConfigMap); err != nil {
		return err
	}
	return nil
}
func (rc *ReadConfig) ReadDefaultParamters() error {

	val, ok := rc.ConfigMap["server_address"]
	if !ok {
		val = "127.0.0.1"
	}
	rc.Server = val
	// level.Info(logger).Log("msg", "")

	val, ok = rc.ConfigMap["server_port"]
	if !ok {
		val = "5666"
	}
	rc.ServerPort = val

	if val, ok := rc.ConfigMap["transport_mode"]; ok {
		s, err := strconv.Atoi(val)
		if err != nil {
			return err
		}
		rc.TransportMode = uint16(s)
	} else {
		rc.TransportMode = uint16(0)
	}

	val, ok = rc.ConfigMap["nrpe_user"]
	if !ok {
		val = "nagios"
	}
	rc.Nrpe_user = val

	val, ok = rc.ConfigMap["nrpe_group"]
	if !ok {
		val = "nagios"
	}
	rc.Nrpe_group = val

	if val, ok := rc.ConfigMap["debug"]; ok {
		s, err := strconv.Atoi(val)
		if err != nil {
			return err
		}
		if s != 0 {
			rc.Debug = true
		} else {
			rc.Debug = false
		}
	} else {
		rc.Debug = false
	}

	if val, ok := rc.ConfigMap["dont_blame_nrpe"]; ok {
		s, err := strconv.Atoi(val)
		if err != nil {
			return err
		}
		if s != 0 {
			rc.CommandArgs = true
		} else {
			rc.CommandArgs = false
		}
	} else {
		rc.CommandArgs = false
	}

	val, ok = rc.ConfigMap["nasty_metachars"]
	if !ok {
		val = "|`&><'\\[]{};\r\n"
	}
	rc.NastyMetachars = val

	return nil
}

/* parse commands from config file and build a list of valid NrpeCommand */
func (rc *ReadConfig) ReadCommands() {
	for key, value := range rc.ConfigMap {
		if strings.HasPrefix(key, "command[") {
			init_str := strings.Index(key, "[")
			end_str := strings.Index(key, "]")
			cmd := common.BuildNrpeCommand(value)
			rc.AllowedCommands[key[init_str+1:end_str]] = &cmd
		}
	}
}

// TODO, for every option, loop through the ConfigMap? hm refactor it ASAP
func (rc *ReadConfig) ReadPrivileges() {
	for key, value := range rc.ConfigMap {
		switch key {
		case "nrpe_user":
			rc.Nrpe_user = value
		case "nrpe_group":
			rc.Nrpe_group = value
		}
	}
}

/*
	 check if command identified by cmd is referenced in list of allowed commands obtained from config file.
		return:
		  pointer to valid NrpeCommand if found
		  nil and "not found error" else.
*/
func (rc *ReadConfig) GetCommand(cmd string) (*common.NrpeCommand, error) {
	var val *common.NrpeCommand
	ok := false
	if val, ok = rc.AllowedCommands[cmd]; ok {
		return val, nil
	}
	return val, fmt.Errorf("command not found")
}

/* Parse allowed_hosts config line to obtain a list of IP and network that can be check on connection.
 */
func (rc *ReadConfig) ReadAllowedHosts() {
	ip_list, ok := rc.ConfigMap["allowed_hosts"]
	if !ok {
		ip_list = "127.0.0.1"
	}
	ip_lists := strings.Split(ip_list, ",")
	// rc.AllowedHosts = make([]*net.IPNet, len(ip_lists))
	for _, ip_str := range ip_lists {
		ip_str = strings.Trim(ip_str, " ")
		if !strings.Contains(ip_str, "\\") {
			if !strings.Contains(ip_str, ":") {
				ip_str = fmt.Sprintf("%s/32", ip_str)
			} else {
				ip_str = fmt.Sprintf("%s/64", ip_str)
			}
		}
		_, net, err := net.ParseCIDR(ip_str)
		if err == nil {
			rc.AllowedHosts = append(rc.AllowedHosts, net)
		}
	}
}

/*
check if ip is in allowed hosts
loop on all networks computed from allowed_hosts lists
checking if input ip address is contained in
return:

	true if found a valid network
	false else
*/
func (rc *ReadConfig) IsHostAllowed(ip net.IP) bool {
	res := false
	for _, network := range rc.AllowedHosts {
		if network.Contains(ip) {
			res = true
			break
		}
	}
	return res
}
