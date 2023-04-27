package main

import (
	"fmt"
	"strings"

	"net"
	"os"

	"github.com/canonical/nrped/common"
	"github.com/canonical/nrped/drop_privilege"
	"github.com/canonical/nrped/read_config"
	"github.com/droundy/goopt"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/prometheus/common/promlog"
	"github.com/spacemonkeygo/openssl"
)

var logger log.Logger

func main() {

	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s -h for help\n", os.Args[0])
		os.Exit(1)
	}

	config_file := goopt.String([]string{"-c", "--config"}, "nrpe.cfg",
		"config file to use")
	//the first option, will be the default, if the -m isnt given
	run_mode := goopt.Alternatives([]string{"-m", "--mode"},
		[]string{"foreground", "daemon", "systemd"}, "operating mode")
	goopt.Parse(nil)

	lvl := new(promlog.AllowedLevel)
	lvl.Set("info")
	logConfig := promlog.Config{
		Level: lvl,
	}
	logger = promlog.New(&logConfig)

	//implement different run modes..
	level.Info(logger).Log("msg", "config", "run_mode", *run_mode, "status", "not implemented!")

	level.Info(logger).Log("msg", "reading config file...")
	config_obj := new(read_config.ReadConfig)
	config_obj.Init(*config_file)
	err := config_obj.ReadConfigFile()
	if err != nil {
		level.Error(logger).Log("msg", err)
		os.Exit(1)
	}
	err = config_obj.ReadDefaultParamters()
	if err != nil {
		level.Error(logger).Log("msg", err)
		os.Exit(1)
	}

	if config_obj.Debug {
		lvl.Set("debug")
		logger = promlog.New(&logConfig)
	}

	level.Info(logger).Log("msg", "config", "debug", config_obj.Debug)
	service := net.JoinHostPort(config_obj.Server, config_obj.ServerPort)
	if config_obj.Server == "*" {
		service = net.JoinHostPort("0.0.0.0", config_obj.ServerPort)
	}
	level.Info(logger).Log("msg", "config", "listen", service)
	level.Info(logger).Log("msg", "config", "transport_mode", config_obj.TransportMode)

	level.Info(logger).Log("msg", "config", "nrpe_user", config_obj.Nrpe_user, "nrpe_group", config_obj.Nrpe_group)
	level.Info(logger).Log("msg", "config", "nasty_chars", config_obj.NastyMetachars)
	level.Info(logger).Log("msg", "config", "AllowCommandArgs", config_obj.CommandArgs)

	//extract the commands command[cmd_name] = "/bin/foobar"
	config_obj.ReadCommands()
	if config_obj.Debug {
		for cmd_name, cmd := range config_obj.AllowedCommands {
			level.Debug(logger).Log("msg", "config", "command", cmd_name, "params", strings.Join(append([]string{cmd.Name}, cmd.Args...), " "))
		}
	}
	config_obj.ReadAllowedHosts()
	if config_obj.Debug {
		for _, netw := range config_obj.AllowedHosts {
			level.Debug(logger).Log("msg", "config allow", "net", netw.String())
		}
	}

	// config_obj.ReadPrivileges()
	//TODO check for errors
	//what we gonna do with the group?
	pwd := drop_privilege.Getpwnam(config_obj.Nrpe_user)
	drop_privilege.DropPrivileges(int(pwd.Uid), int(pwd.Gid))
	err = setupSocket(service, config_obj)
	if err != nil {
		level.Error(logger).Log("msg", err)
		os.Exit(1)
	}
}

func setupSocket(service string, config_obj *read_config.ReadConfig) error {
	var listener net.Listener
	var err error

	switch config_obj.TransportMode {
	case 0:
		listener, err = net.Listen("tcp", service)
	case 1:
		var ctx *openssl.Ctx
		ctx, err = openssl.NewCtx()
		if err != nil {
			err = fmt.Errorf("error creating SSL context: %s", err)
			return err
		}
		// err = ctx.SetCipherList("ALL:!MD5:@STRENGTH")
		err = ctx.SetCipherList("ALL:!MD5:@STRENGTH:@SECLEVEL=0")
		if err != nil {
			err = fmt.Errorf("error setting SSL cipher list: %s", err)
			return err
		}
		listener, err = openssl.Listen("tcp", service, ctx)
	}

	if err != nil {
		return err
	}
	level.Info(logger).Log("msg", "nrped waiting for connection")

	for {
		if conn, err := listener.Accept(); err != nil {
			continue
		} else {
			// run as a goroutine
			go handleClient(conn, config_obj)
		}
	}

	return nil
}

func handleClient(conn net.Conn, config_obj *read_config.ReadConfig) {
	// close connection on exit
	defer conn.Close()

	level.Debug(logger).Log("msg", "new connection from", "ip", conn.RemoteAddr())
	if config_obj.IsHostAllowed(conn.RemoteAddr().(*net.TCPAddr).IP) {
		level.Debug(logger).Log("msg", "host is allowed list")
	} else {
		level.Warn(logger).Log("msg", "host is not allowed list")
		return
	}
	// if addr, ok := conn.RemoteAddr().(*net.TCPAddr); ok {
	// 	fmt.Println(addr.IP.String())
	// }
	pkt_rcv, err := common.ReceivePacket(conn)
	if err != nil {
		level.Error(logger).Log("msg", err)
		return
	}

	cmdline := pkt_rcv.GetCommandBuffer()

	pkt_rcv_crc32value := pkt_rcv.GetCRC32()

	if crc32, _ := pkt_rcv.DoCRC32(); crc32 != pkt_rcv_crc32value {
		level.Warn(logger).Log("msg", "CRC not matching", "crc32_received", pkt_rcv_crc32value, "crc32_computed", crc32)
		return
	}

	pkt_send, err := common.MakeNrpePacket("", common.RESPONSE_PACKET, int(pkt_rcv.Version()))
	if err != nil {
		level.Error(logger).Log("msg", err)
		os.Exit(common.STATE_UNKNOWN)
	}

	cmd := common.CommandLine2Cmd(cmdline)
	level.Debug(logger).Log("msg", "new query received", "command", cmd.Name, "params", strings.Join(cmd.Args, " "))
	if len(cmd.Args) > 0 && !config_obj.CommandArgs {
		level.Warn(logger).Log("msg", "command args are not allowed '(check dont_blame_nrpe config argument)'")
		pkt_send.SetResultCode(common.STATE_UNKNOWN)
		goto send_result
	}

	//its a response, but not to the HELLO_COMMAND
	if cmd.Name == common.HELLO_COMMAND {
		level.Debug(logger).Log("msg", "sending banner")
		pkt_send.SetCommand(common.PROGRAM_VERSION)
	} else if cmd.Name == common.EMPTY_COMMAND {
		level.Debug(logger).Log("msg", "sending banner")
		pkt_send.SetCommand(fmt.Sprintf("NRPED GO v%s", common.PROGRAM_VERSION))
	} else {
		cfg_cmd, err := config_obj.GetCommand(cmd.Name)
		if err != nil {
			level.Info(logger).Log("msg", "command not found", "command", cmd.Name)
			pkt_send.SetResultCode(common.STATE_UNKNOWN)
			goto send_result
		}
		return_id, return_stdout := cfg_cmd.Execute(cmd, config_obj.NastyMetachars, logger)
		pkt_send.SetResultCode(return_id)
		pkt_send.SetCommand(string(return_stdout))
	}

send_result:
	if err := pkt_send.PrepareToSend(common.RESPONSE_PACKET); err != nil {
		level.Error(logger).Log("msg", err)
	}

	err = pkt_send.SendPacket(conn)
	if err != nil {
		level.Error(logger).Log("msg", err)
	}
}
