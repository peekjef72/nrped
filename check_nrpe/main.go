package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/canonical/nrped/common"
	"github.com/droundy/goopt"
	"github.com/spacemonkeygo/openssl"
)

func getSocket(transport_type int, endpoint string, tcpAddr *net.TCPAddr) (net.Conn, error) {
	switch transport_type {
	case 0:
		return net.DialTCP("tcp", nil, tcpAddr)
	case 1:
		var ctx *openssl.Ctx
		var conn net.Conn
		var err error
		ctx, err = openssl.NewCtx()
		if err != nil {
			err = fmt.Errorf("error creating SSL context: %s", err)
			return nil, err
		}
		// err = ctx.SetCipherList("ALL:!MD5:@STRENGTH")
		err = ctx.SetCipherList("ALL:!MD5:@STRENGTH:@SECLEVEL=0")
		if err != nil {
			err = fmt.Errorf("error setting SSL cipher list: %s", err)
			return nil, err
		}
		conn, err = openssl.Dial("tcp", endpoint, ctx, openssl.InsecureSkipHostVerification)
		if conn == (*openssl.Conn)(nil) || err != nil {
			err = fmt.Errorf("error dialing NRPE server: %s", err)
			return nil, err

		}
		return conn, nil
	case 3:
		conn, err := tls.Dial("tcp", endpoint,
			&tls.Config{
				InsecureSkipVerify: true,
			},
		)
		if err != nil {
			err = fmt.Errorf("error dialing NRPE server: %s", err)
			return conn, err
		}
		return conn, nil

	case 2:
		return nil, nil //implement it
	}
	return nil, nil
}

func prepareConnection(endpoint string, transport_type int) net.Conn {
	tcpAddr, err := net.ResolveTCPAddr("tcp4", endpoint)
	common.CheckError(err)
	conn, err := getSocket(transport_type, endpoint, tcpAddr)

	common.CheckError(err)

	if conn != nil {
		return conn
	}
	return nil
}

func main() {

	if len(os.Args) < 2 {
		fmt.Printf("%s -h for help\n", os.Args[0])
		os.Exit(1)
	}
	goopt.Description = func() string {
		return "Check nrpe go program to contact a NRPEDaemon."
	}
	goopt.Version = "0.0.3"
	goopt.Summary = "Check nrpe go program to contact a NRPEDaemon."

	var host = goopt.String([]string{"-H", "--host"}, "127.0.0.1", "The remote host running NRPE-Server")
	var port = goopt.Int([]string{"-p", "--port"}, 5666, "The remote port on which the NRPE-server listens")
	var transport = goopt.Int([]string{"-t", "--transport"}, 0, "Transport type: 0 - clear, 1 - ssl, 2 -ssh")
	var nrpe_version = goopt.Int([]string{"-n", "--nrpe_version"}, 4, "nrpe client packet version: 2, 3 or 4 (default)")
	var command = goopt.String([]string{"-c", "--command"}, "_NRPE_CHECK",
		"The check command defined in the nrpe.cfg file you would like to trigger. Default nrped version banner.")
	var arguments []string
	goopt.Parse(nil)
	if len(goopt.Args) > 0 {
		arguments = goopt.Args
	}
	service := net.JoinHostPort(*host, strconv.Itoa(*port))
	conn := prepareConnection(service, *transport)
	// close connection on exit
	defer conn.Close()

	// build nrpe command line with args base on human readable blank separated command and args
	cmd := common.NewNrpeCommand(*command, strings.Join(arguments, " "))
	if *nrpe_version < common.NRPE_PACKET_VERSION_1 || *nrpe_version > common.NRPE_PACKET_VERSION_4 {
		fmt.Println("invalid nrpe packet version")
		*nrpe_version = common.NRPE_PACKET_VERSION_4
	}
	// build nrpe packet
	pkt_to_send, err := common.MakeNrpePacket(cmd.ToCommandLine(), common.QUERY_PACKET, *nrpe_version)
	if err != nil {
		fmt.Printf("Error: '%s'\n", err)
		os.Exit(common.STATE_UNKNOWN)
	}

	if err := pkt_to_send.PrepareToSend(common.QUERY_PACKET); err != nil {
		fmt.Printf("Error: '%s'\n", err)
		os.Exit(common.STATE_UNKNOWN)
	}

	err = pkt_to_send.SendPacket(conn)
	common.CheckError(err)
	response_from_command, err := common.ReceivePacket(conn)
	if err != nil {
		fmt.Printf("Error: '%s'\n", err)
		os.Exit(common.STATE_UNKNOWN)
	} else {
		fmt.Println(response_from_command.GetCommandBuffer())
	}
	// fmt.Printf("return code: %s", common.MessageState(response_from_command.ResultCode()))
	os.Exit(response_from_command.ResultCode())
}
