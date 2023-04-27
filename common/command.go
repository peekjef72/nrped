package common

import (
	"bufio"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
)

// Command represents command name and argument list
type NrpeCommand struct {
	Name string
	Args []string
}

// NewCommand creates Command object with the given name and optional argument list
func NewNrpeCommand(name string, args ...string) NrpeCommand {
	return NrpeCommand{
		Name: name,
		Args: args,
	}
}

// toStatusLine convers Command content to a formated string ready to send to nrped (args separated by !)
func (c *NrpeCommand) ToCommandLine() string {
	if c.Args != nil && len(c.Args) > 0 {
		args := strings.Join(c.Args, "!")
		return c.Name + "!" + args
	}

	return c.Name
}

// convert NrpeCommand to human readable string
func (cmd *NrpeCommand) ToString() string {
	return strings.Join(append([]string{cmd.Name}, cmd.Args...), " ")
}

/*
	 Execute the command send as object with parameters from cmd_params.
	   Convert $ARGx$ from caller to value from cmd_params.args[x] if it exists.
	   Nasty_chars are checked on each parameter: if some found return message and critical status to querier.
	   return:
	    * uint16: exit status from command execution STATUS_OK, STATUS_WARNING, STATUS_CRITICAL, STATUS_UNKNOWN
		*[]byte: content of stdout.
*/
func (c *NrpeCommand) Execute(cmd_params *NrpeCommand, nasty_chars string, logger log.Logger) (int16, []byte) {
	cmd := NrpeCommand{
		Name: c.Name,
	}
	cmd.Args = make([]string, len(c.Args))
	// have to substitute $ARGx$ with command parameter x if it exists!
	regex := *regexp.MustCompile(`^\$ARG(\d+)\$$`)

	if len(c.Args) > 0 {
		for i := range c.Args {
			res := regex.FindStringSubmatch(c.Args[i])
			if len(res) > 0 {
				if arg_num, err := strconv.Atoi(res[1]); err == nil {
					if arg_num >= 1 && arg_num <= len(c.Args) {
						if arg_num <= len(cmd_params.Args) {
							cmd.Args[i] = cmd_params.Args[arg_num-1]
						} else {
							cmd.Args[i] = ""
						}
					}
				}
			} else {
				cmd.Args[i] = c.Args[i]
			}
			if strings.ContainsAny(cmd.Args[i], nasty_chars) {
				if logger != nil {
					level.Debug(logger).Log("msg", "command parameter contains nasty chars", "index", i, "param", cmd.Args[i])
				}
				return STATE_CRITICAL, []byte("nasty chars found")
			}
		}
		// well... it seems that if Args[x] contains several args ("-w5% -c3%") command exec doesn't understand these 2 params!!
		// have to join all parts then split again !
		args := strings.Join(cmd.Args, " ")
		cmd.Args = strings.Fields(args)
	}

	cmdLine := exec.Command(cmd.Name, cmd.Args...)
	if logger != nil {
		level.Debug(logger).Log("msg", "will launch command", "cmd", strings.Join(cmdLine.Args, " "))
	}
	cmd_stdout, _ := cmdLine.StdoutPipe()
	if err := cmdLine.Start(); err != nil {
		return int16(2), []byte(fmt.Sprintf("%s", err))
	}
	stdout_reader := bufio.NewReader(cmd_stdout)
	read_line, _, _ := stdout_reader.ReadLine()
	result := cmdLine.Wait()
	status := 0
	if result != nil {
		status = result.(*exec.ExitError).ProcessState.Sys().(syscall.WaitStatus).ExitStatus()
	}
	if logger != nil {
		level.Debug(logger).Log("msg", "command execute successfully", "exit_code", status, "stdout", read_line)
	}
	return int16(status), read_line
}

/*
	 build a NrpeCommand from a command line sent by a nrpe query.
	   args are separated by rune '!'
	   return:
		NrpeCommand
*/
func CommandLine2Cmd(cmdline string) *NrpeCommand {
	var cmd NrpeCommand
	elmts := strings.Split(cmdline, "!")
	if len(elmts) > 1 {
		cmd = NewNrpeCommand(elmts[0], elmts[1:]...)
	} else {
		cmd = NewNrpeCommand(elmts[0])
	}
	return &cmd
}

/*
	 build a NrpeCommand from a command line in human readable format (space separated).
	   return:
		NrpeCommand
*/
func BuildNrpeCommand(command string) NrpeCommand {
	var cmd NrpeCommand

	elmts := strings.Fields(command)

	if len(elmts) > 1 {
		cmd = NewNrpeCommand(elmts[0], elmts[1:]...)
	} else {
		cmd = NewNrpeCommand(elmts[0])
	}
	return cmd
}
