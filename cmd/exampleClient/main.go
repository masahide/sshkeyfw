package main

import (
	"bytes"
	"log"
	"os"

	"github.com/kelseyhightower/envconfig"
	"github.com/masahide/sshkeyfw"
)

type params struct {
	sshkeyfw.SSHKeyfw
	Host    string `default:"localhost:22"`
	SSHUser string
	Command string
}

var p params

func init() {
	log.SetFlags(log.Lshortfile | log.LstdFlags)
	err := envconfig.Process("", &p)
	if err != nil {
		log.Fatal(err.Error())
	}
	if len(p.Command) == 0 {
		envconfig.Usage("", &p)
		os.Exit(1)
	}
}

func main() {
	s := &p.SSHKeyfw
	err := s.Connect(p.Host, p.SSHUser)
	if err != nil {
		log.Fatalf("%+v", err)
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	err = s.Run(p.Command, stdout, stderr, nil)
	if err != nil {
		log.Fatalf("%+v", err)
	}
	log.Printf("stdout:%s", stdout)
	log.Printf("stderr:%s", stderr)
}
