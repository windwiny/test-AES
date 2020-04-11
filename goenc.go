// asdf.go
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

var debug bool
var en bool
var ciphername, mode, key, iv string

func init() {
	flag.BoolVar(&debug, "debug", false, "DEBUG mode")

	flag.StringVar(&ciphername, "enc", "AES", "ciphername AES|DES")
	flag.StringVar(&mode, "mode", "OFB", "cipher mode CFB|CTR|OFB")
	flag.BoolVar(&en, "e", true, "true encrypt or false decrypt")
	flag.StringVar(&key, "key", "", "Key= 16|24|32 bytes")
	flag.StringVar(&iv, "iv", "", "IV= 16 bytes")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"Usage:\n"+
				" %s -e -enc AES -mode CFB -key 1234567890abcdef -iv 9876543210ABCDEF file_name \n"+
				" Read STDIN and Write STDOUT\n",
			os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()
	if !debug {
		for _, v := range os.Environ() {
			v := strings.ToUpper(v)
			if strings.HasPrefix(v, "DEBUG=") && !strings.HasPrefix(v, "DEBUG=0") && !strings.HasPrefix(v, "DEBUG=FALSE") {
				debug = true
			}
		}
	}
	if debug {
		fmt.Fprintf(os.Stderr, ` Args:
  debug %v
  encrypt? %v
  enc %v
  mode %v
  key %v
  iv %v

`, debug, en, ciphername, mode, key, iv)
	}

	switch len([]byte(key)) {
	case 16, 24, 32:
	default:
		fmt.Fprintf(os.Stderr, "key size not 16/24/32 bytes\n")
		os.Exit(1)
	}
	switch len([]byte(iv)) {
	case 16:
	default:
		fmt.Fprintf(os.Stderr, "iv size not 16 bytes\n")
		os.Exit(1)
	}
	switch ciphername {
	case "AES", "DES":
	default:
		fmt.Fprintf(os.Stderr, "cipher support AES/DES, unknow \"%s\"\n", ciphername)
		os.Exit(1)
	}
	switch mode {
	case "CBC", "CFB", "CTR", "OFB":
	default:
		fmt.Fprintf(os.Stderr, "cipher mode support CBC|CFB|CTR|OFB, unkonow \"%s\"\n", mode)
		os.Exit(1)
	}

}

func main() {
	// dst := new(strings.Builder)
	len_in, len_out := DoEnc(ciphername, mode, en, []byte(key), []byte(iv), os.Stdin, os.Stdout)
	if debug {
		fmt.Fprintf(os.Stderr, "key:%q iv:%q src len:%d dst len:%d\n", string(key), string(iv), len_in, len_out)
	}
	// fmt.Printf("%s", dst.String())
}

func DoEnc(ciphername, mode string, en bool, key, iv []byte, in io.Reader, out io.Writer) (len_in, len_out int) {
	var blk cipher.Block
	var err error

	switch ciphername {
	case "AES":
		blk, err = aes.NewCipher(key)
	case "DES":
		blk, err = des.NewCipher(key)
	default:
		fmt.Fprintf(os.Stderr, "not support \"%s\" cipher\n", ciphername)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "err in aes.NewCipher %q\n", err)
	}

	var blkmode cipher.BlockMode
	var stream cipher.Stream
	switch mode {
	// case "CBC":
	// 	if en {
	// 		blkmode = cipher.NewCBCEncrypter(blk, iv)
	// 	} else {
	// 		blkmode = cipher.NewCBCDecrypter(blk, iv)
	// 	}
	case "CFB":
		if en {
			stream = cipher.NewCFBEncrypter(blk, iv)
		} else {
			stream = cipher.NewCFBDecrypter(blk, iv)
		}
	case "CTR":
		stream = cipher.NewCTR(blk, iv)
	case "OFB":
		stream = cipher.NewOFB(blk, iv)
	default:
		fmt.Fprintf(os.Stderr, "not support \"%s\" mode\n", mode)
		os.Exit(1)
	}
	_ = stream
	_ = blkmode
	ii := bufio.NewReader(in)
	lll := 10240 // read buffer size
	msg := make([]byte, lll)
	dst := make([]byte, lll)

	omsg := bufio.NewWriter(out)
	defer omsg.Flush()
	for {
		l1, err := ii.Read(msg)
		if err == io.EOF {
			break
		}
		len_in += l1
		msg = msg[:l1]
		dst = dst[:l1]
		stream.XORKeyStream(dst, msg)
		l2, _ := omsg.Write(dst)
		len_out += l2
	}
	return
}
