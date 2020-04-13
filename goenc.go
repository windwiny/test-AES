// asdf.go
package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
)

var debug bool
var en bool
var ciphername, mode string
var key, iv []byte

func init() {
	flag.BoolVar(&debug, "debug", false, "DEBUG mode")

	flag.StringVar(&ciphername, "enc", "AES", "ciphername AES|DES")
	flag.StringVar(&mode, "mode", "OFB", "cipher mode CFB|CTR|OFB")
	flag.BoolVar(&en, "e", true, "true encrypt or false decrypt")
	var key2, iv2 string
	flag.StringVar(&key2, "key", "", "Key to use, specified as a hexadecimal string, 16|24|32 byte")
	flag.StringVar(&iv2, "iv", "", "IV to use, specified as a hexadecimal string, 16 byte")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(),
			"Usage:\n"+
				" %s -e -enc AES -mode CFB -key 1234567890abcdef -iv 9876543210ABCDEF file_name \n"+
				" Read STDIN and Write STDOUT\n",
			os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	switch ciphername {
	case "AES", "DES":
	default:
		fmt.Fprintf(os.Stderr, "cipher support AES/DES, unknow \"%s\"\n", ciphername)
		os.Exit(1)
	}

	switch mode {
	case "CBC", "CFB", "CTR", "OFB":
	default:
		fmt.Fprintf(os.Stderr, "cipher mode support CBC|CFB|CTR|OFB, unknow \"%s\"\n", mode)
		os.Exit(1)
	}

	var err error
	key, err = hex.DecodeString(key2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "key not hexadecimal string\n")
		os.Exit(1)
	}
	switch len(key) {
	case 16, 24, 32:
	default:
		fmt.Fprintf(os.Stderr, "key size not 16/24/32 byte, is [%d]\n", len(key))
		os.Exit(1)
	}

	iv, err = hex.DecodeString(iv2)
	if err != nil {
		fmt.Fprintf(os.Stderr, "iv not hexadecimal string\n")
		os.Exit(1)
	}
	switch len(iv) {
	case 16:
	default:
		fmt.Fprintf(os.Stderr, "iv size not 16 byte, is [%d]\n", len(iv))
		os.Exit(1)
	}

	if !debug {
		for _, v := range os.Environ() {
			v := strings.ToUpper(v)
			if strings.HasPrefix(v, "DEBUG=") && !strings.HasPrefix(v, "DEBUG=0") && !strings.HasPrefix(v, "DEBUG=FALSE") {
				debug = true
			}
		}
	}
	if debug {
		fmt.Fprintf(os.Stderr, " Args:\n"+
			"  debug:[%v]  encrypt?:[%v]  enc:[%v]  mode:[%v]\n"+
			"  key: %v\n"+
			"  iv: %v\n\n",
			debug, en, ciphername, mode, key, iv)
	}
}

func main() {
	// dst := new(strings.Builder)
	len_in, len_out, err := DoEnc(ciphername, mode, en, key, iv, os.Stdin, os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(2)
	}
	if debug {
		fmt.Fprintf(os.Stderr, "key:%q iv:%q src len:%d dst len:%d\n", string(key), string(iv), len_in, len_out)
	}
	// fmt.Printf("%s", dst.String())
}

func DoEnc(ciphername, mode string, en bool, key, iv []byte, in io.Reader, out io.Writer) (len_in, len_out int, err error) {
	var blk cipher.Block

	switch ciphername {
	case "AES":
		blk, err = aes.NewCipher(key)
	case "DES":
		blk, err = des.NewCipher(key)
	default:
		err = fmt.Errorf("not support \"%s\" cipher\n", ciphername)
		return
	}

	if err != nil {
		err = fmt.Errorf("err in aes.NewCipher %q\n", err)
		return
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
		err = fmt.Errorf("not support \"%s\" mode\n", mode)
		return
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
