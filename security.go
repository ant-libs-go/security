/* ######################################################################
# Author: (zfly1207@126.com)
# Created Time: 2020-08-04 12:36:40
# File Name: security.go
# Description:
####################################################################### */

package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"encoding/base64"
	"errors"
	"fmt"

	"github.com/ant-libs-go/util"
)

type Security struct {
	key      string
	hmacSize int
	cipher   cipher.Block
}

func New(key string) *Security {
	o := &Security{}
	o.key = key
	o.hmacSize = 10

	var err error
	if o.cipher, err = aes.NewCipher([]byte(key[:aes.BlockSize])); err != nil {
		panic(err.Error())
	}
	return o
}

func (this Security) Encode(data string) (r string) {
	d1 := this.encrypt(this.PKCS7Pad([]byte(data)))
	d2 := this.urlsafe_encode(d1)
	return this.hashData(d2)
}

func (this Security) Decode(data string) (string, error) {
	d1, err := this.validateData(data)
	if err != nil {
		return "", err
	}
	d2, err := this.urlsafe_decode(d1)
	if err != nil {
		return "", err
	}
	d3 := this.PKCS7UPad(this.decrypt(d2))
	return string(d3), nil
}

func (this Security) encrypt(plaintext []byte) []byte {
	if len(plaintext)%aes.BlockSize != 0 {
		panic("Need a multiple of the blocksize 16")
	}

	ciphertext := make([]byte, 0)
	text := make([]byte, 16)
	for len(plaintext) > 0 {
		this.cipher.Encrypt(text, plaintext)
		plaintext = plaintext[aes.BlockSize:]
		ciphertext = append(ciphertext, text...)
	}
	return ciphertext
}

func (this Security) decrypt(ciphertext []byte) []byte {
	if len(ciphertext)%aes.BlockSize != 0 {
		panic("Need a multiple of the blocksize 16")
	}

	plaintext := make([]byte, 0)
	text := make([]byte, 16)
	for len(ciphertext) > 0 {
		this.cipher.Decrypt(text, ciphertext)
		ciphertext = ciphertext[aes.BlockSize:]
		plaintext = append(plaintext, text...)
	}
	return plaintext
}

func (this Security) PKCS7Pad(data []byte) []byte {
	padLength := aes.BlockSize - len(data)%aes.BlockSize
	for i := 0; i < padLength; i++ {
		data = append(data, byte(padLength))
	}
	return data
}

func (this Security) PKCS7UPad(data []byte) []byte {
	padLength := int(data[len(data)-1])
	return data[:len(data)-padLength]
}

func (this Security) urlsafe_encode(data []byte) string {
	buf := make([]byte, base64.StdEncoding.EncodedLen(len(data)))
	base64.StdEncoding.Encode(buf, data)

	// str = strings.Replace(str, "+", "-", -1)
	// str = strings.Replace(str, "/", "_", -1)
	// str = strings.Replace(str, "=", ".", -1)

	b := util.BytesReplace(buf, []byte{43}, []byte{45}, -1)
	b = util.BytesReplace(b, []byte{47}, []byte{95}, -1)
	b = util.BytesReplace(b, []byte{61}, []byte{46}, -1)
	return string(b)
}

func (this Security) urlsafe_decode(str string) (data []byte, err error) {
	// str = strings.Replace(str, "-", "+", -1)
	// str = strings.Replace(str, "_", "/", -1)
	// str = strings.Replace(str, ".", "=", -1)

	b := util.BytesReplace([]byte(str), []byte{45}, []byte{43}, -1)
	b = util.BytesReplace(b, []byte{95}, []byte{47}, -1)
	b = util.BytesReplace(b, []byte{46}, []byte{61}, -1)

	var n int
	buf := make([]byte, base64.StdEncoding.DecodedLen(len(str)))
	n, err = base64.StdEncoding.Decode(buf, b)
	return buf[:n], err
}

func (this Security) hashData(data string) string {
	return this.computeHMAC(data) + data
}

func (this Security) validateData(data string) (string, error) {
	if len(data) > this.hmacSize && len(this.key) > 0 &&
		data[:this.hmacSize] == this.computeHMAC(data[this.hmacSize:]) {
		return data[this.hmacSize:], nil
	} else {
		return "", errors.New("validateData error")
	}
}

func (this Security) computeHMAC(data string) string {
	md5_sum := fmt.Sprintf("%x", md5.Sum([]byte(data+this.key)))
	return md5_sum[:this.hmacSize]
}
