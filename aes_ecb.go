/* ######################################################################
# Author: (zfly1207@126.com)
# Created Time: 2020-08-04 10:53:10
# File Name: aes_ecb.go
# Description:
####################################################################### */

package security

import (
	"bytes"
	"crypto/aes"
	"errors"
	"fmt"
)

type PADDING int

const (
	ZERO_PADDING  PADDING = 1
	PKCS5_PADDING PADDING = 2
	PKCS7_PADDING PADDING = 3
)

type AesEcb struct {
	BlockSize   int
	PaddingType PADDING
}

func NewAesEcb(blockSize int, paddingType PADDING) (*AesEcb, error) {
	if blockSize != 16 && blockSize != 24 && blockSize != 32 {
		return nil, fmt.Errorf("key size is not 16 or 24 or 32, but %d", blockSize)
	}

	ae := &AesEcb{BlockSize: blockSize, PaddingType: paddingType}
	return ae, nil
}

func (ae AesEcb) Encrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:ae.BlockSize])
	if err != nil {
		return nil, err
	}

	switch ae.PaddingType {
	case ZERO_PADDING:
		plaintext = ae.ZeroPadding(plaintext, aes.BlockSize)
	case PKCS5_PADDING:
		plaintext = ae.PKCS5Padding(plaintext, aes.BlockSize)
	case PKCS7_PADDING:
		plaintext = ae.PKCS7Padding(plaintext, aes.BlockSize)
	}

	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext is not a multiple of the block size")
	}

	ciphertext := make([]byte, 0, len(plaintext))
	tmpData := make([]byte, aes.BlockSize)
	//分组分块加密
	for index := 0; index < len(plaintext); index += aes.BlockSize {
		block.Encrypt(tmpData, plaintext[index:index+aes.BlockSize])
		ciphertext = append(ciphertext, tmpData...)
	}
	return ciphertext, nil
}

func (ae AesEcb) Decrypt(key, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:ae.BlockSize])
	if err != nil {
		return nil, err
	}

	if len(plaintext) < aes.BlockSize {
		return nil, errors.New("plaintext too short")
	}

	if len(plaintext)%aes.BlockSize != 0 {
		return nil, errors.New("plaintext is not a multiple of the block size")
	}

	decryptData := make([]byte, 0, len(plaintext))
	tmpData := make([]byte, aes.BlockSize)
	for index := 0; index < len(plaintext); index += aes.BlockSize {
		block.Decrypt(tmpData, plaintext[index:index+aes.BlockSize])
		decryptData = append(decryptData, tmpData...)
	}

	switch ae.PaddingType {
	case ZERO_PADDING:
		decryptData = ae.ZeroUnPadding(decryptData)
	case PKCS5_PADDING:
		decryptData = ae.PKCS5UnPadding(decryptData)
	case PKCS7_PADDING:
		decryptData = ae.PKCS7UnPadding(decryptData)
	}
	return decryptData, nil
}

func (ae AesEcb) ZeroPadding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{0}, padding)
	return append(ciphertext, padtext...)
}

func (ae AesEcb) ZeroUnPadding(originData []byte) []byte {
	return bytes.TrimRightFunc(originData, func(r rune) bool {
		return r == rune(0)
	})
}

func (ae AesEcb) PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func (ae AesEcb) PKCS5UnPadding(originData []byte) []byte {
	length := len(originData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(originData[length-1])
	return originData[:(length - unpadding)]
}

func (ae AesEcb) PKCS7Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	for i := 0; i < padding; i++ {
		ciphertext = append(ciphertext, byte(padding))
	}
	return ciphertext
}

func (ae AesEcb) PKCS7UnPadding(originData []byte) []byte {
	length := len(originData)
	// 去掉最后一个字节 unpadding 次
	unpadding := int(originData[length-1])
	return originData[:(length - unpadding)]
}
