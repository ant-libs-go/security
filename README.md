# Security

security是一个简单的对称加密算法

[![License](https://img.shields.io/:license-apache%202-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![GoDoc](https://godoc.org/github.com/ant-libs-go/security?status.png)](http://godoc.org/github.com/ant-libs-go/security)
[![Go Report Card](https://goreportcard.com/badge/github.com/ant-libs-go/security)](https://goreportcard.com/report/github.com/ant-libs-go/security)

## 安装

	go get github.com/ant-libs-go/security

## 快速开始

```golang
key := "8dssword99.2020%"
rawStr := "abcdefghijklmnopqrstuvwxyz"

mgr := New(key)
encStr := mgr.Encode(rawStr)
decStr, _ := mgr.Decode(encStr)
```
