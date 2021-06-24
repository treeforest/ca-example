package client

import (
	"bytes"
	"github.com/treeforest/ca-example/tools"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io/ioutil"
	"net/http"
)

type Client struct {
	privKey         *rsa.PrivateKey
	srvCert         *x509.Certificate
	srvCertAsn1Data []byte
	httpClient      *http.Client
}

func NewClient() *Client {
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	tools.WriteToFile("client-key.pem", "PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privKey))

	return &Client{
		privKey:    privKey,
		httpClient: &http.Client{},
	}
}

// GetServerCertificate 获取服务端的证书
func (c *Client) GetServerCertificate() error {
	// 发起http请求
	req, _ := http.NewRequest("GET", "http://0.0.0.0:20001", bytes.NewBuffer([]byte("")))
	req.Header.Set("cmd", "get-cert")
	resp, _ := c.httpClient.Do(req)

	// 获取到返回的数据
	certAsn1Data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	c.srvCertAsn1Data = certAsn1Data
	c.srvCert, _ = x509.ParseCertificate(certAsn1Data)
	tools.WriteToFile("server-cert.pem", "SERVER CERTIFICATE", certAsn1Data)
	return nil
}

// CheckServerCertificateFromCA 向CA验证获取到的服务端证书
func (c *Client) CheckServerCertificateFromCA() bool {
	// 发起http请求
	req, _ := http.NewRequest("POST", "http://0.0.0.0:20000", bytes.NewBuffer(c.srvCertAsn1Data))
	req.Header.Set("cmd", "check")
	resp, _ := c.httpClient.Do(req)

	// 获取到返回的数据
	ok, _ := ioutil.ReadAll(resp.Body)

	return string(ok) == "success"
}

// SignByServer 请求服务端对msg进行签名
func (c *Client) SignByServer(msg []byte) (signature []byte) {
	req, _ := http.NewRequest("POST", "http://0.0.0.0:20001", bytes.NewBuffer(msg))
	req.Header.Set("cmd", "sign")
	resp, _ := c.httpClient.Do(req)
	signature, _ = ioutil.ReadAll(resp.Body)
	return
}

func (c *Client) VerifyServerSignature(signed, signature []byte) bool {
	return c.srvCert.CheckSignature(x509.SHA256WithRSA, signed, signature) == nil
}
