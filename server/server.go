package server

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"github.com/treeforest/ca-example/tools"
)

// Server 服务器
type Server struct {
	privKey      *rsa.PrivateKey
	cert         *x509.Certificate
	certAsn1Data []byte
	httpClient   *http.Client
}

func NewServer() *Server {
	// 生成2048位的私钥
	privKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	s := &Server{privKey: privKey, httpClient: &http.Client{}}
	tools.WriteToFile("server-key.pem", "PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privKey))
	log.Println("RSA私钥生成并写入到 server-key.pem...")
	return s
}

// Serve 启动http服务
func (s *Server) Serve() error {
	lis, err := net.Listen("tcp", "0.0.0.0:20001")
	if err != nil {
		log.Fatal("Failed to listen tcp")
	}

	return http.Serve(lis, s)
}

func (s *Server) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Fatal("Failed to read request message")
	}

	cmd := req.Header.Get("cmd")
	switch cmd {
	case "get-cert":
		log.Printf("收到来自 %s 的获取证书请求", req.RemoteAddr)
		resp.Write(s.certAsn1Data)
	case "sign":
		log.Printf("收到来自 %s 的签名请求", req.RemoteAddr)
		digest := sha256.Sum256(body)
		signData, _ := s.privKey.Sign(rand.Reader, digest[:], crypto.SHA256)
		resp.Write(signData)
	default:
		log.Printf("收到来自 %s 的非法命令：%s", req.RemoteAddr, cmd)
	}
}

// GetCertificateFromCA 获取由CA颁发的证书。向CA发起证书请求，CA验证后颁发证书
func (s *Server) GetCertificateFromCA() error {
	csrTemplate := &x509.CertificateRequest{
		Signature: []byte("zut"),
		Subject: pkix.Name{
			Country:            []string{"CN"},
			Organization:       []string{"zut"},
			OrganizationalUnit: []string{"unit"},
			CommonName:         "zut",
		},
		SignatureAlgorithm: x509.SHA256WithRSA,
	}

	// 私钥用于对CSR签名，以及将私钥对应的公钥写入到CSR中
	csrAsnaData, err := x509.CreateCertificateRequest(rand.Reader, csrTemplate, s.privKey)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to create certificate request: %v", err))
	}

	log.Println("创建证书签名请求 CSR 成功...")

	// 向ca发起http请求
	req, _ := http.NewRequest("POST", "http://0.0.0.0:20000", bytes.NewBuffer(csrAsnaData))
	req.Header.Set("cmd", "issue")
	resp, _ := s.httpClient.Do(req)

	// 解析asn1编码的证书
	certAsn1Data, _ := ioutil.ReadAll(resp.Body)
	cert, err := x509.ParseCertificate(certAsn1Data)
	if err != nil {
		return errors.New(fmt.Sprintf("Failed to parse certificate: %v", err))
	}

	log.Println("证书请求由CA签名成功...")

	s.certAsn1Data = certAsn1Data
	s.cert = cert
	tools.WriteToFile("server-cert.pem", "CERTIFICATE", certAsn1Data)
	tools.WriteToJsonFile("server-cert.json", cert)
	log.Println("证书文件写入 server-cert.pem server-cert.json...")

	return nil
}
