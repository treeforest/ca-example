package ca

import (
	"github.com/treeforest/ca-example/tools"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"time"
)

// CA 证书颁发机构
type CA struct {
	privKey *rsa.PrivateKey
	cert    *x509.Certificate
}

// NewCA 初始化一个自签名的CA
func NewCA() *CA {
	// 创建CA的RSA格式的私钥
	privkey, _ := rsa.GenerateKey(rand.Reader, 2048)

	// 创建证书模板
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1653),
		Subject:               pkix.Name{Country: []string{"CN"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	// 根据证书模板得到自签名的证书
	certAsn1Data, _ := x509.CreateCertificate(rand.Reader, template, template, &privkey.PublicKey, privkey)

	// MarshalPKCS1PrivateKey 将私钥装换成PKCS #1, ASN.1 DER编码的字节格式， 便于输出到文件
	// cert 是 ASN.1 编码的格式
	tools.WriteToFile("ca-key.pem", "PRIVATE KEY", x509.MarshalPKCS1PrivateKey(privkey))
	tools.WriteToFile("ca-cert.pem", "CERTIFICATE", certAsn1Data)

	cert, _ := x509.ParseCertificate(certAsn1Data)

	return &CA{
		privKey: privkey,
		cert:    cert,
	}
}

// Serve 启动ca的http服务
func (ca *CA) Serve() error {
	lis, err := net.Listen("tcp", "0.0.0.0:20000")
	if err != nil {
		log.Fatal("Failed to listen tcp")
	}

	log.Println("CA service start...")
	log.Println("address: ", lis.Addr().String())
	return http.Serve(lis, ca)
}

func (ca *CA) ServeHTTP(resp http.ResponseWriter, req *http.Request) {
	body, err := ioutil.ReadAll(req.Body)
	if err != nil {
		log.Fatal("Failed to read request message")
	}

	cmd := req.Header.Get("cmd")
	switch cmd {
	case "issue":
		log.Printf("接收到来自 %s 证书签名请求...", req.RemoteAddr)
		csr, err := x509.ParseCertificateRequest(body)
		if err != nil {
			log.Fatal("Failed to parse csr")
		}
		cert, err := ca.IssueCertificate(csr)
		if err != nil {
			log.Println("签名失败...")
		}
		log.Printf("签名成功，并返回给 %s", req.RemoteAddr)
		resp.Header().Set("cmd", "issue-resp")
		resp.Write(cert)

	case "check":
		log.Printf("接收到来自 %s 的证书校验请求...", req.RemoteAddr)
		cert, err := x509.ParseCertificate(body)
		if err != nil {
			log.Fatal("Failed to parse child's certificate")
		}

		var result string = "success"
		err = cert.CheckSignatureFrom(ca.cert)
		if err != nil {
			result = "failed"
		}

		log.Printf("签名校验结果： %s", result)

		resp.Header().Set("cmd", "check-resp")
		resp.Write([]byte(result))

	default:
		resp.Header().Set("cmd", "error")
		resp.Write([]byte("Cmd is invalid"))
	}
}

// IssueCertificate 颁发证书
func (ca *CA) IssueCertificate(csr *x509.CertificateRequest) ([]byte, error) {
	// 校验证书中的国家代码必须是 CN, 实现校验过程
	if csr.Subject.Country[0] != "CN" {
		return nil, errors.New("The country must be CN")
	}

	// 根据证书请求csr组建证书格式
	template := &x509.Certificate{
		Subject:            csr.Subject,
		PublicKeyAlgorithm: csr.PublicKeyAlgorithm,
		PublicKey:          csr.PublicKey,
		SerialNumber:       big.NewInt(time.Now().UnixNano()),
		SignatureAlgorithm: x509.SHA256WithRSA,
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(time.Hour * 24 * 30), // one month
		KeyUsage:           x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:        []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
	}

	// ca 使用自己的私钥与证书对证书进行签名
	clientCert, _ := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.privKey)

	return clientCert, nil
}

// CheckSignature 检查证书的签名是否由该CA签署
func (ca *CA) CheckSignature(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(ca.cert) == nil
}
