package main

import (
	"github.com/treeforest/ca-example/client"
	"log"
)

func main() {
	cli := client.NewClient()

	log.Println("开始获取服务端证书")
	if err := cli.GetServerCertificate(); err != nil {
		log.Fatal("Failed to get server's certificate: ", err)
	}
	log.Println("获取服务端证书成功")

	log.Println("开始向CA请求校验服务端证书")
	if ok := cli.CheckServerCertificateFromCA(); !ok {
		log.Fatal("Failed to check server's certificate")
	}
	log.Println("向CA校验服务端证书通过")

	signed := []byte("Hello World!")
	log.Printf("请求服务端对 %s 的签名", signed)

	signature := cli.SignByServer(signed)
	log.Printf("获取到服务端返回的签名值：%X", signature)

	log.Println("本地使用服务端证书验证签名值：", cli.VerifyServerSignature(signed, signature))
}
