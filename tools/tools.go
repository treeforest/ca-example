package tools

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io/ioutil"
)

func WriteToFile(filename, typ string, data []byte) {
	block := pem.Block{
		Type: typ,
		Bytes: data,
	}

	ioutil.WriteFile(filename, pem.EncodeToMemory(&block), 0777)
}

func WriteToJsonFile(filename string, cert *x509.Certificate) {
	jsonData, _ := json.MarshalIndent(cert, "", "\t")
	ioutil.WriteFile(filename, jsonData, 0777)
}