# ca-example

这是一个关于CA、Server、Client之间关于颁发证书、验证证书、签名、加密通信的事例。

## 运行

~~~
// 启动CA
cd ./ca/cmd
go run main.go

// 启动服务端
cd ./server/cmd
go run main.go

// 启动客户端
cd ./client/cmd
go run main.go
~~~

## 运行时序图

![时序图](https://github.com/treeforest/ca-example/blob/main/ca.png)
