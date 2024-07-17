> 参考链接：
> https://developer.aliyun.com/article/995894
>
> https://liwenzhou.com/posts/Go/json-web-token/#c-0-0-0
>
> https://www.ruanyifeng.com/blog/2018/07/json_web_token-tutorial.html

## 什么是JWT？

JWT全称JSON Web Token是一种跨域认证解决方案，属于一个开放的标准，它规定了一种Token 实现方式，目前多用于前后端分离项目和 OAuth2.0 业务场景下。

## 为什么需要JWT？

在之前的一些web项目中，我们通常使用的是`Cookie-Session`模式实现用户认证。相关流程大致如下：

1. 用户在浏览器端填写用户名和密码，并发送给服务端
2. 服务端对用户名和密码校验通过后会生成一份保存当前用户相关信息的session数据和一个与之对应的标识（通常称为session_id）
3. 服务端返回响应时将上一步的session_id写入用户浏览器的Cookie
4. 后续用户来自该浏览器的每次请求都会自动携带包含session_id的Cookie
5. 服务端通过请求中的session_id就能找到之前保存的该用户那份session数据，从而获取该用户的相关信息。

这种方案依赖于客户端（浏览器）保存 Cookie，并且需要在服务端存储用户的session数据。

在移动互联网时代，我们的用户可能使用浏览器也可能使用APP来访问我们的服务，我们的web应用可能是前后端分开部署在不同的端口，有时候我们还需要支持第三方登录，这下`Cookie-Session`的模式就有些力不从心了。

JWT就是一种基于Token的轻量级认证模式，服务端认证通过后，会生成一个JSON对象，经过签名后得到一个Token（令牌）再发回给用户，用户后续请求只需要带上这个Token，服务端解密之后就能获取该用户的相关信息了。

## 安装

仓库推荐：
>https://github.com/golang-jwt/jwt

安装：
```go
go get github.com/golang-jwt/jwt/v5
```

## 使用

### 默认Claim

> 使用默认字段快速生成Token

```go
package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// 用于签名的字符串:私钥
var mySigningKey = []byte("secret")

// GenRegisteredClaims 使用默认声明创建jwt
func GenRegisteredClaims() (string, error) {
	// 创建 Claims
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)), // 过期时间
		Issuer:    "mobai",                                            // 签发人
	}
	// 生成token对象
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)  // 加密方式和claims
	// 生成签名字符串
	return token.SignedString(mySigningKey)
}

// ParseRegisteredClaims 解析jwt
func ValidateRegisteredClaims(tokenString string) bool {
	// 解析token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return mySigningKey, nil
	})  // 要解析的token和回调函数
	//fmt.Println(string(mySigningKey))  
    fmt.Println(token) 
    // 查看全解析的token的姐u共	
	if err != nil { // 解析token失败
		return false
	}
	return token.Valid
    // 解析token是否有效
}

func main() {
	token, err := GenRegisteredClaims()
	if err != nil {
		fmt.Println("Error generating token: ", err)
		return
	}
	fmt.Println("Generated token:",token)

	valid := ValidateRegisteredClaims(token)
	fmt.Println("Is token valid:",valid)
}

```

>```go
>token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
>    return mySigningKey, nil
>})
>```
>
>解释如下：
>
>`jwt.Parse` 函数接收两个参数：一个是要解析的 token 字符串，另一个是一个回调函数，这个回调函数用于提供解析 token 所需的密钥。
>
>在这个例子中，`tokenString` 是要解析的 token 字符串，`mySigningKey` 是用于解析 token 的密钥。
>
>`jwt.Parse` 函数会返回两个值：一个是解析后的 token 对象，另一个是一个错误对象。如果解析过程中发生错误，错误对象会包含错误信息，否则它将是 `nil`。

### 自定义Claims

>我们需要定制自己的需求来决定JWT中保存哪些数据，比如我们规定在JWT中要存储`username`信息，那么我们就定义一个`CustomClaims`结构体如下：

示例代码：
```go
package main

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// CustomClaims 自定义声明类型 并内嵌jwt.RegisteredClaims
type CustomClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// CustomSecret 用于加盐的字符串
var CustomSecret = []byte("helloworld")

// TokenExpireDuration JWT的过期时间
const TokenExpireDuration = time.Hour * 24

// GenToken 生成JWT
func GenToken(username string) (string, error) {
	claims := CustomClaims{
		username,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(TokenExpireDuration)),
			Issuer:    "mobai",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(CustomSecret)
}

// ParseToken 解析JWT
func ParseToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) {
		return CustomSecret, nil
	})
	if err != nil {
		return nil, err
	}
	if claims, ok := token.Claims.(*CustomClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New("invalid token")
}

func main() {
	// 创建一个新的token
	tokenString, _ := GenToken("user")
	fmt.Println("Generated JWT: ", tokenString)

	// 验证并解析这个token
	claims, _ := ParseToken(tokenString)
	fmt.Println("Parsed JWT: ", claims)
}

```

> 自定义claims -> 生成JWT -> 解析JWT

输出结果如下：

```go
PS C:\Users\27892\Desktop\Golang\Deep_Learn_Pacages\JWT> go run test.go
Generated JWT:  eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InVzZXIiLCJpc3MiOiJteS1wcm9qZWN0IiwiZXhwIjoxNzIxMjgzNDI5fQ.fDwLjFIPF2RknyoUFXCDqc7XXbDhCsLd-xLMoMK11W8
Parsed JWT:  &{user {my-project  [] 2024-07-18 14:17:09 +0800 CST <nil> <nil> }}
```

## 在gin框架中使用JWT（核心）

示例代码：
```go

```

使用方式：

#### POST

> 传递POST的JSON数据给后端去生成对应的token

![image-20240717143221348](./images/image-20240717143221348.png)

发送的结构体：
```go
{
    "username": "q1mi",
    "password": "q1mi123"
}
```

接收的结果：
```go
{
    "code": 2000,
    "data": {
        "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6InExbWkiLCJpc3MiOiJtb2JhaSIsImV4cCI6MTcyMTI4NDI0OH0.YQqM_xapuymKeTMEXfGJIw7fEfQcl8t_MHDhqYtkU8Y"
    },
    "msg": "success"
}
```

#### GET

![image-20240717143324623](./images/image-20240717143324623.png)

设置好Bearer Token直接填入token然后就可以直接获取到之前的登录信息了
