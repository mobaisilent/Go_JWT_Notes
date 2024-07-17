package main

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// 用于签名的字符串
var mySigningKey = []byte("secret")

// GenRegisteredClaims 使用默认声明创建jwt
func GenRegisteredClaims() (string, error) {
	// 创建 Claims
	claims := &jwt.RegisteredClaims{
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour * 24)), // 过期时间
		Issuer:    "mobai",                                            // 签发人
	}
	// 生成token对象
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	// 生成签名字符串
	return token.SignedString(mySigningKey)
}

// ParseRegisteredClaims 解析jwt
func ValidateRegisteredClaims(tokenString string) bool {
	// 解析token
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		return mySigningKey, nil
	})
	//fmt.Println(string(mySigningKey))
	fmt.Println("-----")
	fmt.Println(token)

	// 打印签名的Base64编码
	signature := base64.StdEncoding.EncodeToString(token.Signature)
	fmt.Println("Signature (Base64): ", signature)
	if err != nil { // 解析token失败
		return false
	}
	return token.Valid
	// i解析token是否有效
}

func main() {
	token, err := GenRegisteredClaims()
	if err != nil {
		fmt.Println("Error generating token: ", err)
		return
	}
	fmt.Println("Generated token:", token)

	valid := ValidateRegisteredClaims(token)
	fmt.Println("Is token valid:", valid)
}
