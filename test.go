package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

// 导入gin和jwt包

type UserInfo struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// 创建信息结构体：使用JSON标签

type CustomClaims struct {
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// 创建自定义JWT结构体

var CustomSecret = []byte("helloworld") //创建签名字符串

const TokenExpireDuration = time.Hour * 24 // 设定token过期时间

func GenToken(username string) (string, error) {
	claims := CustomClaims{
		username,
		jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(TokenExpireDuration)),
			Issuer:    "mobai",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims) // 使用HS256和claims生成token值
	return token.SignedString(CustomSecret)
}

// 验证token
func ParseToken(tokenString string) (*CustomClaims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &CustomClaims{}, func(token *jwt.Token) (interface{}, error) { // 记忆这里的结构
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

// 这个函数和前面的介绍基本一致 不再过多赘述了

// 下面是设置接口返回token信息
func authHandler(c *gin.Context) {
	var user UserInfo
	err := c.ShouldBind(&user) // 绑定数据
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": 2001,
			"msg":  "无效的参数",
		})
		return
	}
	if user.Username == "mobai" && user.Password == "mobai123" {
		tokenString, _ := GenToken(user.Username)
		c.JSON(http.StatusOK, gin.H{
			"code": 2000,
			"msg":  "success",
			"data": gin.H{"token": tokenString},
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"code": 2002,
		"msg":  "鉴权失败",
	})
	// return 冗余
}

// 根据前端的GET请求验证token信息
func JWTAuthMiddleware() func(c *gin.Context) {
	return func(c *gin.Context) {
		authHeader := c.Request.Header.Get("Authorization") // 获取请求头中的Authorization信息
		if authHeader == "" {
			c.JSON(http.StatusOK, gin.H{
				"code": 2003,
				"msg":  "请求头中auth为空",
			})
			c.Abort() // 停止当前的HTTP请求
			return
		}
		parts := strings.SplitN(authHeader, " ", 2)     // 分割因为authHeader信息是Bearer + token 之间是空格需要切割
		if !(len(parts) == 2 && parts[0] == "Bearer") { // 不是两段而且头部不是Bearer那么返回错误
			c.JSON(http.StatusOK, gin.H{
				"code": 2004,
				"msg":  "请求头中auth格式有误",
			})
			c.Abort()
			return
		}
		mc, err := ParseToken(parts[1]) // 将token信息解析出来 ParseToken函数见上面
		if err != nil {
			c.JSON(http.StatusOK, gin.H{
				"code": 2005,
				"msg":  "无效的Token",
			})
			c.Abort()
			return
		}
		c.Set("username", mc.Username)
		c.Next() // 调用中间件处理username
	}
}

func homeHandler(c *gin.Context) {
	username := c.MustGet("username").(string) // 这里就调用之前设置的username 转为string对象
	c.JSON(http.StatusOK, gin.H{
		"code": 2000,
		"msg":  "success",
		"data": gin.H{"username": username},
		// 打印username信息  其实就是根据token验证对应的用户信息
	})
	// 常见的设置JSON返回信息
}

func main() {
	r := gin.Default()
	r.POST("/auth", authHandler)
	r.GET("/home", JWTAuthMiddleware(), homeHandler) // 注意这里GET的使用
	r.Run(":8080")
}

// 启动gin 调用端口
