package middleware

import "github.com/gin-gonic/gin"

// LocalStringUTF8 声明「客户端字符串字段按 UTF-8 输出」策略。
// 实际 GBK→UTF-8 在注册入库（internal/agent）与 models.Client.AfterFind（读库展示）中完成。
func LocalStringUTF8() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Next()
	}
}
