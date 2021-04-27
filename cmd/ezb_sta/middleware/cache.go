package middleware

import (
	"github.com/gin-gonic/gin"
	"net/http"
)

func EzbCache(c *gin.Context) {
	c.JSON(http.StatusBadRequest, gin.H{"message": "TODO"})
}
