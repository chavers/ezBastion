package ctrl

import (
	"github.com/gin-gonic/gin"
)

func Routes(route *gin.Engine) {
	// token endpoint
	route.POST("/token", EzbAuthDB)
	//route.POST("/token", EzbAuthform)
	//route.POST("/token", EzbAuthsspi)
	//route.POST("/token", middleware.EzbCache)

	route.GET("/access", GetAccess)
	route.GET("/renew", EzbReNew)
}
