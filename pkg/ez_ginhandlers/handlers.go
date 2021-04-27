// This file is part of ezBastion.

//     ezBastion is free software: you can redistribute it and/or modify
//     it under the terms of the GNU Affero General Public License as published by
//     the Free Software Foundation, either version 3 of the License, or
//     (at your option) any later version.

//     ezBastion is distributed in the hope that it will be useful,
//     but WITHOUT ANY WARRANTY; without even the implied warranty of
//     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//     GNU Affero General Public License for more details.

//     You should have received a copy of the GNU Affero General Public License
//     along with ezBastion.  If not, see <https://www.gnu.org/licenses/>.

package ez_ginhandlers

import (
	"ezBastion/pkg/confmanager"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

func LoadConfig(conf *confmanager.Configuration, exePath string) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("configuration", conf)
		c.Set("exPath", exePath)
		c.Next()
	}
}

func Reqheaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Headers", "Content-Type, authorization")
		c.Header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		if c.Request.Method == "OPTIONS" {
			c.Request.Response.Status = strconv.Itoa(http.StatusOK)
		} else {
			c.Next()
		}
		c.Next()
	}
}
