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

package main

import (
	"ezBastion/cmd/ezb_sta/ctrl"
	"ezBastion/pkg/ez_ginhandlers"
	"ezBastion/pkg/logmanager"
	"github.com/gin-gonic/gin"
	"path"
	"strconv"
)

// Must implement Mainservice interface from servicemanager package
type mainService struct{}

func (sm mainService) StartMainService(serverchan *chan bool) {
	logmanager.Debug("#### Main service started #####")
	// Pushing current conf to controllers
	server := gin.Default()
		
	server.OPTIONS("*a", func(c *gin.Context) {
		c.AbortWithStatus(200)
	})
	
	server.Use(ez_ginhandlers.LoadConfig(&conf, exePath))
	server.Use(ez_ginhandlers.Reqheaders())
	server.Use()
	ctrl.Routes(server)
	server.RunTLS(":"+strconv.Itoa(conf.EZBSTA.Network.Port), path.Join(exePath, conf.TLS.PublicCert), path.Join(exePath, conf.TLS.PrivateKey))
}
