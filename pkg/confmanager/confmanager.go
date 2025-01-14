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

package confmanager

import (
	"github.com/Showmax/go-fqdn"
	toml "github.com/pelletier/go-toml"
	"io/ioutil"
	"os"
	"path"
)

func CheckConfig(confPath string, exePath string) (conf Configuration, err error) {
	raw, readerror := ioutil.ReadFile(confPath)
	if readerror != nil {
		fqdn, err := fqdn.FqdnHostname()
		if err != nil {
			fqdn, _ = os.Hostname()
		}
		conf.EZBPKI.Network.FQDN = fqdn
		conf.EZBPKI.Network.Port = 5010
		conf.TLS.SAN = []string{fqdn}
		conf.EZBWKS.ServiceName = "ezb_wks"
		conf.EZBPKI.CaCert = "cert/ca.crt"
		conf.EZBPKI.CaKey = "cert/ca.key"
		conf.TLS.PrivateKey = "cert/ezbastion.key"
		conf.TLS.PublicCert = "cert/ezbastion.crt"
		conf.Logger.LogLevel = "info"
		conf.Logger.MaxAge = 180
		conf.Logger.MaxBackups = 10
		conf.Logger.MaxSize = 5
		conf.EZBDB.DB = "sqlite"
		conf.EZBDB.SQLITE.DBPath = "db/ezbastion.db"
		conf.EZBDB.NetworkPKI.FQDN = fqdn
		conf.EZBDB.NetworkPKI.Port = 5011
		conf.EZBDB.NetworkJWT.FQDN = fqdn
		conf.EZBDB.NetworkJWT.Port = 5012
		conf.EZBSRV.Network.FQDN = fqdn
		conf.EZBSRV.Network.Port = 5000
		conf.EZBSRV.CacheL1 = 600
		conf.EZBWKS.Network.FQDN = fqdn
		conf.EZBWKS.Network.Port = 5100
		conf.EZBSTA.Network.FQDN = fqdn
		conf.EZBSTA.Network.Port = 1443
		conf.EZBSTA.JWT.TTL = 1200
		conf.EZBSTA.JWT.Audience = "ezBastion"
		conf.EZBSTA.JWT.Issuer = "ezb_sta"
		conf.EZBWKS.ScriptPath = path.Join(exePath, "script")
		conf.EZBWKS.JobPath = path.Join(exePath, "job")
		conf.EZBWKS.LimitMax = 0
		conf.EZBWKS.LimitWarning = 0
		return conf, readerror
	}
	toml.Unmarshal(raw, &conf)
	return conf, nil
}
