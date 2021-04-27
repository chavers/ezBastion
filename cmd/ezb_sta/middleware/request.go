package middleware

import (
	"crypto/tls"
	"ezBastion/pkg/confmanager"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	"path"
)

func tokendb(c *gin.Context) {
	// The body is a JSON object
	//type JsonBody struct {
	//	GrantType string `json:"grant_type"`
	//	UserName  string `json:"username"`
	//	Password  string `json:"password"`
	//}

	ep, _ := c.Get("exPath")
	exPath := ep.(string)
	cnf, _ := c.Get("configuration")
	username, _ := c.Get("unsername")
	conf := cnf.(*confmanager.Configuration)
	fcert := path.Join(exPath, conf.TLS.PublicCert)
	key := path.Join(exPath, conf.TLS.PrivateKey)
	ca := path.Join(exPath, conf.EZBPKI.CaCert)

	cert, err := tls.LoadX509KeyPair(fcert, key)
	if err != nil {
		fmt.Println(err)
		return
	}
	EzbDB := fmt.Sprintf("https://%s:%d/accounts/%s", conf.EZBDB.NetworkPKI.FQDN, conf.EZBDB.NetworkPKI.Port, username)
	client := resty.New()
	client.SetRootCertificate(ca)
	client.SetCertificates(cert)

	request, err := client.R().Get(EzbDB)
	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(request.Body()))
	/*
					var testHash = crypto.createHash('sha256').update(req.body.password + b.salt).digest('hex');
					if (testHash == b.password) {
						req.connection = {};
						const uuidv4 = require('uuid/v4');
						req.uuid = uuidv4();
						req.aud = 'internal';
						req.connection.user = b.name;
						req.sign_key = crypto.createHash('md5').update(bcrypt.genSaltSync(32)).digest('hex');
						next()
					} else {
						console.log(req.body.username + " found in db but bad password, next");
						next();
					}
				} else {
					console.log(error)
					console.log(req.body.username + " not found in db, next");
					next();
				}
			});
		} else {
			console.log("No grant_type, next");
			next();
	*/

}
