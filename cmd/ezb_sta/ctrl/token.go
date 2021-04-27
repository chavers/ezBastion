package ctrl

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	db "ezBastion/cmd/ezb_db/models"
	"ezBastion/cmd/ezb_sta/middleware"
	"ezBastion/cmd/ezb_sta/models"
	"ezBastion/pkg/confmanager"
	"fmt"
	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/go-resty/resty/v2"
	uuid2 "github.com/gofrs/uuid"
	"github.com/mitchellh/mapstructure"
	"golang.org/x/crypto/bcrypt"
	"io/ioutil"
	"net/http"
	"path"
	"strconv"
	"time"
)

var (
	ExePath string
	Conf    confmanager.Configuration
)

func EzbAuthDB(c *gin.Context) {
	var mp models.EzbFormAuth
	err := c.ShouldBindJSON(&mp)
	if err != nil {
		c.String(http.StatusInternalServerError, "#A0002 bind parameters error", err)
		return
	}
	config, _ := c.Keys["configuration"].(*confmanager.Configuration)
	expath := c.GetString("exPath")
	username := mp.Username
	password := mp.Password

	target := "https://" + config.EZBDB.NetworkPKI.FQDN + ":" + strconv.Itoa(config.EZBDB.NetworkPKI.Port) + "/accounts/" + username
	client := resty.New()
	cert, err := tls.LoadX509KeyPair(path.Join(expath, config.TLS.PublicCert), path.Join(expath, config.TLS.PrivateKey))
	if err != nil {
		c.JSON(500, err.Error())
		return
	}
	dbaccount := db.EzbAccounts{}
	client.SetRootCertificate(path.Join(expath, config.EZBPKI.CaCert))
	client.SetCertificates(cert)
	resp, e := client.R().
		EnableTrace().
		SetHeader("Accept", "application/json").
		SetHeader("Authorization", c.GetHeader("Authorization")).
		SetResult(&dbaccount).
		Get(target)
	if e != nil {
		return
	}
	if resp.StatusCode() != 200 {
		c.String(http.StatusInternalServerError, "#A0001 EZB_DB return error", err)
		return
	}

	testhash := fmt.Sprintf("%x", sha256.Sum256([]byte(password+dbaccount.Salt)))
	if testhash == dbaccount.Password {
		// user is computed from specific module
		stauser := models.StaUser{}
		stauser.User = dbaccount.Name
		// TODO compute SID and groups
		c.Set("connection", stauser)
		newuuid, err := uuid2.NewV4()
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Error generating uuid"})
		}
		c.Set("uuid", newuuid.String())
		c.Set("aud", "internal")
		skey, err := bcrypt.GenerateFromPassword([]byte(hex.EncodeToString(randStr(16))), 32)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Error generating sign key"})
		}
		c.Set("sign_key", skey)

		stauser.User = username
		/*
			stauser.UserSid = req.connection.userSid;
			stauser.UserGroups = req.connection.userGroups;
			stauser.Sign_key = req.sign_key;
		*/

		jsonobj, e := createtoken(expath, config, c)
		if e != nil {
			c.JSON(http.StatusBadRequest, gin.H{"message": "Error in token"})
			return
		}
		c.JSON(http.StatusOK, jsonobj)
	}
}

func randStr(len int) []byte {
	buff := make([]byte, len)
	rand.Read(buff)
	str := base64.StdEncoding.EncodeToString(buff)
	// Base 64 can be longer than len
	return []byte(str[:len])
}

func EzbAuthform(c *gin.Context) {
	c.JSON(http.StatusBadRequest, gin.H{"message": "TODO"})
}
func EzbAuthsspi(c *gin.Context) {
	c.JSON(http.StatusBadRequest, gin.H{"message": "TODO"})
}
func EzbReNew(c *gin.Context) {
	c.JSON(http.StatusBadRequest, gin.H{"message": "TODO"})
}

func createtoken(exepath string, conf *confmanager.Configuration, c *gin.Context) (b bearer, err error) {

	cert, err := ioutil.ReadFile(exepath + "/cert/" + conf.EZBSTA.JWT.Issuer + ".crt")
	if err != nil {
		return "", err
	}
	expirationTime := time.Now().Add(time.Minute)
	connect, _ := c.Get("connection")
	stauser := models.StaUser{}
	mapstructure.Decode(connect, &stauser)
	uuid, _ := c.Get("uuid")
	payload := &middleware.Payload{
		JTI: fmt.Sprintf("%v", uuid),
		ISS: conf.EZBSTA.JWT.Issuer,
		SUB: stauser.User,
		AUD: conf.EZBSTA.JWT.Audience,
		EXP: expirationTime.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, payload)
	tokenString, err := token.SignedString(cert)
	if err != nil {
		return b, err
	}
	b.TokenType = "bearer"
	b.AccessToken = tokenString
	b.ExpireAt = payload.EXP
	b.ExpireIn = expirationTime.Second()
	return b, nil
}


type bearer struct {
	ExpireIn    int    `json:"expire_in"`
	ExpireAt    int64  `json:"expire_at"`
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}
