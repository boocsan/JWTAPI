package main

import (
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	jwt "github.com/dgrijalva/jwt-go"
	"github.com/dgrijalva/jwt-go/request"
	"github.com/gorilla/mux"
)

func main() {
	GetCertificate()
	router := mux.NewRouter()
	router.Handle("/get", GetJwtHandler).Methods("GET")
	router.Handle("/verify", JwtVerifyHandler).Methods("GET")
	http.ListenAndServe(":8080", router)
}

// PrivateCertificate JWT Signature Private Certificate
var PrivateCertificate string

// PublicCertificate JWT Signature Public Certificate
var PublicCertificate *rsa.PublicKey

// GetCertificate Load JWT Signature Certificate
func GetCertificate() {
	prifile, err := os.Open("private.key")
	if err != nil {
		fmt.Println("[Error] Open private.key")
	}
	defer prifile.Close()

	prikey, err := ioutil.ReadAll(prifile)
	if err != nil {
		fmt.Println("[Error] Read private.key")
	}
	PrivateCertificate = string(prikey)

	pubfile, err := os.Open("public.key")
	if err != nil {
		fmt.Println("[Error] Open public.key")
	}
	defer pubfile.Close()

	pubkey, err := ioutil.ReadAll(pubfile)
	if err != nil {
		fmt.Println("[Error] Read public.key")
	}
	p, _ := jwt.ParseRSAPublicKeyFromPEM(pubkey)
	PublicCertificate = p
}

// GetJwtHandler Get JWT
var GetJwtHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	t := jwt.New(jwt.SigningMethodHS256)

	c := t.Claims.(jwt.MapClaims)
	c["name"] = "TestUser"
	c["iss"] = "iedred7584"
	c["aud"] = "localhost:8080"
	c["sub"] = base64.StdEncoding.EncodeToString([]byte(time.Now().String()))
	c["iat"] = time.Now()
	c["exp"] = time.Now().Add(time.Hour * 24).Unix()

	token, _ := t.SignedString([]byte(PrivateCertificate))

	w.Write([]byte(token))
})

// JwtVerifyHandler Verify JWT
var JwtVerifyHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	token, err := request.ParseFromRequest(r, request.AuthorizationHeaderExtractor, func(token *jwt.Token) (interface{}, error) {
		_, err := token.Method.(*jwt.SigningMethodRSA)
		if !err {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return PublicCertificate, nil
	})
	if err == nil && token.Valid {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("Verification success."))
		return
	}
	w.WriteHeader(http.StatusUnauthorized)
	w.Write([]byte("Verification Error."))
	return
})
