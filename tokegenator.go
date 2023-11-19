package main

import (
	"crypto/rsa"
	"log"

	//"net/url"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

func fatal(err error) {
	if err != nil {
		log.Fatal(err)
	}
}

type TokenGenerator struct {
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
}

func NewTokenGenerator(privKeyPath string, pubKeyPath string) *TokenGenerator {
	signBytes, err := os.ReadFile(privKeyPath)
	fatal(err)

	signKey, err := jwt.ParseRSAPrivateKeyFromPEM(signBytes)
	fatal(err)

	verifyBytes, err := os.ReadFile(pubKeyPath)
	fatal(err)

	verifyKey, err := jwt.ParseRSAPublicKeyFromPEM(verifyBytes)
	fatal(err)
	return &TokenGenerator{
		verifyKey: verifyKey,
		signKey:   signKey,
	}
}

type clientInfo struct {
	ClientID           string `json:"client-id"`
	AuthorizationGroup string `json:"auth-group"`
}

type customClaims struct {
	*jwt.StandardClaims
	clientInfo
}

type TokenResponse struct {
	TokenValue     string
	TokenSignature string
}

func (gen *TokenGenerator) createToken(client string, group string, exp time.Time) (string, error) {

	t := jwt.New(jwt.GetSigningMethod("RS256"))
	t.Claims = &customClaims{
		&jwt.StandardClaims{
			ExpiresAt: exp.UTC().Unix(),
		},
		clientInfo{client, group},
	}
	t.Header["kid"] = "rhcloud"
	return t.SignedString(gen.signKey)
}

// func (gen *TokenGenerator) parseToken(tokenString string) (*jwt.Token, error) {

// 	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
// 		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
// 			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
// 		}
// 		return gen.verifyKey, nil
// 	})
// 	return token, err

// }

func (gen *TokenGenerator) GenerateToken(clientId string, group string) TokenResponse {

	exp := time.Now().Add(time.Hour)
	tokenStr, _ := gen.createToken(clientId, group, exp)
	parts := strings.Split(tokenStr, ".")
	token := parts[0] + "." + parts[1]
	tokenSignature := strings.ReplaceAll(parts[2], "_", "/")
	tokenSignature = strings.ReplaceAll(tokenSignature, "-", "+") + "==" //AWS requires standard base64 encoding
	return TokenResponse{
		token,
		tokenSignature,
	}
}
