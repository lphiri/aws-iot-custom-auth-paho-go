package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	mqtt "github.com/eclipse/paho.mqtt.golang"
)

const authorizerName = "x-amz-customauthorizer-name"
const authorizerValue = "my-new-authorizer"
const tokenSignatureName = "x-amz-customauthorizer-signature"
const tokenKeyName = "tokenkeyname"

var tokenGenerator *TokenGenerator

func setReconnectingHandler(opts *mqtt.ClientOptions, clientId string) {
	tokenRefresher := func(c mqtt.Client, opts *mqtt.ClientOptions) {
		setCustomAuthHeaders(opts, clientId)
	}
	opts.SetReconnectingHandler(tokenRefresher)
}

func setCustomAuthHeaders(opts *mqtt.ClientOptions, clientId string) {
	headers := http.Header{}
	jwtToken := tokenGenerator.GenerateToken(clientId, "client")
	headers.Set(authorizerName, authorizerValue)
	headers.Set(tokenSignatureName, jwtToken.TokenSignature)
	headers.Set(tokenKeyName, jwtToken.TokenValue)
	opts.SetHTTPHeaders(headers)
}

func main() {
	cn := make(chan os.Signal, 1)
	signal.Notify(cn, os.Interrupt, syscall.SIGTERM)
	endPoint := "wss://connect.outsrights.cc:443"
	clientId := "lindani-test"
	privKeyPath := "keys/rsa.priv"
	publicKeyPath := "keys/rsa.pub"
	tokenGenerator = NewTokenGenerator(privKeyPath, publicKeyPath)
	opts := mqtt.NewClientOptions()
	opts.AddBroker(endPoint)
	opts.SetClientID(clientId)
	//opts.SetUsername(clientId)
	//opts.SetPassword("")
	setCustomAuthHeaders(opts, clientId)
	setReconnectingHandler(opts, clientId)
	mqtt.DEBUG = log.New(os.Stdout, "[DEBUG] ", 0)
	client := mqtt.NewClient(opts)
	if token := client.Connect(); token.Wait() && token.Error() != nil {
		log.Fatal(token.Error())
	}
	fmt.Println("Connected to AWS IoT!")

	//
	fmt.Println("subcriscribing to ")

	token := client.Subscribe(fmt.Sprintf("redhat/insights/%s/data/in", clientId), 1, nil)
	token.Wait()

	// Don't forget to handle MQTT messages, subscriptions, and other logic as needed

	// Disconnect when done
	<-cn
	client.Disconnect(250)
}
