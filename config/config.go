package config

import (
	"encoding/json"
	"os"
)

type Config struct {
	ClientPub    ClientPub     `json:"clientPub"`
	OpcUaClients []OpcUaClient `json:"opcUaClients"`
}

type ClientPub struct {
	ClientId           string `json:"clientId"`
	ServerAddress      string `json:"serverAddress"`
	Qos                int    `json:"qos"`
	ConnectionTimeout  int    `json:"connectionTimeout"`
	WriteTimeout       int    `json:"writeTimeout"`
	KeepAlive          int    `json:"keepAlive"`
	PingTimeout        int    `json:"pingTimeout"`
	ConnectRetry       bool   `json:"connectRetry"`
	AutoConnect        bool   `json:"autoConnect"`
	OrderMaters        bool   `json:"orderMaters"`
	UserName           string `json:"userName"`
	Password           string `json:"password"`
	TlsConn            bool   `json:"tlsConn"`
	RootCAPath         string `json:"rootCAPath"`
	ClientKeyPath      string `json:"clientKeyPath"`
	PrivateKeyPath     string `json:"privateKeyPath"`
	InsecureSkipVerify bool   `json:"insecureSkipVerify"`
	TranslateTopic     bool   `json:"translateTopic"`
	PublishInterval    int    `json:"publishInterval"`
	TopicToPublish     string `json:"topicToPublish"`
	Logs               Logs   `json:"logs"`
}

type Logs struct {
	Debug    bool `json:"debug"`
	Warning  bool `json:"warning"`
	Error    bool `json:"error"`
	Critical bool `json:"critical"`
}

type OpcUaClient struct {
	ClientId           string  `json:"clientId"`
	ServerAddress      string  `json:"serverAddress"`
	PollInterval       int     `json:"pollInterval"`
	MaxAge             float64 `json:"maxAge"`
	MaxSignalsPerRead  int     `json:"maxSignalsPerRead"`
	MinTimeBetweenRead int     `json:"minTimeBetweenRead"`
	NodesToRead        []Node  `json:"nodesToRead"`
}

type Node struct {
	Name   string `json:"name"`
	NodeID string `json:"nodeID"`
}

func ReadConfig() Config {
	f, err := os.Open("./config/config.json")
	if err != nil {
		panic(err)
	}
	defer f.Close()

	var cfg Config
	decoder := json.NewDecoder(f)
	err = decoder.Decode(&cfg)
	if err != nil {
		panic(err)
	}

	return cfg
}
