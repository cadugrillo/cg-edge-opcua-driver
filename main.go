package main

import (
	"cg-edge-opcua-driver/config"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	mqtt "github.com/eclipse/paho.mqtt.golang"
	"github.com/gopcua/opcua"
	"github.com/gopcua/opcua/debug"
	"github.com/gopcua/opcua/ua"
)

var (
	endpoints  []*string
	ConfigFile config.Config
	nodes      []*string
	nodesGroup NodesGroup
	nodesList  []NodesList
	PubConnOk  bool
	SubConnOk  bool
	payload    Payload
	payloads   []Payload
	v          interface{}
	c          [8]*opcua.Client
	connStatus [8]bool
)

type NodesList struct {
	nodesGroup []NodesGroup
}

type NodesGroup struct {
	nodes []*ua.ReadValueID
}

type Payload struct {
	ClientName    string   `json:"clientName"`
	ServerAddress string   `json:"serverAddress"`
	Signals       []Signal `json:"signals"`
}

type Signal struct {
	Name  string        `json:"name"`
	Qc    ua.StatusCode `json:"qc"`
	Ts    time.Time     `json:"ts"`
	Value interface{}   `json:"value"`
}

func NewTLSConfig(rootCAPath string, clientKeyPath string, privateKeyPath string, insecureSkipVerify bool) *tls.Config {

	certpool := x509.NewCertPool()
	pemCerts, err := ioutil.ReadFile(rootCAPath)
	if err == nil {
		certpool.AppendCertsFromPEM(pemCerts)
	}

	cert, err := tls.LoadX509KeyPair(clientKeyPath, privateKeyPath)
	if err != nil {
		panic(err)
	}

	cert.Leaf, err = x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		panic(err)
	}
	//fmt.Println(cert.Leaf)

	return &tls.Config{
		RootCAs:            certpool,
		ClientAuth:         tls.NoClientCert,
		ClientCAs:          nil,
		InsecureSkipVerify: insecureSkipVerify,
		Certificates:       []tls.Certificate{cert},
	}
}

func main() {
	////////////////////OPCUA CONFIGURATION SECTION////////////////////////////
	ConfigFile = config.ReadConfig()

	for u := 0; u < len(ConfigFile.OpcUaClients); u++ {

		nodesListNew := NodesList{}
		nodesList = append(nodesList, nodesListNew)

		endpointName := fmt.Sprintf("endpoint%d", u)
		endpoint := []*string{flag.String(endpointName, ConfigFile.OpcUaClients[u].ServerAddress, "OPC UA Endpoint URL")}
		endpoints = append(endpoints, endpoint...)

		payload.ClientName = ConfigFile.OpcUaClients[u].ClientId
		payload.ServerAddress = ConfigFile.OpcUaClients[u].ServerAddress
		payloads = append(payloads, payload)

		for i := 0; i < len(ConfigFile.OpcUaClients[u].NodesToRead); i++ {

			node := []*string{flag.String(ConfigFile.OpcUaClients[u].ClientId+"_"+ConfigFile.OpcUaClients[u].NodesToRead[i].Name, ConfigFile.OpcUaClients[u].NodesToRead[i].NodeID, "NodeID to read")}
			nodes = append(nodes, node...)
		}

		j := 0
		k := 0
		for i := 0; i < len(nodes); i++ {

			id, err := ua.ParseNodeID(*nodes[i])
			if err != nil {
				log.Fatalf("invalid node id: %v", err)
			}
			r := []*ua.ReadValueID{{NodeID: id}}
			nodesGroup.nodes = append(nodesGroup.nodes, r...)
			j = j + 1

			if (j == ConfigFile.OpcUaClients[u].MaxSignalsPerRead) || (i == len(nodes)-1) {
				s := []NodesGroup{{nodes: nodesGroup.nodes}}
				nodesList[u].nodesGroup = append(nodesList[u].nodesGroup, s...)
				nodesGroup.nodes = nil
				j = 0
				log.Println("Client: ", ConfigFile.OpcUaClients[u].ClientId, ":::Node Group: ", k, ":::", nodesList[u].nodesGroup[k].nodes)
				k = k + 1
			}

		}
		nodes = []*string{}
		nodesGroup = NodesGroup{}
	}

	flag.BoolVar(&debug.Enable, "debug", false, "enable debug logging")
	flag.Parse()
	log.SetFlags(0)

	////////////////////END OF OPCUA CONFIGURATION SECTION/////////////////////

	////////////////////MQTT CONFIGURATION SECTION////////////////////////////
	//logs
	if ConfigFile.ClientPub.Logs.Error {
		mqtt.ERROR = log.New(os.Stdout, "[ERROR] ", 0)
	}
	if ConfigFile.ClientPub.Logs.Critical {
		mqtt.CRITICAL = log.New(os.Stdout, "[CRITICAL] ", 0)
	}
	if ConfigFile.ClientPub.Logs.Warning {
		mqtt.WARN = log.New(os.Stdout, "[WARN]  ", 0)
	}
	if ConfigFile.ClientPub.Logs.Debug {
		mqtt.DEBUG = log.New(os.Stdout, "[DEBUG] ", 0)
	}

	/////opts for Pub Broker
	optsPub := mqtt.NewClientOptions()
	optsPub.AddBroker(ConfigFile.ClientPub.ServerAddress)

	switch ConfigFile.ClientPub.TlsConn {
	case true:
		tlsPub := NewTLSConfig(ConfigFile.ClientPub.RootCAPath, ConfigFile.ClientPub.ClientKeyPath, ConfigFile.ClientPub.PrivateKeyPath, ConfigFile.ClientPub.InsecureSkipVerify)
		optsPub.SetClientID(ConfigFile.ClientPub.ClientId).SetTLSConfig(tlsPub)
	case false:
		optsPub.SetClientID(ConfigFile.ClientPub.ClientId)
		optsPub.SetUsername(ConfigFile.ClientPub.UserName)
		optsPub.SetPassword(ConfigFile.ClientPub.Password)
	}

	optsPub.SetOrderMatters(ConfigFile.ClientPub.OrderMaters)                                      // Allow out of order messages (use this option unless in order delivery is essential)
	optsPub.ConnectTimeout = (time.Duration(ConfigFile.ClientPub.ConnectionTimeout) * time.Second) // Minimal delays on connect
	optsPub.WriteTimeout = (time.Duration(ConfigFile.ClientPub.WriteTimeout) * time.Second)        // Minimal delays on writes
	optsPub.KeepAlive = int64(ConfigFile.ClientPub.KeepAlive)                                      // Keepalive every 10 seconds so we quickly detect network outages
	optsPub.PingTimeout = (time.Duration(ConfigFile.ClientPub.PingTimeout) * time.Second)          // local broker so response should be quick
	optsPub.ConnectRetry = ConfigFile.ClientPub.ConnectRetry                                       // Automate connection management (will keep trying to connect and will reconnect if network drops)
	optsPub.AutoReconnect = ConfigFile.ClientPub.AutoConnect
	optsPub.DefaultPublishHandler = func(_ mqtt.Client, msg mqtt.Message) { fmt.Printf("PUB BROKER - UNEXPECTED : %s\n", msg) }

	optsPub.OnConnectionLost = func(cl mqtt.Client, err error) {
		fmt.Println("PUB BROKER - CONNECTION LOST")
		PubConnOk = false
	}

	optsPub.OnConnect = func(c mqtt.Client) {
		fmt.Println("PUB BROKER - CONNECTION STABLISHED")
		PubConnOk = true
	}

	optsPub.OnReconnecting = func(mqtt.Client, *mqtt.ClientOptions) { fmt.Println("PUB BROKER - ATTEMPTING TO RECONNECT") }

	//connect to PUB broker
	//
	clientPub := mqtt.NewClient(optsPub)

	if tokenPub := clientPub.Connect(); tokenPub.Wait() && tokenPub.Error() != nil {
		panic(tokenPub.Error())
	}
	fmt.Println("PUB BROKER  - CONNECTION IS UP")
	////////////////////END OF MQTT CONFIGURATION SECTION////////////////////////////

	ctx := context.Background()

	for i := 0; i < len(ConfigFile.OpcUaClients); i++ {
		c[i] = opcua.NewClient(*endpoints[i], opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AutoReconnect(true), opcua.ReconnectInterval(time.Minute))
		if err := c[i].Connect(ctx); err != nil {
			fmt.Println(err)
			connStatus[i] = false
			fmt.Println(ConfigFile.OpcUaClients[i].ClientId, ConfigFile.OpcUaClients[i].ServerAddress, ":::OPC UA SERVER - CONNECTION NOT STABLISHED")
			continue
		}
		defer c[i].CloseWithContext(ctx)
		connStatus[i] = true
		fmt.Println(ConfigFile.OpcUaClients[i].ClientId, ConfigFile.OpcUaClients[i].ServerAddress, ":::OPC UA SERVER - CONNECTION STABLISHED")
	}

	for u := 0; u < len(ConfigFile.OpcUaClients); u++ {
		go func(u int, ctx context.Context) {
			for {

				if connStatus[u] == false {
					fmt.Println(ConfigFile.OpcUaClients[u].ClientId, ConfigFile.OpcUaClients[u].ServerAddress, ":::OPC UA SERVER - ATTEMPTING TO RECONNECT")
					c[u] = opcua.NewClient(*endpoints[u], opcua.SecurityMode(ua.MessageSecurityModeNone), opcua.AutoReconnect(true), opcua.ReconnectInterval(time.Minute))
					time.Sleep(time.Duration(5) * time.Second)
					if err := c[u].Connect(ctx); err != nil {
						fmt.Println(err)
						continue
					}
					fmt.Println(ConfigFile.OpcUaClients[u].ClientId, ConfigFile.OpcUaClients[u].ServerAddress, ":::OPC UA SERVER - CONNECTION RESTABLISHED")
					connStatus[u] = true
					continue
				}

				for j := 0; j < len(nodesList[u].nodesGroup); j++ {
					req := &ua.ReadRequest{
						MaxAge:             ConfigFile.OpcUaClients[u].MaxAge,
						NodesToRead:        nodesList[u].nodesGroup[j].nodes,
						TimestampsToReturn: ua.TimestampsToReturnBoth,
					}

					resp, err := c[u].ReadWithContext(ctx, req)
					if err != nil {
						fmt.Println("Read failed: %", err)
						c[u].Close()
						connStatus[u] = false
						break
					}

					for i := 0; i < len(resp.Results); i++ {

						if resp.Results[i].Status != ua.StatusOK {
							log.Println(ConfigFile.OpcUaClients[u].ClientId, ConfigFile.OpcUaClients[u].ServerAddress, ":::Status not OK:", resp.Results[i].Status)
							continue
						}

						x := resp.Results[i].Value.Value()
						switch x.(type) {
						case nil:
							log.Println("node value is nil")
						case bool:
							v = x.(bool)
							//log.Println("node value (bool): ", v, ConfigFile.OpcUaClients[u].NodesToRead[ConfigFile.OpcUaClients[u].MaxSignalsPerRead*j+i].Name)
						case uint16:
							v = x.(uint16)
							//log.Println("node value (uint16): ", v, ConfigFile.OpcUaClients[u].NodesToRead[ConfigFile.OpcUaClients[u].MaxSignalsPerRead*j+i].Name)
						case int16:
							v = x.(int16)
							//log.Println("node value (int16): ", v, ConfigFile.OpcUaClients[u].NodesToRead[ConfigFile.OpcUaClients[u].MaxSignalsPerRead*j+i].Name)
						case float32:
							v = x.(float32)
							//log.Println("node value (float32): ", v, ConfigFile.OpcUaClients[u].NodesToRead[ConfigFile.OpcUaClients[u].MaxSignalsPerRead*j+i].Name)
						}

						opcsignal := []Signal{{Name: ConfigFile.OpcUaClients[u].NodesToRead[ConfigFile.OpcUaClients[u].MaxSignalsPerRead*j+i].Name,
							Qc:    resp.Results[i].Status,
							Ts:    resp.Results[i].SourceTimestamp,
							Value: v,
						}}

						payloads[u].Signals = append(payloads[u].Signals, opcsignal...)
					}
					pl, err := json.Marshal(payloads[u])
					if err != nil {
						log.Fatal(err)
					}
					clientPub.Publish(ConfigFile.ClientPub.TopicToPublish, byte(ConfigFile.ClientPub.Qos), false, pl)
					payloads[u].Signals = nil
					pl = nil
					time.Sleep(time.Duration(ConfigFile.OpcUaClients[u].MinTimeBetweenRead) * time.Millisecond)
				}
				time.Sleep(time.Duration(ConfigFile.OpcUaClients[u].PollInterval) * time.Second)

			}
		}(u, ctx)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt)
	signal.Notify(sig, syscall.SIGTERM)

	<-sig
	fmt.Println("signal caught - exiting")

	for i := 0; i < len(ConfigFile.OpcUaClients); i++ {
		c[i].Close()
	}

	clientPub.Disconnect(1000)
	fmt.Println("shutdown complete")
}
