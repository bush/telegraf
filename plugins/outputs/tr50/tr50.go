package tr50

import (
	"fmt"
	"strings"
	"regexp"
	"sync"
	"time"
	"encoding/json"

	"github.com/influxdata/telegraf"
	"github.com/influxdata/telegraf/internal"
	"github.com/influxdata/telegraf/internal/tls"
	"github.com/influxdata/telegraf/plugins/outputs"

	paho "github.com/eclipse/paho.mqtt.golang"
)

var sampleConfig = `
  ## URLs of mqtt brokers
  servers = ["helixdevicecloud.com:8883"]

  ## topic for producer messages
  #api_topic = "api"

  ## QoS policy for messages
  ##   0 = at most once
  ##   1 = at least once
  ##   2 = exactly once
  qos = 2

  ## thing key and app token to connect to the MQTT API.
  # thing_key = "my-thing-key"
  # app_token = "my-app-token"

  ## client ID, if not set a random ID is generated
  # client_id = ""

  ## Timeout for write operations. default: 5s
  # timeout = "5s"

  ## Optional TLS Config
  # tls_ca = "/etc/telegraf/ca.pem"
  # tls_cert = "/etc/telegraf/cert.pem"
  # tls_key = "/etc/telegraf/key.pem"
  ## Use TLS but skip chain & host verification
  # insecure_skip_verify = false
`

type MQTT struct {
	Servers     []string `toml:"servers"`
	Username    string
	Password    string
	Database    string
	Timeout     internal.Duration
	ApiTopic string
	QoS         int    `toml:"qos"`
	ClientID    string `toml:"client_id"`
	tls.ClientConfig

	client paho.Client
	opts   *paho.ClientOptions

	sync.Mutex
}

var (
	allowedChars = regexp.MustCompile(`[^a-zA-Z0-9-_]`)
	hypenChars   = strings.NewReplacer(
		"/", "-",
		"@", "-",
		"*", "-",
	)
	dropChars = strings.NewReplacer(
		`\`, "",
		"..", ".",
	)
)

func (m *MQTT) Connect() error {
	var err error
	m.Lock()
	defer m.Unlock()
	if m.QoS > 2 || m.QoS < 0 {
		return fmt.Errorf("MQTT Output, invalid QoS value: %d", m.QoS)
	}

	m.opts, err = m.createOpts()
	if err != nil {
		return err
	}

	m.client = paho.NewClient(m.opts)
	if token := m.client.Connect(); token.Wait() && token.Error() != nil {
		return token.Error()
	}

	return nil
}

func (m *MQTT) Close() error {
	if m.client.IsConnected() {
		m.client.Disconnect(20)
	}
	return nil
}

func (m *MQTT) SampleConfig() string {
	return sampleConfig
}

func (m *MQTT) Description() string {
	return "Configuration for MQTT server to send metrics to"
}

func (m *MQTT) Write(metrics []telegraf.Metric) error {
	m.Lock()
	defer m.Unlock()
	if len(metrics) == 0 {
		return nil
	}

  if m.ApiTopic == "" {
    m.ApiTopic = "api"
  }

	for _, metric := range metrics {

	  buf, err := serialize(metric, m.Username)

		if err != nil {
      return err
		}

			err = m.publish(m.ApiTopic, buf)
			if err != nil {
				return fmt.Errorf("Could not write to MQTT server, %s", err)
			}
  }

	return nil
}

func (m *MQTT) publish(topic string, body []byte) error {
	token := m.client.Publish(topic, byte(m.QoS), false, body)
	token.WaitTimeout(m.Timeout.Duration)
	if token.Error() != nil {
		return token.Error()
	}
	return nil
}

func (m *MQTT) createOpts() (*paho.ClientOptions, error) {
	opts := paho.NewClientOptions()
	opts.KeepAlive = 0 * time.Second

	if m.Timeout.Duration < time.Second {
		m.Timeout.Duration = 5 * time.Second
	}
	opts.WriteTimeout = m.Timeout.Duration

	if m.ClientID != "" {
		opts.SetClientID(m.ClientID)
	} else {
		opts.SetClientID("Telegraf-Output-" + internal.RandomString(5))
	}

	tlsCfg, err := m.ClientConfig.TLSConfig()
	if err != nil {
		return nil, err
	}

	scheme := "tcp"
	if tlsCfg != nil {
		scheme = "ssl"
		opts.SetTLSConfig(tlsCfg)
	}

	user := m.Username
	if user != "" {
		opts.SetUsername(user)
	}
	password := m.Password
	if password != "" {
		opts.SetPassword(password)
	}

	if len(m.Servers) == 0 {
		return opts, fmt.Errorf("could not get host infomations")
	}
	for _, host := range m.Servers {
		server := fmt.Sprintf("%s://%s", scheme, host)

		opts.AddBroker(server)
	}
	opts.SetAutoReconnect(true)
	return opts, nil
}

func serialize(metric telegraf.Metric, thingKey string) ([]byte, error) {
	m := createObject(metric, thingKey)
	serialized, err := json.Marshal(m)
	if err != nil {
		return []byte{}, err
	}
	serialized = append(serialized, '\n')

	return serialized, nil
}

func createObject(metric telegraf.Metric, thingKey string) map[string]interface{} {

  timestamp := metric.Time().Format(time.RFC3339)
  tag := metric.Name()
  for _, value := range metric.Tags() {
    value = sanitize(value)
    tag += "-" + value
  }

  // Maps the fields to an array of key/value pairs
  var data[]map[string]interface{}
  for key, value := range metric.Fields() {
    keyname := tag + "-" + key
    data = append(data,map[string]interface{}{"key": keyname, "value": value, "ts": timestamp})
	}

  m := map[string]interface{}{
    "cmd": map[string]interface{}{
      "command": "property.batch",
      "params": map[string]interface{}{
        "thingKey": thingKey,
        "key": "my-global-key",
        "ts": timestamp,
        "corrid": "my-corr-id",
        "aggregate":"true",
        "data":data,
      },
    },
  }

  return m
}

func sanitize(value string) string {
	// Apply special hypenation rules to preserve backwards compatibility
	value = hypenChars.Replace(value)
	// Apply rule to drop some chars to preserve backwards compatibility
	value = dropChars.Replace(value)
	// Replace any remaining illegal chars
	return allowedChars.ReplaceAllLiteralString(value, "_")
}

func init() {
	outputs.Add("tr50", func() telegraf.Output {
		return &MQTT{}
	})
}
