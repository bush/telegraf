# WRS IoT Output Plugin

This plugin provides an MQTT interface to the WRS IoT telemetry engine.

```toml
[[outputs.wrsiot]]
  ## URLs of mqtt brokers
  servers = ["helix-device-cloud-mqtt-server:8883"]

  ## topic for producer messages
  #api_topic = "api"

  ## QoS policy for messages
  ##   0 = at most once
  ##   1 = at least once
  ##   2 = exactly once
  qos = 2

  ## username and password to connect MQTT server.
  # username = "my-username-or-thing-key"
  # password = "my-password-or-app-token"

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
```

### Required parameters:

* `servers`: List of strings, this is for speaking to a cluster of `mqtt` brokers. On each flush interval, Telegraf will randomly choose one of the urls to write to. Each URL should just include host and port e.g. -> `["{host}:{port}","{host2}:{port2}"]`
* `qos`: The `mqtt` QoS policy for sending messages. See https://www.ibm.com/support/knowledgecenter/en/SSFKSJ_9.0.0/com.ibm.mq.dev.doc/q029090_.htm for details.

### Optional parameters:
* `username`: The username or thing key to connect MQTT server.
* `password`: The password or app token to connect MQTT server.
* `client_id`: The unique client id to connect MQTT server. If this paramater is not set then a random ID is generated.
* `api_topic`: The `mqtt` telemetry topic to publish to. Defaults to `api` 
* `timeout`: Timeout for write operations. default: 5s
* `tls_ca`: TLS CA
* `tls_cert`: TLS CERT
* `tls_key`: TLS key
* `insecure_skip_verify`: Use TLS but skip chain & host verification (default: false)
