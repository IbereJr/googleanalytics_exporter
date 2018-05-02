/*
Obtains Google Analytics RealTime API metrics, and presents them to
prometheus for scraping.
*/
package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/jwt"
	"google.golang.org/api/analytics/v3"
	"gopkg.in/yaml.v2"
)

var (
	credsfile = os.Getenv("CRED_FILE")
	conffile  = os.Getenv("CONFIG_FILE")
	promGauge = make(map[string]prometheus.Gauge)
	config    = new(conf)
)

// conf defines configuration parameters
type conf struct {
	Interval   int                   `yaml:"interval"`
	Metrics    []string              `yaml:"metrics"`
	Dimensions []map[string][]string `yaml:"dimensions"`
	ViewID     string                `yaml:"viewid"`
	PromPort   string                `yaml:"promport"`
}

func init() {
	config.getConf(conffile)

	// All metrics are registered as Prometheus Gauge
	for _, metric := range config.Metrics {
		registerMetric(metric)
	}
}

func registerMetric(metric string) {
	promGauge[metric] = prometheus.NewGauge(prometheus.GaugeOpts{
		Name:        fmt.Sprintf("ga_%s", strings.Replace(metric, ":", "_", 1)),
		Help:        fmt.Sprintf("Google Analytics %s", metric),
		ConstLabels: map[string]string{"job": "googleAnalytics"},
	})

	prometheus.MustRegister(promGauge[metric])
}

func main() {
	creds := getCreds(credsfile)

	// JSON web token configuration
	jwtc := jwt.Config{
		Email:        creds["client_email"],
		PrivateKey:   []byte(creds["private_key"]),
		PrivateKeyID: creds["private_key_id"],
		Scopes:       []string{analytics.AnalyticsReadonlyScope},
		TokenURL:     creds["token_uri"],
		// Expires:      time.Duration(1) * time.Hour, // Expire in 1 hour
	}

	httpClient := jwtc.Client(oauth2.NoContext)
	as, err := analytics.New(httpClient)
	if err != nil {
		panic(err)
	}

	// Authenticated RealTime Google Analytics API service
	rts := analytics.NewDataRealtimeService(as)

	// Expose the registered metrics via HTTP.
	http.Handle("/metrics", promhttp.Handler())

	go http.ListenAndServe(fmt.Sprintf(":%s", config.PromPort), nil)

	for {
		for _, metric := range config.Metrics {
			// Go routine per metric
			go func(metric string) {
				dimensions := getDimensions(metric)
				metrics := getMetric(rts, metric, dimensions)
				for key, value := range metrics {
					// Gauge value to float64
					valf, _ := strconv.ParseFloat(value, 64)
					promGauge[key].Set(valf)
				}
			}(metric)
		}
		time.Sleep(time.Second * time.Duration(config.Interval))
	}
}

// getMetric queries GA RealTime API for a specific metric.
func getMetric(rts *analytics.DataRealtimeService, metric string, gaDimensions string) map[string]string {
	getc := rts.Get(config.ViewID, metric)

	if len(gaDimensions) > 0 {
		getc.Dimensions(gaDimensions)
	}

	m, err := getc.Do()
	if err != nil {
		panic(err)
	}

	metrics := make(map[string]string, len(m.Rows))
	if len(m.Rows) == 1 {
		metrics[metric] = m.Rows[0][0]
		return metrics
	}

	for _, row := range m.Rows {
		if !strings.Contains(row[0], "(not set)") {
			label := buildMetricLabel(row)
			registerMetric(label)
			metrics[label] = row[2]
		}
	}

	return metrics
}

func buildMetricLabel(row []string) string {
	reg, _ := regexp.Compile("[^a-zA-Z0-9]+")

	action := reg.ReplaceAllString(row[1], "")
	category := reg.ReplaceAllString(row[0], "")
	rows := []string{"rt:", action, category}

	return strings.Replace(strings.Join(rows, "_"), " ", "_", -1)
}

// getDimensions gets dimensions from one specific metric.
func getDimensions(metric string) string {
	var dimensions string
	for _, dimensionMap := range config.Dimensions {
		dimensions = strings.Join(dimensionMap[metric][:], ",")
	}

	return dimensions
}

// conf.getConf reads yaml configuration file
func (c *conf) getConf(filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	if err = yaml.Unmarshal(data, &c); err != nil {
		panic(err)
	}
}

// https://console.developers.google.com/apis/credentials
// 'Service account keys' creds formated file is expected.
// NOTE: the email from the creds has to be added to the Analytics permissions
func getCreds(filename string) (r map[string]string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		panic(err)
	}
	if err = json.Unmarshal(data, &r); err != nil {
		panic(err)
	}

	return r
}
