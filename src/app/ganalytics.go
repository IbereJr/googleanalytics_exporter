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
	credsfile    = os.Getenv("CRED_FILE")
	conffile     = os.Getenv("CONFIG_FILE")
	promGauge    = make(map[string]prometheus.Gauge)
	promGaugeVec = make(map[string]*prometheus.GaugeVec)
	config       = new(conf)
)

// conf defines configuration parameters
type conf struct {
	Interval   int                       `yaml:"interval"`
	Metrics    []string                  `yaml:"metrics"`
	Dimensions []map[string][]string     `yaml:"dimensions"`
	Filters    []map[string][]string     `yaml:"filters"`
	Dynamic    []map[string][]string     `yaml:"dynamic"`
	ViewID     string                    `yaml:"viewid"`
	PromPort   string                    `yaml:"promport"`
	Tags       map[string]string         `yaml:"tags"`
	Debug      bool                      `yaml:"debug"`
}

func init() {
	config.getConf(conffile)
        if config.Debug { fmt.Printf("Config = %+v \n", config) }
	for _, metric := range config.Metrics {
                if config.Debug { fmt.Printf("  Registrando = %#v \n", metric) }
		config.Tags["job"] = "googleAnalytics"
		promGauge[metric] = prometheus.NewGauge(prometheus.GaugeOpts{
			Name:        fmt.Sprintf("ga_%s", strings.Replace(metric, ":", "_", 1)),
			Help:        fmt.Sprintf("Google Analytics %s", metric),
			ConstLabels: config.Tags,
		})
		prometheus.Register(promGauge[metric])
	}
}

func registerMetricVec(metric string, Tags map[string]string) {
	promGaugeVec[metric] = prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name:        fmt.Sprintf("ga_%s", strings.Replace(metric, ":", "_", 1)),
		Help:        fmt.Sprintf("Google Analytics %s", metric),
		ConstLabels: Tags,
	}, []string{"category"})
	if err := prometheus.Register(promGaugeVec[metric]); err != nil {
		if are, ok := err.(prometheus.AlreadyRegisteredError); ok { promGaugeVec[metric] = are.ExistingCollector.(*prometheus.GaugeVec) } else { panic(err) }
	}
}

func main() {
	creds := getCreds(credsfile)
	if config.Debug {
           fmt.Printf("Projeto : %#v \n", creds["project_id"])
	   fmt.Printf("Credenciais : %#v \n", creds["client_email"])
	}
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
	if err != nil { panic(err) }

	// Authenticated RealTime Google Analytics API service
	rts := analytics.NewDataRealtimeService(as)

	// Expose the registered metrics via HTTP.
	http.Handle("/metrics", promhttp.Handler())

	go http.ListenAndServe(fmt.Sprintf(":%s", config.PromPort), nil)

	for {
                if config.Debug { fmt.Printf("-[Collect]------------------------------------------ \n") }
		for _, metric := range config.Metrics {
			go func(metric string) {
				dimensions := getDimensions(metric)
				filters := getFilters(metric)
				tags := getDynamics(metric)
                                if config.Debug {
			           fmt.Printf("Processando metrica = %#v \n", metric)
				   fmt.Printf("  Dimensions : %+v \n", dimensions)
				   fmt.Printf("  Filters    : %+v \n", filters)
				   fmt.Printf("  Tags    : %+v \n", tags)
			        }
				collectMetric(rts, metric, dimensions, filters, tags)
			}(metric)
		}
		time.Sleep(time.Second * time.Duration(config.Interval))
	}
}

// getMetric queries GA RealTime API for a specific metric.
func collectMetric(rts *analytics.DataRealtimeService, metric string, rtDimensions string, rtFilters string, rtTags map[string]*regexp.Regexp ) {
	getc := rts.Get(config.ViewID, metric)
	if len(rtDimensions) > 0 { getc.Dimensions(rtDimensions) }
	if len(rtFilters) > 0 { getc.Filters(rtFilters) }

	m, err := getc.Do()
	if err != nil { panic(err) }
	Tags:=make(map[string]string)

//	if len(m.Rows) == 1 {
//		if config.Debug { fmt.Printf("Resultado Single: %+v \n", m.Rows[0]) }
//		valf, _ := strconv.ParseFloat(m.Rows[0][0], 64)
//		promGauge[metric].Set(valf)
//		return
//	}

        for k,v := range config.Tags { Tags[k]=v }
	valac := 0.0
	for _, row := range m.Rows {
                if config.Debug { fmt.Printf("Resultado ROW  %#v --------> %#v \n", row[0], row[1]) }
		category := row[0]
		if !strings.Contains(category, "(not set)") {
			label := buildMetricLabel(row[0])
			for tag, re := range rtTags {
			     res := re.FindStringSubmatch(row[0])
			     if config.Debug { fmt.Printf("   - Tag: %+v    Res: %+v \n", tag, res[1]) }
			     Tags[tag]=res[1]
		        }
			registerMetricVec(label,Tags)
			valf, _ := strconv.ParseFloat(row[1], 64)
			promGaugeVec[label].WithLabelValues(category).Set(valf)
			valac = valac + valf
		}
	}
	promGauge[metric].Set(valac)
}

func buildMetricLabel(action string) string {
	reg, _ := regexp.Compile("[^a-zA-Z0-9]+")
	rows := []string{"rt:", reg.ReplaceAllString(action, "")}
	return strings.Replace(strings.Join(rows, "_"), " ", "_", -1)
}

// getDimensions gets dimensions from one specific metric.
func getDimensions(metric string) string {
	var dimensions string
	for _, arr := range config.Dimensions {
	   for key, val := range arr {
	      if key == metric { dimensions = strings.Join(val, ",") }
	   }
	}
	return dimensions
}

// getFilters gets filters from one specific metric.
func getFilters(metric string) string {
	var filters string
	for _, arr := range config.Filters {
	   for key, val := range arr {
	      if key == metric { filters = strings.Join(val, ",") }
	   }
	}
	return filters
}

// getDynamics gets dynamic tags
func getDynamics(metric string) map[string]*regexp.Regexp {
	var Dynamics map[string]*regexp.Regexp
	Dynamics=make(map[string]*regexp.Regexp)
	for _, arr := range config.Dynamic {
	   for key, val := range arr {
	      if key == metric {
		 for _, dynTag := range val {
		    tag := strings.Split(dynTag,"=")
//		    fmt.Printf(" Tag: %+v => %+v \n", tag[0], tag[1])
	            Dynamics[tag[0]]=regexp.MustCompile(tag[1])
		 }
              }
	   }
	}
	return Dynamics
}

// conf.getConf reads yaml configuration file
func (c *conf) getConf(filename string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil { panic(err) }
	if err = yaml.Unmarshal(data, &c); err != nil { panic(err) }
}

// https://console.developers.google.com/apis/credentials
// 'Service account keys' creds formated file is expected.
// NOTE: the email from the creds has to be added to the Analytics permissions
func getCreds(filename string) (r map[string]string) {
	data, err := ioutil.ReadFile(filename)
	if err != nil { panic(err) }
	if err = json.Unmarshal(data, &r); err != nil { panic(err) }
	return r
}
