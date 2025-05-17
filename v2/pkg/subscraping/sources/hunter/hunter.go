package hunter

import (
	"context"
	"encoding/base64"
	"fmt"
	"io/ioutil"
	"time"

	"github.com/YouChenJun/subfinder-plus/pkg/subscraping"
	jsoniter "github.com/json-iterator/go"
)

type hunterResp struct {
	Code    int        `json:"code"`
	Data    hunterData `json:"data"`
	Message string     `json:"message"`
}

type infoArr struct {
	URL      string `json:"url"`
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	Domain   string `json:"domain"`
	Protocol string `json:"protocol"`
}

type hunterData struct {
	InfoArr []infoArr `json:"arr"`
	Total   int       `json:"total"`
}

// Source is the passive scraping agent
type Source struct {
	apiKeys   []string
	timeTaken time.Duration
	errors    int
	results   int
	skipped   bool
}

// Run function returns all subdomains found with the service
func (s *Source) Run(ctx context.Context, domain string, session *subscraping.Session) <-chan subscraping.Result {
	results := make(chan subscraping.Result)
	s.errors = 0
	s.results = 0
	var responseStrings []string

	go func() {
		defer func(startTime time.Time) {
			s.timeTaken = time.Since(startTime)
			close(results)
		}(time.Now())

		randomApiKey := subscraping.PickRandom(s.apiKeys, s.Name())
		if randomApiKey == "" {
			s.skipped = true
			return
		}

		var pages = 1
		// hunter api doc https://hunter.qianxin.com/home/helpCenter?r=5-1-2
		qbase64 := base64.URLEncoding.EncodeToString([]byte(fmt.Sprintf("domain=\"%s\"", domain)))
		resp, err := session.SimpleGet(ctx, fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=1&page_size=100&is_web=3", randomApiKey, qbase64))
		if err != nil && resp == nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		var response hunterResp
		// 先读取响应体内容
		bodyBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}
		defer resp.Body.Close() // 确保 Body 被关

		err = jsoniter.ConfigCompatibleWithStandardLibrary.Unmarshal(bodyBytes, &response)
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			return
		}
		fmt.Println(response.Code)
		if response.Code == 401 || response.Code == 400 || response.Code == 4024 {
			results <- subscraping.Result{
				Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", response.Message),
			}
			s.errors++
			return
		}

		if response.Data.Total > 0 {
			for _, hunterInfo := range response.Data.InfoArr {
				subdomain := hunterInfo.Domain
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
				s.results++
			}
			responseStrings = append(responseStrings, string(bodyBytes))
		}
		//count pages
		pages = int(response.Data.Total/100) + 1
		if pages > 1 {
			for currentPage := 2; currentPage <= pages; currentPage++ {
				time.Sleep(5 * time.Second)
				resp, err = session.SimpleGet(ctx, fmt.Sprintf("https://hunter.qianxin.com/openApi/search?api-key=%s&search=%s&page=%d&page_size=100&is_web=3", randomApiKey, qbase64, currentPage))
				if err != nil && resp == nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					s.errors++
					session.DiscardHTTPResponse(resp)
					continue
				}
				// 先读取响应体内容
				bodyBytes, err = ioutil.ReadAll(resp.Body)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					s.errors++
					return
				}
				defer resp.Body.Close() // 确保 Body 被关

				err = jsoniter.ConfigCompatibleWithStandardLibrary.Unmarshal(bodyBytes, &response)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					s.errors++
					continue
				}
				fmt.Println(response.Code)
				//if code == 4024 this means that your api may have insufficient balance
				if response.Code == 401 || response.Code == 400 || response.Code == 4024 {
					results <- subscraping.Result{
						Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", response.Message),
					}
					s.errors++
					continue
				}

				if response.Data.Total > 0 {
					for _, hunterInfo := range response.Data.InfoArr {
						subdomain := hunterInfo.Domain
						results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
						s.results++
					}
					responseStrings = append(responseStrings, string(bodyBytes))
				}
			}
		}
		subscraping.WriteResponseData(responseStrings, s.Name(), session.RespFileDirectory)
	}()

	return results
}

// Name returns the name of the source
func (s *Source) Name() string {
	return "hunter"
}

func (s *Source) IsDefault() bool {
	return true
}

func (s *Source) HasRecursiveSupport() bool {
	return false
}

func (s *Source) NeedsKey() bool {
	return true
}

func (s *Source) AddApiKeys(keys []string) {
	s.apiKeys = keys
}

func (s *Source) Statistics() subscraping.Statistics {
	return subscraping.Statistics{
		Errors:    s.errors,
		Results:   s.results,
		TimeTaken: s.timeTaken,
		Skipped:   s.skipped,
	}
}
