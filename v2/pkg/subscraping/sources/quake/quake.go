// Package quake logic
package quake

import (
	"bytes"
	"context"
	"fmt"
	"io/ioutil"
	"strings"
	"time"

	jsoniter "github.com/json-iterator/go"

	"github.com/YouChenJun/subfinder-plus/pkg/subscraping"
)

type quakeResults struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    []struct {
		Service struct {
			HTTP struct {
				Host string `json:"host"`
			} `json:"http"`
		}
	} `json:"data"`
	Meta struct {
		Pagination struct {
			Total int `json:"total"`
		} `json:"pagination"`
	} `json:"meta"`
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
		var pagesize = 100
		// quake api doc https://quake.360.cn/quake/#/help remove "include":["service.http.host"], can get all data
		var requestBody = []byte(fmt.Sprintf(`{"query":"domain: %s", "latest": true, "start":0, "size":%d, "latest":true}`, domain, pagesize))
		resp, err := session.Post(ctx, "https://quake.360.net/api/v3/search/quake_service", "", map[string]string{
			"Content-Type": "application/json", "X-QuakeToken": randomApiKey,
		}, bytes.NewReader(requestBody))
		if err != nil {
			results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
			s.errors++
			session.DiscardHTTPResponse(resp)
			return
		}

		var response quakeResults
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
		if response.Code != 0 {
			results <- subscraping.Result{
				Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", response.Message),
			}
			s.errors++
			return
		}

		if response.Meta.Pagination.Total > 0 {
			for _, quakeDomain := range response.Data {
				subdomain := quakeDomain.Service.HTTP.Host
				if strings.ContainsAny(subdomain, "暂无权限") {
					subdomain = ""
				}
				results <- subscraping.Result{Source: s.Name(), Type: subscraping.Subdomain, Value: subdomain}
				s.results++
			}
			responseStrings = append(responseStrings, string(bodyBytes))
		}
		pages = int(response.Meta.Pagination.Total/pagesize) + 1
		if pages > 1 {
			for currentPage := 2; currentPage <= pages; currentPage++ {
				//限速
				time.Sleep(10 * time.Second)
				var start = (currentPage - 1) * pagesize
				requestBody = []byte(fmt.Sprintf(`{"query":"domain: %s","latest": true, "start":%d, "size":%d ,"latest":true}`, domain, start, pagesize))
				resp, err = session.Post(ctx, "https://quake.360.net/api/v3/search/quake_service", "", map[string]string{
					"Content-Type": "application/json", "X-QuakeToken": randomApiKey,
				}, bytes.NewReader(requestBody))
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					s.errors++
					session.DiscardHTTPResponse(resp)
					continue
				}
				//读取响应信息
				bodyBytes, err = ioutil.ReadAll(resp.Body)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					s.errors++
					resp.Body.Close()
					continue
				}
				err = jsoniter.ConfigCompatibleWithStandardLibrary.Unmarshal(bodyBytes, &response)
				if err != nil {
					results <- subscraping.Result{Source: s.Name(), Type: subscraping.Error, Error: err}
					s.errors++
					continue
				}
				resp.Body.Close()

				if response.Code != 0 {
					results <- subscraping.Result{
						Source: s.Name(), Type: subscraping.Error, Error: fmt.Errorf("%s", response.Message),
					}
					s.errors++
					continue
				}

				if response.Meta.Pagination.Total > 0 {
					for _, quakeDomain := range response.Data {
						subdomain := quakeDomain.Service.HTTP.Host
						if strings.ContainsAny(subdomain, "暂无权限") {
							subdomain = ""
						}
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
	return "quake"
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
