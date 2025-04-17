package runner

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	jsoniter "github.com/json-iterator/go"

	"github.com/YouChenJun/subfinder-plus/pkg/resolve"
)

// OutputWriter outputs content to writers.
type OutputWriter struct {
	JSON bool
}

type jsonSourceResult struct {
	Host   string `json:"host"`
	Input  string `json:"input"`
	Source string `json:"source"`
}

type jsonSourceIPResult struct {
	Host   string `json:"host"`
	IP     string `json:"ip"`
	Input  string `json:"input"`
	Source string `json:"source"`
}

type jsonSourcesResult struct {
	Host    string   `json:"host"`
	Input   string   `json:"input"`
	Sources []string `json:"sources"`
}

// NewOutputWriter creates a new OutputWriter
func NewOutputWriter(json bool) *OutputWriter {
	return &OutputWriter{JSON: json}
}

func (o *OutputWriter) createFile(filename string, appendToFile bool) (*os.File, error) {
	if filename == "" {
		return nil, errors.New("empty filename")
	}

	dir := filepath.Dir(filename)

	if dir != "" {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			err := os.MkdirAll(dir, os.ModePerm)
			if err != nil {
				return nil, err
			}
		}
	}

	var file *os.File
	var err error
	if appendToFile {
		file, err = os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	} else {
		file, err = os.Create(filename)
	}
	if err != nil {
		return nil, err
	}

	return file, nil
}

// WriteHostIP writes the output list of subdomain to an io.Writer
func (o *OutputWriter) WriteHostIP(input string, results map[string]resolve.Result, writer io.Writer) error {
	var err error
	if o.JSON {
		err = writeJSONHostIP(input, results, writer)
	} else {
		err = writePlainHostIP(input, results, writer)
	}
	return err
}

func writePlainHostIP(_ string, results map[string]resolve.Result, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for _, result := range results {
		sb.WriteString(result.Host)
		sb.WriteString(",")
		sb.WriteString(result.IP)
		sb.WriteString(",")
		sb.WriteString(result.Source)
		sb.WriteString("\n")

		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}

func writeJSONHostIP(input string, results map[string]resolve.Result, writer io.Writer) error {
	encoder := jsoniter.NewEncoder(writer)

	var data jsonSourceIPResult

	for _, result := range results {
		data.Host = result.Host
		data.IP = result.IP
		data.Input = input
		data.Source = result.Source

		err := encoder.Encode(&data)
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteHostNoWildcard writes the output list of subdomain with nW flag to an io.Writer
func (o *OutputWriter) WriteHostNoWildcard(input string, results map[string]resolve.Result, writer io.Writer) error {
	hosts := make(map[string]resolve.HostEntry)
	for host, result := range results {
		hosts[host] = resolve.HostEntry{Domain: host, Host: result.Host, Source: result.Source}
	}

	return o.WriteHost(input, hosts, writer)
}

// WriteHost writes the output list of subdomain to an io.Writer
func (o *OutputWriter) WriteHost(input string, results map[string]resolve.HostEntry, writer io.Writer) error {
	var err error
	if o.JSON {
		err = writeJSONHost(input, results, writer)
	} else {
		err = writePlainHost(input, results, writer)
	}
	return err
}

func writePlainHost(_ string, results map[string]resolve.HostEntry, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for _, result := range results {
		sb.WriteString(result.Host)
		sb.WriteString("\n")

		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}

func writeJSONHost(input string, results map[string]resolve.HostEntry, writer io.Writer) error {
	encoder := jsoniter.NewEncoder(writer)

	var data jsonSourceResult
	for _, result := range results {
		data.Host = result.Host
		data.Input = input
		data.Source = result.Source
		err := encoder.Encode(data)
		if err != nil {
			return err
		}
	}
	return nil
}

// WriteSourceHost writes the output list of subdomain to an io.Writer
func (o *OutputWriter) WriteSourceHost(input string, sourceMap map[string]map[string]struct{}, writer io.Writer) error {
	var err error
	if o.JSON {
		err = writeSourceJSONHost(input, sourceMap, writer)
	} else {
		err = writeSourcePlainHost(input, sourceMap, writer)
	}
	return err
}

func writeSourceJSONHost(input string, sourceMap map[string]map[string]struct{}, writer io.Writer) error {
	encoder := jsoniter.NewEncoder(writer)

	var data jsonSourcesResult

	for host, sources := range sourceMap {
		data.Host = host
		data.Input = input
		keys := make([]string, 0, len(sources))
		for source := range sources {
			keys = append(keys, source)
		}
		data.Sources = keys

		err := encoder.Encode(&data)
		if err != nil {
			return err
		}
	}
	return nil
}

func writeSourcePlainHost(_ string, sourceMap map[string]map[string]struct{}, writer io.Writer) error {
	bufwriter := bufio.NewWriter(writer)
	sb := &strings.Builder{}

	for host, sources := range sourceMap {
		sb.WriteString(host)
		sb.WriteString(",[")
		sourcesString := ""
		for source := range sources {
			sourcesString += source + ","
		}
		sb.WriteString(strings.Trim(sourcesString, ", "))
		sb.WriteString("]\n")

		_, err := bufwriter.WriteString(sb.String())
		if err != nil {
			bufwriter.Flush()
			return err
		}
		sb.Reset()
	}
	return bufwriter.Flush()
}

func WriteResponseData(results map[string][]resolve.ResponseData, RespFileDirectory string) {
	if !strings.HasSuffix(RespFileDirectory, "/") {
		RespFileDirectory += "/"
	}
	writers := make(map[string]struct {
		file   *os.File
		writer *bufio.Writer
	})

	// 统一清理资源
	defer func() {
		for _, w := range writers {
			// 确保先刷新缓冲区
			if err := w.writer.Flush(); err != nil {
				fmt.Printf("刷新缓冲区失败: %v\n", err)
			}
			// 然后关闭文件
			if err := w.file.Close(); err != nil {
				fmt.Printf("关闭文件失败: %v\n", err)
			}
		}
	}()

	for source, responseDataSlice := range results {
		if source == "" {
			continue
		}

		w, exists := writers[source]
		if !exists {
			filename := filepath.Join(RespFileDirectory, source+".json")
			file, err := createFile(filename, false) // 使用 createFile 方法，不追加内容
			if err != nil {
				fmt.Printf("创建文件失败 [%s]: %w\n", filename, err)
				continue
			}

			w = struct {
				file   *os.File
				writer *bufio.Writer
			}{
				file:   file,
				writer: bufio.NewWriter(file),
			}
			writers[source] = w
		}

		for _, responseData := range responseDataSlice {
			data := responseData.Response + "\n"

			// 执行缓冲写入
			if _, err := w.writer.WriteString(data); err != nil {
				fmt.Printf("数据写入失败 [%s]: %w\n", source, err)
				continue
			}
		}

		// 立即刷新缓冲区 如需保证实时写入可启用，但会影响性能
		if err := w.writer.Flush(); err != nil {
			fmt.Printf("缓冲区刷新失败 [%s]: %w\n", source, err)
		}
	}
}
func createFile(filename string, appendToFile bool) (*os.File, error) {
	if filename == "" {
		return nil, errors.New("empty filename")
	}

	dir := filepath.Dir(filename)

	if dir != "" {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			err := os.MkdirAll(dir, os.ModePerm)
			if err != nil {
				return nil, err
			}
		}
	}

	var file *os.File
	var err error
	if appendToFile {
		file, err = os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	} else {
		file, err = os.Create(filename)
	}
	if err != nil {
		return nil, err
	}

	return file, nil
}
