package subscraping

import (
	"bufio"
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gologger"
)

const MultipleKeyPartsLength = 2

func PickRandom[T any](v []T, sourceName string) T {
	var result T
	length := len(v)
	if length == 0 {
		gologger.Debug().Msgf("Cannot use the %s source because there was no API key/secret defined for it.", sourceName)
		return result
	}
	return v[rand.Intn(length)]
}

func CreateApiKeys[T any](keys []string, provider func(k, v string) T) []T {
	var result []T
	for _, key := range keys {
		if keyPartA, keyPartB, ok := createMultiPartKey(key); ok {
			result = append(result, provider(keyPartA, keyPartB))
		}
	}
	return result
}

func createMultiPartKey(key string) (keyPartA, keyPartB string, ok bool) {
	parts := strings.Split(key, ":")
	ok = len(parts) == MultipleKeyPartsLength

	if ok {
		keyPartA = parts[0]
		keyPartB = parts[1]
	}

	return
}

func WriteResponseData(response []string, source string, RespFileDirectory string) {
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
			if err := w.writer.Flush(); err != nil {
				fmt.Printf("刷新缓冲区失败: %v\n", err)
			}
			if err := w.file.Close(); err != nil {
				fmt.Printf("关闭文件失败: %v\n", err)
			}
		}
	}()
	for _, data := range response {
		if source == "" || data == "" {
			continue
		}
		w, exists := writers[source]
		if !exists {
			filename := filepath.Join(RespFileDirectory, source+".json")
			file, err := createFile(filename, false)
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
		// 判断是否需要添加换行符
		var line string
		if strings.HasSuffix(data, "\n") {
			line = data // 数据自带换行，无需添加
		} else {
			line = data + "\n" // 数据无换行，手动添加
		}
		if _, err := w.writer.WriteString(line + "\n"); err != nil {
			fmt.Printf("数据写入失败 [%s]: %w\n", source, err)
			continue
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
