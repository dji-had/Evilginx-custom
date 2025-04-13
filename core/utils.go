package core

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"

	"github.com/kgretzky/evilginx2/log"
)

func GenRandomToken() string {
	rdata := make([]byte, 64)
	_, err := rand.Read(rdata)
	if err != nil {
		log.Error("rand.Read: %v", err)
	}
	hash := sha256.Sum256(rdata)
	token := fmt.Sprintf("%x", hash)
	return token
}

func GenRandomString(n int) string {
	const lb = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	b := make([]byte, n)
	for i := range b {
		t := make([]byte, 1)
		_, err := rand.Read(t)
		if err != nil {
			log.Error("rand.Read: %v", err)
		}
		b[i] = lb[int(t[0])%len(lb)]
	}
	return string(b)
}

func GenRandomAlphanumString(n int) string {
	const lb = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		t := make([]byte, 1)
		_, err := rand.Read(t)
		if err != nil {
			log.Error("rand.Read: %v", err)
		}
		b[i] = lb[int(t[0])%len(lb)]
	}
	return string(b)
}

func CreateDir(path string, perm os.FileMode) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		err = os.Mkdir(path, perm)
		if err != nil {
			return err
		}
	}
	return nil
}

type BaseHTTPRequest struct {
	Method string
	Url    string
	Input  []byte
	JSON   bool
	Client *http.Client
}

func (baseData *BaseHTTPRequest) MakeRequest() ([]byte, error) {
	var err error
	var request *http.Request

	request, err = http.NewRequest(baseData.Method, baseData.Url, bytes.NewReader(baseData.Input))
	if err != nil {
		return nil, err
	}
	if baseData.JSON {
		request.Header.Set("Content-Type", "application/json; charset=UTF-8")
	}
	response, error := baseData.Client.Do(request)
	if error != nil {
		return nil, err
	}
	defer response.Body.Close()
	defer func() {
		if err = response.Body.Close(); err != nil {
			log.Error("error trying to close HTTP response body: %+v", err)
		}
	}()

	body, err := ioutil.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}

	return body, nil

}
