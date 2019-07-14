package main

//gcloud app deploy

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"

	"golang.org/x/oauth2"
)

var oauth2config oauth2.Config

func main() {
	//if running the server locally, load the variables from env.json file
	if os.Getenv("NODE_PROCESS") != "production" {
		readEnvFile("env.json")
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
		log.Printf("Defaulting to port %s", port)
	}

	oauth2config = oauth2.Config{
		ClientID:     os.Getenv("CLIENT_ID"),
		ClientSecret: os.Getenv("CLIENT_SECRET"),
		Scopes:       []string{"read:vat", "write:vat"},
		RedirectURL:  os.Getenv("SERVER_URL") + ":" + port + "/oauth2",
		Endpoint: oauth2.Endpoint{
			AuthURL:  os.Getenv("HMRC_API_URL") + "/oauth/authorize",
			TokenURL: os.Getenv("HMRC_API_URL") + "/oauth/token",
		},
	}

	http.HandleFunc("/", indexHandler)
	// 2 - This displays our state, code and
	// token and expiry time that we get back
	// from our Authorization server
	http.HandleFunc("/oauth2", authHandler)

	log.Printf("Listening on port %s", port)
	log.Fatal(http.ListenAndServe(fmt.Sprintf(":%s", port), nil))
}

func readEnvFile(fileName string) {
	config := make(map[string]interface{})

	//filename is the path to the json config file
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("Error - unable to open file: %s\n", err)
	}

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&config)
	if err != nil {
		log.Fatalf("Error - unable to decode JSON: %s\n", err)
	}

	for k, v := range config {
		os.Setenv(k, fmt.Sprintf("%v", v))
	}
}

// returns the URL to login HMRC
func indexHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	// var hmrcAPIURL url
	u, err := url.ParseRequestURI(os.Getenv("HMRC_API_URL") + "/oauth/authorize")
	if err != nil {
		log.Fatalf("Error - parsing url: %s\n", err)
	}

	q := u.Query()
	q.Add("client_id", os.Getenv("CLIENT_ID"))
	q.Add("redirect_uri", os.Getenv("SERVER_URL")+":"+os.Getenv("PORT")+"/oauth2")
	q.Add("response_type", "code")
	q.Add("scope", "read:vat+write:vat")
	q.Add("state", os.Getenv("STATE_CHECK"))
	u.RawQuery = q.Encode()
	a := "<a href=" + u.String() + ">" + u.String() + "</a>"
	fmt.Fprint(w, a)
}

// Authorize
func authHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Access-Control-Allow-Origin", "*")

	r.ParseForm()
	state := r.Form.Get("state")
	if state != os.Getenv("STATE_CHECK") {
		http.Error(w, "State invalid", http.StatusBadRequest)
		return
	}

	code := r.Form.Get("code")
	if code == "" {
		http.Error(w, "Code not found", http.StatusBadRequest)
		return
	}

	token, err := oauth2config.Exchange(context.Background(), code)
	if err != nil {
		log.Println(err)
		http.Error(w, "Unable to fetch token", http.StatusInternalServerError)
		return
	}

	// return the token
	e := json.NewEncoder(w)
	e.SetIndent("", "  ")
	e.Encode(*token)
}
