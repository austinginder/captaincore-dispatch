package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/gorilla/websocket"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme/autocert"
)

const letternumberBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var db *gorm.DB
var err error
var config = LoadConfiguration("config.json")
var debug bool

//var clients = make(map[*websocket.Conn]bool) // connected clients
type Client struct {
	Token string
	// The websocket connection.
	conn *websocket.Conn

	// Buffered channel of outbound messages.
	send chan []byte
}

var clients []Client

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool {
		return true
	},
	ReadBufferSize:  1024,
	WriteBufferSize: 1024,
}

type httpHandlerFunc func(http.ResponseWriter, *http.Request)

const (
	htmlIndex = `<html><body>Welcome!</body></html>`
)

// Define our message object
type SocketRequest struct {
	Token  string `json:"token"`
	Action string `json:"action"`
}

type SocketResponse struct {
	Token  string `json:"token"`
	TaskID string `json:"task_id"`
}

type Config struct {
	Tokens []struct {
		CaptainID string `json:"captain_id"`
		Token     string `json:"token"`
	} `json:"tokens"`
	Servers []struct {
		Name     string `json:"name"`
		Address  string `json:"address"`
		Requires []struct {
			Command string `json:"command"`
		} `json:"requires"`
	} `json:"servers"`
	Host    string `json:"host"`
	Port    string `json:"port"`
	SSLMode string `json:"ssl_mode"`
}

type Task struct {
	gorm.Model
	CaptainID int
	ProcessID int
	Command   string
	Status    string
	Response  string
	Origin    string
	Token     string
}

type Origin struct {
	ID     string
	Server string
	Token  string
}

func LoadConfiguration(file string) Config {
	var config Config
	configFile, err := os.Open(file)
	defer configFile.Close()
	if err != nil {
		fmt.Println(err.Error())
	}
	jsonParser := json.NewDecoder(configFile)
	jsonParser.Decode(&config)
	return config
}

func fetchCaptainID(t string, r *http.Request) string {
	for _, v := range config.Tokens {
		if v.Token == t {
			return v.CaptainID
		}
	}
	return "0"
}

func fetchToken(captainID string) string {
	for _, v := range config.Tokens {
		if v.CaptainID == captainID {
			return v.Token
		}
	}
	return "0"
}

func generateToken() string {
	n := 48
	output := make([]byte, n)
	// We will take n bytes, one byte for each character of output.
	randomness := make([]byte, n)
	// read all random
	_, err := rand.Read(randomness)
	if err != nil {
		panic(err)
	}
	l := len(letternumberBytes)
	// fill output
	for pos := range output {
		// get random item
		random := uint8(randomness[pos])
		// random % 64
		randomPos := random % uint8(l)
		// put into output
		output[pos] = letternumberBytes[randomPos]
	}
	o := string(output)
	return o
}

func deferCommand(c string) string {
	for _, v := range config.Servers {
		for _, r := range v.Requires {
			if r.Command == c {
				return v.Address
			}
		}
	}
	return "0"
}

func generateCertificateAuthority() {
	ca := &x509.Certificate{
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization:  []string{"CaptainCore"},
			Country:       []string{"USA"},
			Province:      []string{"PA"},
			Locality:      []string{"Lancaster"},
			StreetAddress: []string{"342 N Queen St"},
			PostalCode:    []string{"17603"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey
	caB, err := x509.CreateCertificate(rand.Reader, ca, ca, pub, priv)
	if err != nil {
		log.Println("create ca failed", err)
		return
	}

	// Public key
	certOut, err := os.Create("certs/ca.crt")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: caB})
	certOut.Close()
	log.Print("written certs/cat.crt\n")

	// Private key
	keyOut, err := os.OpenFile("certs/ca.key", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Print("written certs/ca.key\n")
}

func generateCert() {

	// Load CA
	catls, err := tls.LoadX509KeyPair("certs/ca.crt", "certs/ca.key")
	if err != nil {
		panic(err)
	}
	ca, err := x509.ParseCertificate(catls.Certificate[0])
	if err != nil {
		panic(err)
	}

	// Prepare certificate
	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization:  []string{"CaptainCore"},
			Country:       []string{"USA"},
			Province:      []string{"PA"},
			Locality:      []string{"Lancaster"},
			StreetAddress: []string{"342 N Queen St"},
			PostalCode:    []string{"17603"},
			CommonName:    "CaptainCore",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		SubjectKeyId:          []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
	}

	priv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pub := &priv.PublicKey

	// Sign the certificate
	certB, err := x509.CreateCertificate(rand.Reader, cert, ca, pub, catls.PrivateKey)

	// Public key
	certOut, err := os.Create("certs/cert.pem")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: certB})
	certOut.Close()
	log.Print("written certs/cert.pem\n")

	// Private key
	keyOut, err := os.OpenFile("certs/key.pem", os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	log.Print("written certs/key.pem\n")
}

func allTasks(w http.ResponseWriter, r *http.Request) {
	var tasks []Task
	vars := mux.Vars(r)
	token := r.Header.Get("token")
	captainID := fetchCaptainID(token, r)
	page, _ := strconv.Atoi(vars["page"])
	if page > 0 {
		offset := page * 10
		db.Offset(offset).Limit(10).Order("created_at desc").Where("captain_id = ?", captainID).Find(&tasks)
	} else {
		db.Limit(10).Order("created_at desc").Where("captain_id = ?", captainID).Find(&tasks)
	}

	json.NewEncoder(w).Encode(tasks)
}

func newRun(w http.ResponseWriter, r *http.Request) {
	var task Task
	json.NewDecoder(r.Body).Decode(&task)
	token := r.Header.Get("token")
	randomToken := generateToken()
	captainID := fetchCaptainID(token, r)

	task.Status = "Started"
	task.CaptainID, err = strconv.Atoi(captainID)
	task.Token = randomToken

	db.Create(&task)

	// Starts running CaptainCore command
	response := runCommand("captaincore "+task.Command+" --captain_id="+captainID, task)
	fmt.Fprintf(w, response)

}

func newBackground(w http.ResponseWriter, r *http.Request) {
	var task Task
	json.NewDecoder(r.Body).Decode(&task)
	token := r.Header.Get("token")
	randomToken := generateToken()
	captainID := fetchCaptainID(token, r)

	task.Status = "Started"
	task.CaptainID, err = strconv.Atoi(captainID)
	task.Token = randomToken

	db.Create(&task)

	// Starts running CaptainCore command
	go runCommand("captaincore "+task.Command+" --captain_id="+captainID, task)
	fmt.Fprintf(w, "Successfully Started Task " + task.Token)
}

func newTask(w http.ResponseWriter, r *http.Request) {
	var task Task
	json.NewDecoder(r.Body).Decode(&task)
	token := r.Header.Get("token")
	randomToken := generateToken()
	captainID := fetchCaptainID(token, r)
	task.Status = "Queued"
	task.CaptainID, err = strconv.Atoi(captainID)
	task.Token = randomToken

	db.Create(&task)
	taskID := strconv.FormatUint(uint64(task.ID), 10)
	response := "{ \"task_id\" : " + taskID + ", \"token\" : \"" + randomToken + "\" }"
	fmt.Fprintf(w, response)

}

func deleteTask(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	command := vars["command"]

	var tasks Task
	db.Where("command = ?", command).Find(&tasks)
	db.Delete(&tasks)

	fmt.Fprintf(w, "Successfully Deleted Task")
}

func viewTask(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	id := vars["id"]
	token := r.Header.Get("token")
	captainID := fetchCaptainID(token, r)

	var tasks Task
	db.Where("id = ?", id).Where("captain_id = ?", captainID).Find(&tasks)
	fmt.Println("{}", tasks)
	json.NewEncoder(w).Encode(tasks)
}

func updateTask(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	id := vars["id"]
	token := r.Header.Get("token")
	captainID := fetchCaptainID(token, r)

	var task Task
	db.Where("id = ?", id).Where("captain_id = ?", captainID).Find(&task)
	task.Status = "Completed"
	db.Save(&task)

	fmt.Fprintf(w, "Successfully Updated Task")
}

func faviconAppleHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "img/apple-touch-icon.png")
}

func faviconHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "img/favicon.ico")
}

func wsHandler(w http.ResponseWriter, r *http.Request) {
	// Upgrade initial GET request to a websocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Fatal(err)
	}
	// Make sure we close the connection when the function returns
	defer conn.Close()

	newClient := Client{Token: "", conn: conn, send: make(chan []byte, 256)}
	clients = append(clients, newClient)
	log.Println("Successfully established connection", clients)

	for {
		data := SocketRequest{}
		err := conn.ReadJSON(&data)
		if err != nil {
			fmt.Println("Error reading json.", err)
		}

		var task Task
		db.Where("token = ?", data.Token).Find(&task)

		// Refuse connection if token not valid
		if task.Token == "" {

			// Find current connection and remove from clients
			for i := 0; i < len(clients); i++ {
				if clients[i].conn == conn {
					log.Println("Removing client: ", clients[i])
					clients = append(clients[:i], clients[i+1:]...)
					i-- // form the remove item index to start iterate next item
				}
			}
			break

		}

		// Find current connection and update Token
		for i := 0; i < len(clients); i++ {
			if clients[i].conn == conn {
				clients[i].Token = data.Token
				break
			}
		}

		// Execute job if requested
		if data.Action == "start" {
			captainID := strconv.Itoa(task.CaptainID)
			go runCommand("captaincore "+task.Command+" --captain_id="+captainID, task)
		}
		if data.Action == "kill" {
			go killCommand(task)
		}
		log.Println("Socket data request:", data)
		log.Println("Executing command for client:", clients)

	}
}

func handleRequests() {

	var httpsSrv *http.Server
	var httpSrv *http.Server
	var m *autocert.Manager

	router := mux.NewRouter().StrictSlash(true)
	router.HandleFunc("/apple-touch-icon.png", faviconAppleHandler).Methods("GET")
	router.HandleFunc("/favicon.ico", faviconHandler).Methods("GET")
	router.HandleFunc("/task/{id}", checkSecurity(viewTask)).Methods("GET")
	router.HandleFunc("/task/{id}", checkSecurity(updateTask)).Methods("PUT")
	router.HandleFunc("/task/{id}", checkSecurity(deleteTask)).Methods("DELETE")
	router.HandleFunc("/tasks", checkSecurity(newTask)).Methods("POST")
	router.HandleFunc("/tasks", checkSecurity(allTasks)).Methods("GET")
	router.HandleFunc("/tasks/{page}", checkSecurity(allTasks)).Methods("GET")
	router.HandleFunc("/run", checkSecurity(newRun)).Methods("POST")
	router.HandleFunc("/run/background", checkSecurity(newBackground)).Methods("POST")
	router.HandleFunc("/ws", wsHandler)

	if config.SSLMode == "development" {

		// Generate ca.crt and ca.key if not found
		caFile, err := os.Open("certs/ca.crt")
		if err != nil {
			generateCertificateAuthority()
		}
		defer caFile.Close()

		// Generate cert.pem and key.pem for https://localhost
		generateCert()

		// Launch HTTPS server
		fmt.Println("Starting server https://" + config.Host)
		log.Fatal(http.ListenAndServeTLS(":"+config.Port, "certs/cert.pem", "certs/key.pem", handlers.LoggingHandler(os.Stdout, router)))

	}
	if config.SSLMode == "production" {

		// Manage Let's Encrypt SSL

		// Note: use a sensible value for data directory
		// this is where cached certificates are stored

		httpsSrv = &http.Server{
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
			IdleTimeout:  120 * time.Second,
			Handler:      router,
		}

		//  handlers.LoggingHandler(os.Stdout, router

		dataDir := "certs/"
		hostPolicy := func(ctx context.Context, host string) error {
			// Note: change to your real domain
			allowedHost := config.Host
			if host == allowedHost {
				return nil
			}
			return fmt.Errorf("acme/autocert: only %s host is allowed", allowedHost)
		}

		m = &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: hostPolicy,
			Cache:      autocert.DirCache(dataDir),
		}

		httpsSrv.Addr = config.Host + ":443"
		httpsSrv.TLSConfig = &tls.Config{GetCertificate: m.GetCertificate}

		// Spin up web server on port 80 to listen for autocert HTTP challenge
		httpSrv = makeHTTPServer()
		httpSrv.Addr = ":80"

		// allow autocert handle Let's Encrypt auth callbacks over HTTP.
		if m != nil {
			// https://github.com/golang/go/issues/21890
			httpSrv.Handler = m.HTTPHandler(httpSrv.Handler)
		}

		// Launch HTTP server
		go func() {
			fmt.Println("Starting server http://localhost")
			err := httpSrv.ListenAndServe()
			if err != nil {
				log.Fatalf("httpSrv.ListenAndServe() failed with %s", err)
			}
		}()

		// Launch HTTPS server
		fmt.Println("Starting server https://" + config.Host)
		log.Fatal(httpsSrv.ListenAndServeTLS("", ""))

	}

}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	io.WriteString(w, htmlIndex)
}

func makeServerFromMux(mux *http.ServeMux) *http.Server {
	// set timeouts so that a slow or malicious client doesn't
	// hold resources forever
	return &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
		IdleTimeout:  120 * time.Second,
		Handler:      mux,
	}
}

func makeHTTPServer() *http.Server {
	mux := &http.ServeMux{}
	mux.HandleFunc("/", handleIndex)
	return makeServerFromMux(mux)

}

func initialMigration() {

	// Migrate the schema
	db.AutoMigrate(&Task{})

}

func isJSON(str string) bool {
	var js json.RawMessage
	return json.Unmarshal([]byte(str), &js) == nil
}

func killCommand(t Task) {
	syscall.Kill(-t.ProcessID, syscall.SIGKILL)
	syscall.Kill(t.ProcessID, syscall.SIGKILL)
	log.Println("Process killed ", strconv.Itoa(t.ProcessID))
}

func runCommand(cmd string, t Task) string {

	// See https://regexr.com/4154h for custom regex to parse commands
	// Inspired by https://gist.github.com/danesparza/a651ac923d6313b9d1b7563c9245743b
	pattern := `(--[^\s]+="[^"]+")|"([^"]+)"|'([^']+)'|([^\s]+)`
	parts := regexp.MustCompile(pattern).FindAllString(cmd, -1)

	// The first part is the command, the rest are the args:
	head := parts[0]
	arguments := parts[1:len(parts)]

	// log.Println("Hunting for socket with token ", t.Token)

	// Find current connection write data
	var client Client
	for _, c := range clients {
		log.Println("Client:", c.Token)
		if c.Token == t.Token {
			client = c
			break
		}
	}

	// If site command then loop through servers and reply a bare version of the command
	if len(config.Servers) >= 1 && parts[1] == "site" {

		relayCommand := strings.Replace(t.Command, "site ", "site bare-", 1)
		relayCommand = strings.Replace(relayCommand, "\"", "\\\"", -1)
		captainID := strconv.Itoa(t.CaptainID)
		token := fetchToken(captainID)

		for _, v := range config.Servers {
			fmt.Println("Relaying " + relayCommand + " to server " + v.Address)
			url := "https://" + v.Address + "/run"
			var jsonStr = []byte(`{"command":"` + relayCommand + `"}`)
			req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
			req.Header.Add("token", token)
			req.Header.Add("Content-Type", "application/json")

			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				fmt.Println(err)
				continue
			}
			err = resp.Body.Close()
			if err != nil {
				log.Fatal(err)
				continue
			}

			if debug == true {
				body, _ := ioutil.ReadAll(resp.Body)
				fmt.Println(string(body))
			}

		}
	}

	// Defer command to defined CaptainCore server
	deferServer := deferCommand(parts[1])
	if deferServer != "0" {
		fmt.Println("Defering " + t.Command + " to server " + deferServer)
		captainID := strconv.Itoa(t.CaptainID)
		token := fetchToken(captainID)
		taskID := strconv.FormatUint(uint64(t.ID), 10)
		origin := `{\"id\":\"` + taskID + `\",\"server\":\"` + config.Host + `\",\"token\":\"` + token + `\"}`
		var jsonStr = []byte(`{"command":"` + t.Command + `","origin":"` + origin + `"}`)
		fmt.Println(bytes.NewBuffer(jsonStr))

		// Build URL
		url := "https://" + deferServer + "/tasks"

		req, _ := http.NewRequest("POST", url, bytes.NewBuffer(jsonStr))
		req.Header.Add("token", token)
		req.Header.Add("Content-Type", "application/json")

		httpclient := &http.Client{}
		resp, err := httpclient.Do(req)
		if err != nil {
			fmt.Println(err)
		}

		//fmt.Println("response Status:", resp.Status)
		//fmt.Println("response Headers:", resp.Header)
		body, _ := ioutil.ReadAll(resp.Body)
		res := SocketResponse{}
		json.Unmarshal(body, &res)
		fmt.Println("response Body:", res.Token)

		t.Status = "Started"
		t.Response = string(body)

		db.Save(&t)

		response := "{ \"task_id\" : " + taskID + "}"

		// If socket found then connect to deferred server web socket and start the task
		if client.Token == t.Token {

			u := "wss://" + deferServer + "/ws"
			log.Printf("connecting to %s", u)
			c, _, err := websocket.DefaultDialer.Dial(u, nil)
			if err != nil {
				log.Fatal("dial:", err)
			}
			defer c.Close()
			done := make(chan struct{})

			// Start command on remote server
			jsonMessage := "{ \"token\" : \"" + res.Token + "\", \"action\" : \"start\" }"
			c.WriteMessage(websocket.TextMessage, []byte(jsonMessage))
			if debug == true {
				log.Println("Writting to socket:", client)
				log.Println("Starting command on deferred server:", jsonMessage)
			}

			// Relay that stream output back to current client
			go func() {
				defer close(done)
				for {
					_, message, errRead := c.ReadMessage()
					if errRead != nil {
						log.Println("read:", errRead)
						return
					}
					// Write data to websocket if found
					client.conn.WriteMessage(1, message)
				}
			}()
			for {
				select {
				case <-done:
					// Clean up websocket if found
					client.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
					client.conn.Close()
					break
				}
			}
		}

		return response
	}

	// Loop through arguments and remove quotes from ---command="" due to bug
	for i, v := range arguments {
		if strings.HasPrefix(v, "--command=") {
			newArgument := strings.Replace(v, "\"", "", 1)
			newArgument = strings.Replace(newArgument, "\"", "", -1)
			arguments[i] = newArgument
		}
	}

	// Format the command
	command := exec.Command(head, arguments...)

	// Sanity check -- capture stdout and stderr:
	stdout, _ := command.StdoutPipe() // Standard out: out.String()
	stderr, _ := command.StderrPipe() // Standard errors: stderr.String()

	// Setup process group
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Run the command
	err := command.Start()

	// Grab proccess id
	t.ProcessID = command.Process.Pid
	db.Save(&t)

	if debug == true {
		fmt.Println("Starting command process ID " + strconv.Itoa(command.Process.Pid))
	}
	if err != nil {
		log.Fatalf("cmd.Start() failed with '%s'\n", err)
	}

	s := bufio.NewScanner(io.MultiReader(stdout, stderr))
	lines := []string{}
	for s.Scan() {
		// Write data to websocket if found
		if client.Token == t.Token {
			if debug == true {
			log.Println("Writting to socket:", client)
			}
			client.conn.WriteMessage(1, s.Bytes())
		}
		// Write data for final output
		lines = append(lines, s.Text())
	}

	err = command.Wait()
	if err != nil {
		client.conn.WriteMessage(1, []byte("Error: "+err.Error()))
		client.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		client.conn.Close()
	}

	// Clean up websocket if found
	if client.Token == t.Token {
		client.conn.WriteMessage(1, []byte("Finished."))
		client.conn.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
		client.conn.Close()
	}

	t.Status = "Completed"

	// If origin set then make request to mark that completed
	if t.Origin != "" {
		var origin Origin
		json.Unmarshal([]byte(t.Origin), &origin)

		fmt.Println("Updating origin server " + origin.Server + " Job ID " + origin.ID)

		// Build URL
		url := "https://" + origin.Server + "/task/" + origin.ID

		client := &http.Client{}
		client.Timeout = time.Second * 15

		req, err := http.NewRequest(http.MethodPut, url, nil)
		if err != nil {
			log.Fatalf("http.NewRequest() failed with '%s'\n", err)
		}

		req.Header.Set("Content-Type", "application/json; charset=utf-8")
		req.Header.Add("token", origin.Token)

		resp, err := client.Do(req)
		if err != nil {
			log.Fatalf("client.Do() failed with '%s'\n", err)
		}

		defer resp.Body.Close()
		if err != nil {
			log.Fatalf("ioutil.ReadAll() failed with '%s'\n", err)
		}
	}

	// Add results to db if in JSON format
	//if isJSON(stdout.String()) {
	//t.Response = stdout.String()
	//}

	db.Save(&t)

	output := strings.Join(lines, "\n")

	if debug == true {

		log.Println("scanner output:", lines)

		// Loop through and output command arguments
		// fmt.Println(strings.Join(arguments, ", "))
		for _, v := range command.Args {
			fmt.Println(v)
		}
		//fmt.Println(stdout.String())
		//fmt.Println(stderr.String())
	}

	return output //stdout.String()

}

func serverCmd() *cobra.Command {
	return &cobra.Command{
		Use: "server",
		RunE: func(cmd *cobra.Command, args []string) error {

			// Handle Subsequent requests
			handleRequests()

			return nil
		},
	}
}

func checkSecurity(next httpHandlerFunc) httpHandlerFunc {
	return func(res http.ResponseWriter, req *http.Request) {
		header := req.Header.Get("token")
		unauthorized := true
		for _, v := range config.Tokens {
			if v.Token == header {
				unauthorized = false
			}
		}
		if unauthorized {
			res.WriteHeader(http.StatusUnauthorized)
			res.Write([]byte("401 - Unauthorized"))
			return
		}
		next(res, req)
	}
}

// main function to boot up everything
func main() {

	db, err = gorm.Open("sqlite3", "sql.db")
	if err != nil {
		panic("failed to connect database")
	}
	defer db.Close()

	initialMigration()

	cmd := &cobra.Command{
		Use:     "captaincore-dispatch",
		Short:   "CaptainCore Dispatch Server 💻",
		Version: "0.1.6",
	}

	cmd.SetUsageTemplate(`[33mUsage:[0m{{if .Runnable}}
  {{.UseLine}}{{end}}{{if .HasAvailableSubCommands}}
  {{.CommandPath}} [command]{{end}}{{if gt (len .Aliases) 0}}

Aliases:
  {{.NameAndAliases}}{{end}}{{if .HasExample}}

Examples:
{{.Example}}{{end}}{{if .HasAvailableSubCommands}}

[33mAvailable Commands:[0m {{range .Commands}}{{if (or .IsAvailableCommand (eq .Name "help"))}}
  {{rpad .Name .NamePadding }} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableLocalFlags}}

[33mFlags:[0m 
{{.LocalFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasAvailableInheritedFlags}}

Global Flags:
{{.InheritedFlags.FlagUsages | trimTrailingWhitespaces}}{{end}}{{if .HasHelpSubCommands}}

Additional help topics:{{range .Commands}}{{if .IsAdditionalHelpTopicCommand}}
  {{rpad .CommandPath .CommandPathPadding}} {{.Short}}{{end}}{{end}}{{end}}{{if .HasAvailableSubCommands}}

Use "{{.CommandPath}} [command] --help" for more information about a command.{{end}}
`)
	cmdServerCmd := serverCmd()
	cmd.AddCommand(cmdServerCmd)
	cmdServerCmd.Flags().BoolVar(&debug, "debug", false, "Debug")

	if err := cmd.Execute(); err != nil {
		//fmt.Println(err)
		os.Exit(0)
	}

}
