package main

import (
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
	"log"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/sqlite"
	"github.com/spf13/cobra"
	"golang.org/x/crypto/acme/autocert"
)

var db *gorm.DB
var err error
var config = LoadConfiguration("config.json")
var debug bool

type httpHandlerFunc func(http.ResponseWriter, *http.Request)

const (
	htmlIndex = `<html><body>Welcome!</body></html>`
)

type Config struct {
	Token   string `json:"token"`
	Host    string `json:"host"`
	Port    string `json:"port"`
	SSLMode string `json:"ssl_mode"`
}

type Task struct {
	gorm.Model
	Command  string
	Status   string
	Response string
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
	page, _ := strconv.Atoi(vars["page"])
	if page > 0 {
		offset := page * 10
		db.Offset(offset).Limit(10).Order("created_at desc").Find(&tasks)
	} else {
		db.Limit(10).Order("created_at desc").Find(&tasks)
	}

	json.NewEncoder(w).Encode(tasks)
}

func newRun(w http.ResponseWriter, r *http.Request) {
	var task Task
	json.NewDecoder(r.Body).Decode(&task)

	task.Status = "Started"

	db.Create(&task)

	// Starts running CaptainCore command
	response := runCommand("captaincore "+task.Command, task)
	fmt.Fprintf(w, response)

}

func newTask(w http.ResponseWriter, r *http.Request) {
	var task Task
	json.NewDecoder(r.Body).Decode(&task)

	task.Status = "Started"

	db.Create(&task)
	taskID := strconv.FormatUint(uint64(task.ID), 10)
	response := "{ \"task_id\" : " + taskID + "}"
	fmt.Fprintf(w, response)

	// Starts running CaptainCore command
	go runCommand("captaincore "+task.Command, task)

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

	var tasks Task
	db.Where("id = ?", id).Find(&tasks)
	fmt.Println("{}", tasks)
	json.NewEncoder(w).Encode(tasks)
}

func updateTask(w http.ResponseWriter, r *http.Request) {

	vars := mux.Vars(r)
	command := vars["command"]

	var tasks Task
	db.Where("command = ?", command).Find(&tasks)

	tasks.Command = command

	db.Save(&tasks)
	fmt.Fprintf(w, "Successfully Updated Task")
}

func faviconAppleHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "img/apple-touch-icon.png")
}

func faviconHandler(w http.ResponseWriter, r *http.Request) {
	http.ServeFile(w, r, "img/favicon.ico")
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
		fmt.Println("Starting server https://" + config.Host + ":" + config.Port)
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

		fmt.Println("Starting server https://" + config.Host + ":" + config.Port)
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

func runCommand(cmd string, t Task) string {

	// See https://regexr.com/4154h for custom regex to parse commands
	// Inspired by https://gist.github.com/danesparza/a651ac923d6313b9d1b7563c9245743b
	pattern := `(--[^\s]+="[^"]+")|"([^"]+)"|'([^']+)'|([^\s]+)`
	parts := regexp.MustCompile(pattern).FindAllString(cmd, -1)

	//	The first part is the command, the rest are the args:
	head := parts[0]
	arguments := parts[1:len(parts)]

	//	Format the command
	command := exec.Command(head, arguments...)

	//	Sanity check -- capture stdout and stderr:
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout // Standard out: out.String()
	command.Stderr = &stderr // Standard errors: stderr.String()

	//	Run the command
	command.Run()

	t.Status = "Completed"

	// Add results to db if in JSON format
	if isJSON(stdout.String()) {
		t.Response = stdout.String()
	}

	db.Save(&t)

	if debug == true {
		fmt.Println(stdout.String())
	}

	return stdout.String()

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
		if header != config.Token {
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
		Version: "0.1.1",
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
