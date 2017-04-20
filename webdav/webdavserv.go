package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"golang.org/x/net/webdav"
)

var dir string

func main() {

	dirFlag := flag.String("d", "./", "Directory to serve from. Default is CWD")
	httpPort := flag.Int("p", 80, "Port to serve on (Plain HTTP)")
	httpsPort := flag.Int("ps", 443, "Port to serve TLS on")
	serveSecure := flag.Bool("s", false, "Serve HTTPS. Default false")

	flag.Parse()

	dir = *dirFlag

	srv := &webdav.Handler{
		FileSystem: webdav.Dir(dir),
		LockSystem: webdav.NewMemLS(),
		Logger: func(r *http.Request, err error) {
			if err != nil {
				log.Printf("WEBDAV [%s][%s]: %s, ERROR: %s\n", r.RemoteAddr, r.Method, r.URL, err)
			} else {
				log.Printf("WEBDAV [%s][%s]: %s \n", r.RemoteAddr, r.Method, r.URL)
			}
		},
	}

	http.Handle("/", srv)

	if *serveSecure == true {
		if _, err := os.Stat("./cert.pem"); err != nil {
			fmt.Println("[x] No cert.pem in current directory. Please provide a valid cert")
			return
		}
		if _, er := os.Stat("./key.pem"); er != nil {
			fmt.Println("[x] No key.pem in current directory. Please provide a valid cert")
			return
		}

		go http.ListenAndServeTLS(fmt.Sprintf(":%d", *httpsPort), "cert.pem", "key.pem", nil)
	}
	if err := http.ListenAndServe(fmt.Sprintf(":%d", *httpPort), nil); err != nil {
		log.Fatalf("Error with WebDAV server: %v", err)
	}

}
