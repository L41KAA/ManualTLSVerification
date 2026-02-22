package main

import (
    "bufio"
	"crypto/x509"
    "crypto/sha1"
	"fmt"
	"net"
    "os"
    "strings"
    "time"

	tls "github.com/refraction-networking/utls"
)

func log(format string, args ...any){
    timestamp := time.Now().Format(time.Stamp)
    fmt.Printf("[%s] " + format + "\n", append([]any{timestamp}, args...)...)
}

func make_request(domain string, port string, knownHashes *[]string){
    domain_port := fmt.Sprintf("%s:%s", domain, port)
	tcpConn, err := net.Dial("tcp", domain_port)
	if err != nil {
		log("TCP Connect Error: '%v'\n", err)
        os.Exit(1)
	}
	defer tcpConn.Close()


	config := &tls.Config{
		ServerName:         domain,
		InsecureSkipVerify: true,

		// Called with the raw cert chain BEFORE standard verification.
		// rawCerts: DER-encoded certs, verifiedChains: nil at this stage.
		VerifyPeerCertificate: func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
            log("#################### REQUEST START ###################")
            defer log("#################### REQUEST END ###################")
			log("Attempting Certificate Verification...")

            cert, err := x509.ParseCertificate(rawCerts[0])
            if err != nil {
                fmt.Println("Failed to Parse the Server Cert")
                return nil
            }
            hash := sha1.Sum(cert.Raw)
            hashStr := fmt.Sprintf("%x", hash)
            for _, h := range *knownHashes {
                if h == hashStr {
                    log("%s Hash is already Cached!", hashStr)
                    return nil
                }
            }
			log("============ [Server Cert] ===========")
			log("\tSubject:    %s", cert.Subject)
			log("\tIssuer:     %s", cert.Issuer)
			log("\tNot Before: %s", cert.NotBefore)
			log("\tNot After:  %s", cert.NotAfter)
			log("\tDNS SANs:   %v", cert.DNSNames)
			log("\tSHA1 Hash:  %x", hash)
			log("======================================\n")

            // Check Chain
            intermediates := x509.NewCertPool()
            roots, _ := x509.SystemCertPool()

            // Intermediates
			for i, rawCert := range rawCerts[1:] {
				pcert, err := x509.ParseCertificate(rawCert)
				if err != nil {
					return fmt.Errorf("failed to parse cert %d: %w", err)
				}
                intermediates.AddCert(pcert)


                hash := sha1.Sum(pcert.Raw)
				log("========== [Intermediate %d] ==========", i)
				log("\tSubject:    %s", pcert.Subject)
				log("\tIssuer:     %s", pcert.Issuer)
				log("\tNot Before: %s", pcert.NotBefore)
				log("\tNot After:  %s", pcert.NotAfter)
				log("\tDNS SANs:   %v", pcert.DNSNames)
				log("\tSHA1 Hash:  %x", hash)
				log("======================================\n")
			}

            opts := x509.VerifyOptions{
                DNSName:    domain,
                Roots:      roots,
                Intermediates: intermediates,
            }

            _, jerr := cert.Verify(opts)
            if jerr != nil {
                log("Verification Failed: '%v'", jerr)
                reader := bufio.NewReader(os.Stdin)
                fmt.Printf("Continue? (Y/n): ")
                input, _ := reader.ReadString('\n')
                input = strings.TrimSpace(strings.ToLower(input))

                switch input {
                    case "", "y", "yes":
                        *knownHashes = append(*knownHashes, hashStr)
                        return nil
                    default:
                        return jerr
                }
            }

			// Return nil to allow, or an error to abort the handshake
            *knownHashes = append(*knownHashes, hashStr)
			return nil
		},
	}


	tlsConn := tls.UClient(tcpConn, config, tls.HelloChrome_Auto)

	if err := tlsConn.Handshake(); err != nil {
		log("Handshake failed: %v", err)
		return
	}
	defer tlsConn.Close()

	log("Handshake successful!")
}

func main() {
    if len(os.Args) !=  3 {
        fmt.Printf("Usage: %s <host> <port>\n", os.Args[0])
        os.Exit(1)
    }
    domain := os.Args[1]
    port := os.Args[2]
    knownHashes := []string{}
    make_request(domain, port, &knownHashes)
    make_request(domain, port, &knownHashes)
}
