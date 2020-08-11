package cert

import (
	"bytes"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

type Error struct {
	Code string `json:"code"`
	Type string `json:"type"`
}

type ApiError struct {
	Success string `json:"success"`
	Error   Error  `json:"error"`
}

type ValidationMethod struct {
	FileValidationUrlHttp  string   `json:"file_validation_url_http"`
	FileValidationUrlHttps string   `json:"file_validation_url_https"`
	FileValidationContent  []string `json:"file_validation_content"`
	CnameValidationP1      string   `json:"cname_validation_p1"`
	CnameValidationP2      string   `json:"cname_validation_p2"`
}

/*
type OtherValidation struct {
	ValidationMethods map[string]ValidationMethod
}
*/

/*
type EmailValidation struct {
	Domains map[string][]string
}
*/

type Validation struct {
	EmailValidation map[string][]string         `json:"email_validation"`
	OtherValidation map[string]ValidationMethod `json:"other_methods"`
}

type ExternalCert struct {
	Id                string     `json:"id"`
	Type              string     `json:"type"`
	CommonName        string     `json:"common_name"`
	AdditionalDomains string     `json:"additional_domains"`
	Created           string     `json:"created"`
	Expires           string     `json:"expires"`
	Status            string     `json:"status"`
	ValidationType    string     `json:"validation_type"`
	ValidationEmails  string     `json:"validation_emails"`
	ReplacementFor    string     `json:"replacement_for"`
	Validation        Validation `json:"validation"`
}

type CertResponse struct {
	Certificate string `json:"certificate.crt"`
	CaBundle    string `json:"ca_bundle.crt"`
}

/*
{
   "id":"e386bd087d1d0b909246144ebdafe3bf",
   "type":"1",
   "common_name":"staging1.voltageapp.io",
   "additional_domains":"",
   "created":"2020-08-12 04:18:23",
   "expires":"2020-11-10 00:00:00",
   "status":"draft",
   "validation_type":null,
   "validation_emails":null,
   "replacement_for":"",
   "validation":{
      "email_validation":{
         "staging1.voltageapp.io":[
            "admin@staging1.voltageapp.io",
            "administrator@staging1.voltageapp.io",
            "hostmaster@staging1.voltageapp.io",
            "postmaster@staging1.voltageapp.io",
            "webmaster@staging1.voltageapp.io",
            "admin@voltageapp.io",
            "administrator@voltageapp.io",
            "hostmaster@voltageapp.io",
            "postmaster@voltageapp.io",
            "webmaster@voltageapp.io"
         ]
      },
      "other_methods":{
         "staging1.voltageapp.io":{
            "file_validation_url_http":"http:\/\/staging1.voltageapp.io\/.well-known\/pki-validation\/DF169C5DAA524817584B39C03EC61268.txt",
            "file_validation_url_https":"https:\/\/staging1.voltageapp.io\/.well-known\/pki-validation\/DF169C5DAA524817584B39C03EC61268.txt",
            "file_validation_content":[
               "9C4C6953683B75A30123687DF649C8B7544CCC2A47860582D692FA650D85C799",
               "comodoca.com",
               "c40fe103efdb952"
            ],
            "cname_validation_p1":"_DF169C5DAA524817584B39C03EC61268.staging1.voltageapp.io",
            "cname_validation_p2":"9C4C6953683B75A30123687DF649C8B7.544CCC2A47860582D692FA650D85C799.c40fe103efdb952.comodoca.com"
         }
      }
   }
}
*/

var certServer *http.Server

func GenerateCsr(keyBytes []byte, domain string) (csrBuffer bytes.Buffer, err error) {
	block, _ := pem.Decode(keyBytes)
	x509Encoded := block.Bytes
	privKey, err := x509.ParseECPrivateKey(x509Encoded)
	if err != nil {
		return csrBuffer, err
	}
	subj := pkix.Name{
		CommonName: domain,
	}
	rawSubj := subj.ToRDNSequence()
	asn1Subj, _ := asn1.Marshal(rawSubj)
	template := x509.CertificateRequest{
		RawSubject:         asn1Subj,
		SignatureAlgorithm: x509.ECDSAWithSHA256,
	}
	csrBytes, err := x509.CreateCertificateRequest(rand.Reader, &template, privKey)
	if err != nil {
		return csrBuffer, err
	}
	pem.Encode(&csrBuffer, &pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrBytes})
	return csrBuffer, nil
}

func RequestExternalCert(csr bytes.Buffer, domain string) (certificate ExternalCert, err error) {

	apiKey, found := os.LookupEnv("ZEROSSL_API_KEY")
	if !found {
		return certificate, fmt.Errorf("Failed to get the ZEROSSL_API_KEY environment variable. Make sure it's set")
	}
	parsedCsr := strings.Replace(csr.String(), "\n", "", -1)
	data := url.Values{}
	data.Set("certificate_domains", domain)
	data.Set("certificate_validity_days", "90")
	data.Set("certificate_csr", parsedCsr)
	apiUrl := fmt.Sprintf(
		"https://api.zerossl.com/certificates?access_key=%s",
		apiKey,
	)
	client := &http.Client{}
	request, err := http.NewRequest("POST", apiUrl, strings.NewReader(data.Encode()))
	if err != nil {
		return certificate, err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(request)
	if err != nil {
		return certificate, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return certificate, fmt.Errorf("Received bad response from ZeroSSL: %v - %v", resp.StatusCode, string(body))
	}
	body, _ := ioutil.ReadAll(resp.Body)
	err = json.Unmarshal(body, &certificate)
	if err != nil {
		fmt.Printf("%+v\n", err)
		var apiError ApiError
		err = json.Unmarshal(body, &apiError)
		fmt.Printf("%v\n", string(body))
		if err != nil {
			fmt.Printf("%+v\n", err)
			return certificate, fmt.Errorf("Unknown error occured: %v", string(body))
		}
		return certificate, fmt.Errorf("There was a problem requesting a certificate: %v", apiError.Error.Type)
	}
	return certificate, nil
}

func StartValidationListener(port int, certificate ExternalCert) error {
	apiKey, found := os.LookupEnv("ZEROSSL_API_KEY")
	if !found {
		return fmt.Errorf("Failed to get the ZEROSSL_API_KEY environment variable. Make sure it's set")
	}
	fmt.Printf("%+v\n", certificate)
	domain := certificate.CommonName
	fmt.Printf("%v\n", domain)
	path := certificate.Validation.OtherValidation[domain].FileValidationUrlHttp
	path = strings.Replace(path, "http://"+domain, "", -1)
	content := strings.Join(certificate.Validation.OtherValidation[domain].FileValidationContent[:], "\n")
	fmt.Printf("%v\n", path)
	fmt.Printf("%v\n", content)
	go func() {
		addr := fmt.Sprintf(":%v", port)
		http.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(content))
		})
		certServer = &http.Server{
			Addr:    addr,
			Handler: http.DefaultServeMux,
		}
		err := certServer.ListenAndServe()
		if err != nil {
			fmt.Printf("autocert http: %v\n", err)
			return
		}
	}()

	apiUrl := fmt.Sprintf(
		"https://api.zerossl.com/certificates/%s/challenges?access_key=%s",
		certificate.Id, apiKey,
	)
	data := url.Values{}
	data.Set("validation_method", "HTTP_CSR_HASH")
	client := &http.Client{}
	request, err := http.NewRequest("POST", apiUrl, strings.NewReader(data.Encode()))
	if err != nil {
		return err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return fmt.Errorf("Received bad response from ZeroSSL: %v - %v", resp.StatusCode, string(body))
	}
	body, _ := ioutil.ReadAll(resp.Body)
	fmt.Printf("%v\n", string(body))
	return nil
}

func GetExternalCert(certificate ExternalCert) (string, string, error) {
	apiKey, found := os.LookupEnv("ZEROSSL_API_KEY")
	if !found {
		return "", "", fmt.Errorf("Failed to get the ZEROSSL_API_KEY environment variable. Make sure it's set")
	}
	apiUrl := fmt.Sprintf(
		"https://api.zerossl.com/certificates/%s?access_key=%s",
		certificate.Id, apiKey,
	)
	client := &http.Client{}
	request, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return "", "", err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	for {
		resp, err := client.Do(request)
		if err != nil {
			return "", "", err
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			body, _ := ioutil.ReadAll(resp.Body)
			return "", "", fmt.Errorf("Received bad response from ZeroSSL: %v - %v", resp.StatusCode, string(body))
		}
		body, _ := ioutil.ReadAll(resp.Body)
		fmt.Println("%v", string(body))
		var externalCert ExternalCert
		err = json.Unmarshal(body, &externalCert)
		if err != nil {
			time.Sleep(1 * time.Second)
			var apiError ApiError
			err = json.Unmarshal(body, &apiError)
			if err != nil {
				fmt.Printf("Unknown error occured: %v\n", string(body))
			}
			fmt.Printf("There was a problem requesting a certificate: %s", apiError.Error.Type)
		} else {
			status := externalCert.Status
			if status == "issued" {
				break
			}
			time.Sleep(1 * time.Second)
		}
	}

	apiUrl = fmt.Sprintf(
		"https://api.zerossl.com/certificates/%s/download/return?access_key=%s",
		certificate.Id, apiKey,
	)
	client = &http.Client{}
	request, err = http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return "", "", err
	}
	request.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	resp, err := client.Do(request)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		body, _ := ioutil.ReadAll(resp.Body)
		return "", "", fmt.Errorf("Received bad response from ZeroSSL: %v - %v", resp.StatusCode, string(body))
	}
	body, _ := ioutil.ReadAll(resp.Body)
	var certResponse CertResponse
	err = json.Unmarshal(body, &certResponse)
	if err != nil {
		var apiError ApiError
		err = json.Unmarshal(body, &apiError)
		if err != nil {
			return "", "", fmt.Errorf("Unknown error occured: %v", string(body))
		}
		return "", "", fmt.Errorf("There was a problem requesting a certificate: %s", apiError.Error.Type)
	}
	certServer.Close()
	return certResponse.Certificate, certResponse.CaBundle, nil
}
