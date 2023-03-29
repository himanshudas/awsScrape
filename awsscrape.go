package main

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dgryski/go-pcgr"
	"github.com/valyala/fasthttp"
)

type IPRange struct {
	Prefixes []struct {
		IPPrefix string `json:"ip_prefix"`
	} `json:"prefixes"`
}

type checkIPRangeParams struct {
	ipRange     []byte
	keywordList [][]byte
	timeout     time.Duration
	verbose     bool
}

func parseCommandLineArguments() (string, string, int, time.Duration, bool, string, bool) {
	wordlist := flag.String("wordlist", "", "File containing keywords to search in SSL certificates")
	shortWordlist := flag.String("w", "", "File containing keywords to search in SSL certificates (short form)")
	keyword := flag.String("keyword", "", "Single keyword to search in SSL certificates")
	numThreads := flag.Int("threads", 4, "Number of concurrent threads")
	timeout := flag.Duration("timeout", 1*time.Second, "Timeout for SSL connection")
	randomize := flag.Bool("randomize", false, "Randomize the order in which IP addresses are checked")
	outputFile := flag.String("output", "", "Output file to save results")
	verbose := flag.Bool("verbose", false, "Enable verbose mode")
	flag.BoolVar(verbose, "v", false, "Enable verbose mode (short form)")
	flag.Parse()

	if *wordlist == "" && *shortWordlist != "" {
		*wordlist = *shortWordlist
	}

	return *wordlist, *keyword, *numThreads, *timeout, *randomize, *outputFile, *verbose

}

func pcgShuffle(n int, swap func(i, j int), pcgSource *pcgr.Rand) {
	if n < 0 {
		panic("invalid argument to pcgShuffle")
	}
	randSrc := rand.New(pcgSource)
	for i := n - 1; i > 0; i-- {
		j := randSrc.Intn(i + 1)
		swap(i, j)
	}
}

func main() {
	wordlist, keyword, numThreads, timeout, randomize, outputFile, verbose := parseCommandLineArguments()

	if wordlist == "" && keyword == "" {
		fmt.Println("Usage: go run script.go [-wordlist=<your_keywords_file> | -keyword=<your_keyword>] [-threads=<num_threads>] [-timeout=<timeout_seconds>] [-randomize] [-output=<output_file>] [-verbose]")
		return
	}

	var keywordList [][]byte
	if wordlist != "" {
		f, err := os.Open(wordlist)
		if err != nil {
			log.Fatalf("Error opening wordlist file: %v", err)
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := scanner.Bytes()
			if len(bytes.TrimSpace(line)) > 0 {
				keywordList = append(keywordList, line)
			}
		}
		if err := scanner.Err(); err != nil {
			log.Fatalf("Error reading wordlist file: %v", err)
		}
	} else {
		keywordList = [][]byte{[]byte(keyword)}
	}

	var ipRanges IPRange
	req := fasthttp.AcquireRequest()
	resp := fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)
	req.SetRequestURI("https://ip-ranges.amazonaws.com/ip-ranges.json")

	err := fasthttp.Do(req, resp)
	if err != nil {
		log.Println("Error fetching IP ranges:", err)
		return
	}
	respBody := resp.Body()
	dec := json.NewDecoder(bytes.NewReader(respBody))

	if randomize {
		pcgSource := pcgr.New(time.Now().UnixNano(), 0)
		pcgShuffle(len(ipRanges.Prefixes), func(i, j int) {
			ipRanges.Prefixes[i], ipRanges.Prefixes[j] = ipRanges.Prefixes[j], ipRanges.Prefixes[i]
		}, &pcgSource)

	}

	var ipChan chan []byte
	var progressCounter int32
	var totalIPs int

	for dec.More() {
		if err := dec.Decode(&ipRanges); err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalf("Error parsing JSON: %v", err)
		}
		totalIPs := len(ipRanges.Prefixes)
		for _, prefix := range ipRanges.Prefixes {
			params := checkIPRangeParams{
				ipRange:     []byte(prefix.IPPrefix),
				keywordList: keywordList,
				timeout:     timeout,
				verbose:     verbose,
			}
			go checkIPRange(params, numThreads, outputFile, ipChan, &progressCounter, totalIPs)
		}
	}
	wg := &sync.WaitGroup{}

	ipChan = make(chan []byte, numThreads*10)

	wg.Add(numThreads)
	for i := 0; i < numThreads; i++ {
		go func() {
			defer wg.Done()
			for ip := range ipChan {
				if outputFile != "" {
					if err := writeIPToFile(outputFile, ip); err != nil {
						log.Printf("Error writing to output file: %v", err)
					}
				}
				fmt.Printf("%s\n", ip)
				progress := atomic.AddInt32(&progressCounter, 1)
				fmt.Printf("Progress: %d/%d\n", progress, totalIPs)
			}
		}()
	}

	wg.Wait()
	close(ipChan)

}

func checkIPRange(params checkIPRangeParams, numThreads int, outputFile string, ipChan chan<- []byte, progressCounter *int32, totalIPs int) {
	_, ipNet, err := net.ParseCIDR(string(params.ipRange))
	if err != nil {
		return
	}

	var pool sync.Pool
	pool.New = func() interface{} {
		return make([]byte, 0, 16)
	}

	keywordSorter := &keywordListSorter{params.keywordList}
	sort.Sort(keywordSorter)

	jobs := make(chan net.IP, numThreads)
	wg := &sync.WaitGroup{}

	for i := 0; i < numThreads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				ipStr := pool.Get().([]byte)
				ipStr = ipStr[:0]
				ipStr = ip.To4()
				if ipStr == nil {
					ipStr = []byte(ip.String())
				} else {
					ipStr = []byte(ipStr)
				}

				found, matchedKeywords := checkSSLKeyword(ipStr, keywordSorter, int(params.timeout/time.Second))
				if found {
					if len(matchedKeywords) > 20 {
						ipStr = append(ipStr, []byte(fmt.Sprintf(" Matched keywords found in SSL certificate (Keywords checked: %d)\n", len(params.keywordList)))...)
					} else {
						ipStr = append(ipStr, []byte(fmt.Sprintf(" Matched keywords found in SSL certificate (Keywords: %s)\n", bytes.Join(matchedKeywords, []byte(", "))))...)
					}
					ipChan <- ipStr
				} else if params.verbose {
					if len(params.keywordList) > 20 {
						ipStr = append(ipStr, []byte(fmt.Sprintf(" No matched keyword found in SSL certificate (Keywords checked: %d)\n", len(params.keywordList)))...)
					} else {
						ipStr = append(ipStr, []byte(fmt.Sprintf(" No matched keyword found in SSL certificate (Keywords: %s)\n", bytes.Join(params.keywordList, []byte(", "))))...)
					}
					ipChan <- ipStr
				}
				pool.Put(ipStr)
			}
		}()
	}
	for ip := ipNet.IP.Mask(ipNet.Mask); ipNet.Contains(ip); incrementIP(ip) {
		jobs <- ip
	}
	close(jobs)

	wg.Wait()
}

type keywordListSorter struct {
	keywordList [][]byte
}

func (s *keywordListSorter) Len() int {
	return len(s.keywordList)
}

func (s *keywordListSorter) Less(i, j int) bool {
	return bytes.Compare(s.keywordList[i], s.keywordList[j]) < 0
}

func (s *keywordListSorter) Swap(i, j int) {
	s.keywordList[i], s.keywordList[j] = s.keywordList[j], s.keywordList[i]
}

func checkSSLKeyword(ip []byte, keywordSorter *keywordListSorter, timeout int) (bool, [][]byte) {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: time.Duration(timeout) * time.Second}, "tcp", string(ip)+":443", &tls.Config{InsecureSkipVerify: true})
	if err != nil {
		return false, nil
	}
	defer conn.Close()
	certs := conn.ConnectionState().PeerCertificates
	if certs == nil {
		return false, nil
	}
	var matchedKeywords [][]byte
	for _, cert := range certs {
		var orgBytes [][]byte
		for _, org := range cert.Subject.Organization {
			orgBytes = append(orgBytes, []byte(org))
		}
		var orgUnitBytes [][]byte
		for _, unit := range cert.Subject.OrganizationalUnit {
			orgUnitBytes = append(orgUnitBytes, []byte(unit))
		}
		for _, keyword := range keywordSorter.keywordList {
			if bytes.Contains([]byte(cert.Subject.CommonName), keyword) ||
				bytes.Contains(bytes.Join(orgBytes, []byte(" ")), keyword) ||
				bytes.Contains(bytes.Join(orgUnitBytes, []byte(" ")), keyword) {
				matchedKeywords = append(matchedKeywords, keyword)
			}
		}
	}

	return len(matchedKeywords) > 0, matchedKeywords
}

func writeIPToFile(filename string, ip []byte) error {
	file, err := os.OpenFile(filename, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	defer file.Close()
	_, err = file.Write(ip)
	if err != nil {
		return err
	}
	return nil
}

func incrementIP(ip net.IP) {
	for i := len(ip) - 1; i >= 0; i-- {
		ip[i]++
		if ip[i] != 0 {
			break
		}
	}
}
