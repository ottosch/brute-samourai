package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"runtime"
	"strconv"
	"strings"

	"github.com/docopt/docopt.go"
	"github.com/ottosch/brute-samourai/src/bip38"
	"github.com/ottosch/brute-samourai/src/samourai"
)

var APP_NAME string = "Samourai Backup Cracker"
var APP_USAGE string = `Samourai Backup Cracker v0.1

Usage:
  brute-samourai [--chunk=N/T] [--charset=S] [-t N] [--resume=NUM] [-w <wallet_file>]
  brute-samourai [--chunk=N/T] [--charset=S] [-t N] [--resume=NUM] [-w <wallet_file>] <pwlen_or_pat>
  brute-samourai [--chunk=N/T] [-t N] [--resume=NUM] [-w <wallet_file>] [-s] -i <input_file>
   
Default wallet file:
  If no wallet file is specified, samourai.txt
  is used, with pwlen 4 (equivalent to pattern: '????').

Specifying a wallet file and a set of passwords to try:

  <wallet_file>  Bruteforce crack the given wallet file.

  <pwlen_or_pat> Length, in characters, of the original passphrase. Cracking
                 will try all possible combinations of characters from charset
                 of length pwlen.
                                        *OR*
                 A pattern, where ? represents unknown characters, eg:
                    foo??bar?     -- try things like foo12bar3, fooABbarZ,
                                     fooefbarg, etc
                    ??foo???bar?? -- try things like ABfooCDEbarFG,
                                     12foo345bar67, etc
                 
                 CAVEAT: Note that in this scheme there is no way to represent
                 a '?' character in the static pattern -- ? will always match
                 an unknown character!
                 
                 NOTE: Specifying eg ???? as the pattern is equivalent to
                 specifying pwlen of 4.

  <input_file>   Instead of specifying a pattern and a character set, simply
                 read a list of passwords to try from input_file. The
                 passwords should be one per line. Leading/trailing whitespace
                 will be trimmed from the lines read, unless -s is specified.

Options:
  --chunk=N/T    For running on multiple machines to search the same space,
                 break space up into T pieces and process piece N
  --charset=S    The set of characters to use. Defaults to
                 '0123456789 ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
                 Be sure to set this as restrictive as possible as it greatly
                 affects runtime and search space complexity! (Not used in
                 <input_file> mode.)
  -t N           Set maximum threads to N, defaults to number of CPUs detected
  --resume=NUM   For continuing from a previously-aborted run. Specify the
                 resume offset to continue from, as printed onscreen after a ^C
  -i             Use input file reading mode. Next argument should be a
                 filename to read.  See <input_file> above.
  -s             When using <input_file> reading mode, specifies that leading
                 and trailing whitespace should NOT be trimmed from each
                 password that will be tried (default is to trim).
  -h             Usage Help
  
Examples:
    brute-samourai --resume=3 m?p -w samourai.txt
        Resumes at 3, searches a password of length 3 with the middle
        character being unknown, from ASCII letters, numbers and space.
        
    brute-samourai --charset='mopab' -w samourai.txt 3
        Searches a password of length 3 with all characters being unknown,
        from a very limited set.

    brute-samourai --charset='12345' -w samourai.txt 'foo??bar???'
        Searches a password of length 11, with 2 middle characters unknown and
        3 at the end unknonw, from a very small numeric set.
 
`

var arguments map[string]interface{}

func init() {
	var err error
	arguments, err = docopt.ParseDoc(APP_USAGE)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	chunks := 1
	chunk := 0
	charset := "" // use default
	walletFile := "samourai.txt"
	infile := ""
	notrim := false

	if arguments["--chunk"] != nil {
		var n int
		var err error
		n, err = fmt.Sscanf(arguments["--chunk"].(string), "%d/%d", &chunk, &chunks)
		if err != nil {
			log.Fatal(err)
		}
		if n != 2 {
			log.Fatal("Parse error for --chunk argument")
		}
		if chunk >= chunks || chunk < 0 || chunks <= 0 {
			log.Fatal("chunk parameter invalid")
		}
	}

	if arguments["-i"] != nil && arguments["-i"].(bool) {
		infile = arguments["<input_file>"].(string)
	}
	if arguments["-s"] != nil && arguments["-s"].(bool) {
		if infile == "" {
			log.Fatal("Option -s can only be used if using -i mode!")
		}
		notrim = true
	}
	if arguments["--charset"] != nil {
		if infile != "" {
			log.Fatal("--charset argument cannot be combined with -i!")
		}
		charset = arguments["--charset"].(string)
	}

	var pwlen int = 4
	var pat string = ""

	if arguments["-w"] != nil && arguments["-w"].(bool) && arguments["<wallet_file>"] != nil {
		walletFile = arguments["<wallet_file>"].(string)
	}

	if arguments["<pwlen_or_pat>"] != nil {
		if infile != "" {
			log.Fatal("<pwlen_or_pat> cannot be combined with -i!")
		}
		var err error
		pwlen, err = strconv.Atoi(arguments["<pwlen_or_pat>"].(string))
		if err == nil {
			// used old 'pwlen' syntax, so make pattern be a string full of '?'
			if pwlen < 1 {
				log.Fatal("pwlen must be greater than or equal to 1!")
			}
		} else {
			// uses new 'pattern' syntax
			pat = arguments["<pwlen_or_pat>"].(string)
			pwlen = 0
			runes := []rune(pat)
			for i := 0; i < len(runes); i++ {
				if runes[i] == '?' {
					pwlen++
				}
			}
			if pwlen < 1 || len(runes) < 1 {
				log.Fatal("Error parsing pattern.  Make sure it contains at least one '?' character!")
			}
		}
	}

	payload, err := samourai.ReadPayload(walletFile)
	if err != nil {
		log.Fatalf("Error while parsing wallet file:\n%v\n", err)
	}

	ciphertextBase64 := strings.ReplaceAll(payload, "\n", "")

	var lines []string = nil
	if infile != "" {
		fmt.Printf("Reading password file into memory: %s...\n", infile)
		var mem uint64
		lines, mem = readAllLines(infile, !notrim)
		fmt.Printf("%s memory used for password file data\n", prettyFormatMem(mem))
	}

	ncpu := runtime.NumCPU()
	if arguments["-t"] != nil {
		ncpu, _ = strconv.Atoi(arguments["-t"].(string))
	}
	var resume uint64 = 0
	if arguments["--resume"] != nil {
		resume, _ = strconv.ParseUint(arguments["--resume"].(string), 10, 64)
	}
	fmt.Printf("Running brute force on %d CPUs for wallet file: %s\n", ncpu, walletFile)
	runtime.GOMAXPROCS(ncpu)
	result := bip38.BruteChunk(ncpu, charset, pwlen, pat, lines, chunk, chunks, resume, ciphertextBase64)
	if result == "" {
		fmt.Printf("\nNot found.\n")
		os.Exit(2)
	} else if strings.HasPrefix(result, "to resume") {
		fmt.Printf("Exiting... %s                                               \n", result)
		os.Exit(3)
	} else {
		fmt.Printf("\n\n!!! PASSPHRASE FOUND !!!!\n\n%s\n", result)
		os.Exit(0)
	}
	os.Exit(4) // not reached but added here defensively
}

func readAllLines(fileName string, trim bool) (lines []string, memUsed uint64) {
	file, err := os.Open(fileName)
	if err != nil {
		log.Fatalf("Cannot open input file, error was '%s'", err.Error())
	}
	scanner := bufio.NewScanner(file)
	var mem runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&mem)
	memUsed = mem.Alloc

	for scanner.Scan() {
		line := scanner.Text()
		if trim {
			line = strings.TrimSpace(line)
		}
		if len(line) > 0 {
			lines = append(lines, line)
		}
	}
	if err = scanner.Err(); err != nil {
		log.Fatal("error reading input file:" + err.Error())
	}
	runtime.GC()
	runtime.ReadMemStats(&mem)
	memUsed = mem.Alloc - memUsed
	//    memUsed = tot
	return
}

func prettyFormatMem(size uint64) string {
	rem := uint64(0)
	suffixes := []string{"bytes", "KB", "MB", "GB", "TB"}
	var i int
	for i = 0; i < len(suffixes)-1 && size > 1024; i++ {
		rem = size % 1024
		size /= 1024
	}

	if rem > 0 {
		rem = (rem * 100) / 1024
		return fmt.Sprintf("%v.%v %s", size, rem, suffixes[i])
	}

	return fmt.Sprintf("%v %s", size, suffixes[i])
}
