package main

import (
	"context"
	"crypto/rand"
	"fmt"
	"runtime"
	"sync"
)

/*
A note about the provided keys and signatures:
the provided pubkey and signature, as well as "HexTo___" functions may not work
with all the different implementations people could built.  Specifically, they
are tied to an endian-ness.  If, for example, you decided to encode your public
keys as (according to the diagram in the slides) up to down, then left to right:
<bit 0, row 0> <bit 0, row 1> <bit 1, row 0> <bit 1, row 1> ...

then it won't work with the public key provided here, because it was encoded as
<bit 0, row 0> <bit 1, row 0> <bit 2, row 0> ... <bit 255, row 0> <bit 0, row 1> ...
(left to right, then up to down)

so while in class I said that any decisions like this would work as long as they
were consistent... that's not actually the case!  Because your functions will
need to use the same ordering as the ones I wrote in order to create the signatures
here.  I used what I thought was the most straightforward / simplest encoding, but
endian-ness is something of a tabs-vs-spaces thing that people like to argue
about :).

So for clarity, and since it's not that obvious from the HexTo___ decoding
functions, here's the order used:

secret keys and public keys:
all 256 elements of row 0, most significant bit to least significant bit
(big endian) followed by all 256 elements of row 1.  Total of 512 blocks
of 32 bytes each, for 16384 bytes.
For an efficient check of a bit within a [32]byte array using this ordering,
you can use:
    arr[i/8]>>(7-(i%8)))&0x01
where arr[] is the byte array, and i is the bit number; i=0 is left-most, and
i=255 is right-most.  The above statement will return a 1 or a 0 depending on
what's at that bit location.

Messages: messages are encoded the same way the sha256 function outputs, so
nothing to choose there.

Signatures: Signatures are also read left to right, MSB to LSB, with 256 blocks
of 32 bytes each, for a total of 8192 bytes.  There is no indication of whether
the provided preimage is from the 0-row or the 1-row; the accompanying message
hash can be used instead, or both can be tried.  This again interprets the message
hash in big-endian format, where
    message[i/8]>>(7-(i%8)))&0x01
can be used to determine which preimage block to reveal, where message[] is the
message to be signed, and i is the sequence of bits in the message, and blocks
in the signature.

Hopefully people don't have trouble with different encoding schemes.  If you
really want to use your own method which you find easier to work with or more
intuitive, that's OK!  You will need to re-encode the key and signatures provided
in signatures.go to match your ordering so that they are valid signatures with
your system.  This is probably more work though and I recommend using the big
endian encoding described here.

*/

// Forge is the forgery function, to be filled in and completed.  This is a trickier
// part of the assignment which will require the computer to do a bit of work.
// It's possible for a single core or single thread to complete this in a reasonable
// amount of time, but may be worthwhile to write multithreaded code to take
// advantage of multi-core CPUs.  For programmers familiar with multithreaded code
// in golang, the time spent on parallelizing this code will be more than offset by
// the CPU time speedup.  For programmers with access to 2-core or below CPUs, or
// who are less familiar with multithreaded code, the time taken in programming may
// exceed the CPU time saved.  Still, it's all about learning.
// The Forge() function doesn't take any inputs; the inputs are all hard-coded into
// the function which is a little ugly but works OK in this assigment.
// The input public key and signatures are provided in the "signatures.go" file and
// the code to convert those into the appropriate data structures is filled in
// already.
// Your job is to have this function return two things: A string containing the
// substring "forge" as well as your name or email-address, and a valid signature
// on the hash of that ascii string message, from the pubkey provided in the
// signatures.go file.
// The Forge function is tested by TestForgery() in forge_test.go, so if you
// run "go test" and everything passes, you should be all set.
func Forge() (string, Signature, error) {
	// decode pubkey, all 4 signatures into usable structures from hex strings
	pub, err := HexToPubkey(hexPubkey1)
	if err != nil {
		panic(err)
	}

	sig1, err := HexToSignature(hexSignature1)
	if err != nil {
		panic(err)
	}
	sig2, err := HexToSignature(hexSignature2)
	if err != nil {
		panic(err)
	}
	sig3, err := HexToSignature(hexSignature3)
	if err != nil {
		panic(err)
	}
	sig4, err := HexToSignature(hexSignature4)
	if err != nil {
		panic(err)
	}

	var sigslice []Signature
	sigslice = append(sigslice, sig1)
	sigslice = append(sigslice, sig2)
	sigslice = append(sigslice, sig3)
	sigslice = append(sigslice, sig4)

	var msgslice []Message

	msgslice = append(msgslice, GetMessageFromString("1"))
	msgslice = append(msgslice, GetMessageFromString("2"))
	msgslice = append(msgslice, GetMessageFromString("3"))
	msgslice = append(msgslice, GetMessageFromString("4"))

	fmt.Printf("ok 1: %v\n", Verify(msgslice[0], pub, sigslice[0]))
	fmt.Printf("ok 2: %v\n", Verify(msgslice[1], pub, sigslice[1]))
	fmt.Printf("ok 3: %v\n", Verify(msgslice[2], pub, sigslice[2]))
	fmt.Printf("ok 4: %v\n", Verify(msgslice[3], pub, sig4))

	fmt.Println(sig1)

	sig_hash := sig1.Preimage[0].Hash() // == pub

	fmt.Println(sig_hash)
	fmt.Println(pub.OneHash[0])
	fmt.Println(pub.ZeroHash[0])
	if sig_hash == pub.OneHash[0] {
		fmt.Println("OneHash")
	}
	if sig_hash == pub.ZeroHash[0] {
		fmt.Println("ZeroHash")
	}

	fmt.Println(sig_hash.ToHex())

	msgString := "my forged message"
	var sig Signature
	var sec SecretKey
	sig = sig1

	//var secret SecretKey

	sec = make_secret_key(sigslice, msgslice)
	fmt.Println(sec)
	//check_my_message(sigslice, msgslice, sec)

	var ones Message
	var zeros Message

	for i := 0; i < 32; i++ {
		ones[i] = msgslice[0][i] | msgslice[1][i]
		ones[i] = ones[i] | msgslice[2][i]
		ones[i] = ones[i] | msgslice[3][i]
	}
	for i := 0; i < 32; i++ {
		zeros[i] = msgslice[0][i] & msgslice[1][i]
		zeros[i] = zeros[i] & msgslice[2][i]
		zeros[i] = zeros[i] & msgslice[3][i]
	}

	for i := range 4 {
		fmt.Printf("%08b \n", msgslice[i])
	}

	fmt.Printf("%08b \n", ones)
	fmt.Printf("%08b \n", zeros)

	//var doable_message = look_for_message(ones, zeros)

	//fmt.Println(doable_message)

	/////////

	// Create context to cancel all goroutines once we find a message
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel() // Ensure cleanup

	resultChan := make(chan string, 1) // Channel to receive a found message
	var wg sync.WaitGroup

	// Launch multiple workers (e.g., 5 threads)
	numWorkers := runtime.NumCPU() // Use all available CPU cores
	fmt.Printf("Number of CPUs: %d", numWorkers)
	//numWorkers := 5
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go look_for_message_multi(ctx, ones, zeros, resultChan, &wg)
	}

	// Wait for the first valid message
	foundMessage := <-resultChan
	fmt.Println("Found message:", foundMessage)
	// Found message: forge Dominik5e5ZzrPTKu

	// Cancel all remaining goroutines
	cancel()

	// Wait for all goroutines to finish
	wg.Wait()

	// signature is the preimage from the corresponding row (0,1)
	// signature has 256x256 (32 Blocks with 8 Bit)

	// 11110000
	// 11110000
	// 10000000
	// your code here!
	// ==
	// Geordi La
	// ==

	return msgString, sig, nil

}

const asciiCharset = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

func randomASCIIString(length int) (string, error) {
	bytes := make([]byte, length)
	_, err := rand.Read(bytes)
	if err != nil {
		return "", err
	}

	// Convert bytes to ASCII characters
	for i := 0; i < length; i++ {
		bytes[i] = asciiCharset[int(bytes[i])%len(asciiCharset)]
	}

	return string(bytes), nil
}

func create_message() string {
	var base = "forge Dominik"
	randomStr, err := randomASCIIString(10) // Generate a 10-character random string
	if err != nil {
		panic(err) // Handle error properly in real applications
	}
	return base + randomStr
}
func look_for_message_multi(ctx context.Context, ones Message, zeros Message, resultChan chan<- string, wg *sync.WaitGroup) {
	defer wg.Done() // Signal goroutine completion

	for {
		select {
		case <-ctx.Done():
			// Stop if another goroutine found the message
			return
		default:
			// Generate a message
			suprise := create_message()
			supr := GetMessageFromString(suprise)
			var check_zeros, check_ones Message
			message_not_found := false

			// Check if the message is correct
			for i := 0; i < 32; i++ {
				check_ones[i] = supr[i] & ones[i]
				check_zeros[i] = supr[i] | zeros[i]

				if check_ones[i] != supr[i] || check_zeros[i] != supr[i] {
					message_not_found = true
					break // No need to continue checking
				}
			}

			if !message_not_found {
				resultChan <- suprise // Send the correct message
				return
			}
		}
	}
}

func look_for_message(ones Message, zeros Message) string {
	var suprise = create_message()
	var supr = GetMessageFromString(suprise)
	var check_zeros Message
	var check_ones Message
	var message_not_found = true

	for message_not_found {
		message_not_found = false
		suprise = create_message()
		supr = GetMessageFromString(suprise)
		for i := 0; i < 32; i++ {

			check_ones[i] = supr[i] & ones[i]
			check_zeros[i] = supr[i] | zeros[i]

			if check_ones[i] != supr[i] {
				// no correct message
				message_not_found = true
			}
			if check_zeros[i] != supr[i] {
				// no correct message
				message_not_found = true
			}
		}
		fmt.Println(suprise)
	}
	return suprise
}

func make_secret_key(signatures []Signature, messages []Message) SecretKey {
	var sec SecretKey
	var flag byte

	//signatures: 4 signatures with 256 32 byte blocks corresponding to message
	//message: 4 messages for the corresponding signature
	var message = messages[0]
	var signature = signatures[0]

	fmt.Printf("%b", message)
	fmt.Printf("\n -----------------------")
	for j := range 4 {
		message = messages[j]
		signature = signatures[j]
		for i := range 256 {
			flag = message[i/8] >> (7 - (i % 8)) & 0x01
			if flag == 1 {
				// the Preimage -> secret from onePre
				sec.OnePre[i] = signature.Preimage[i]
			}
			if flag == 0 {
				// the Preimage -> secret from zeroPro
				sec.ZeroPre[i] = signature.Preimage[i]
			}
		}
	}

	for i := range 256 {
		fmt.Printf("%d : %x \n", i, sec.OnePre[i])
		fmt.Printf("%d : %x \n", i, sec.ZeroPre[i])
		fmt.Printf("---------------------------\n")
	}

	var mymessage = "my forged messsage"

	var mes = GetMessageFromString(mymessage)

	fmt.Printf("%b", mes)
	return sec

}

//func get_value_from_signatures(sig1, sig2, sig3, sig4) {
// get the 4 signatures under question and search for the correct one
// we also need the public key here to check which is the right signature
// hash(sig) == pub
// sig is a part of the secret key
//}

// hint:
// arr[i/8]>>(7-(i%8)))&0x01
