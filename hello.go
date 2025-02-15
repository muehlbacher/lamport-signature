package main

import (
	"crypto/sha256"
	"fmt"
)
type Block [32]byte

type Message Block


func main() {
	var a = "Hello World"
	fmt.Println(a)

	var x uint8 = 0xAC    // x = 10101100
	fmt.Printf("%b \n",x)
    x = x & 0xF0         // x = 10100000
	fmt.Printf("%b \n",x)

		// Define your message
	textString := "Test message"
	fmt.Printf("%s\n", textString)
		// convert message into a block
	m := GetMessageFromString(textString)
	fmt.Printf("%x\n", m[:])

	fmt.Printf("%08b\n",m[0])
	//m[0] = m[0] >> 1

	fmt.Printf("%x\n", 0b10000000)

	fmt.Printf("%08b \n", 0x80 & m[0])

	//fmt.Printf("%08b\n",m[0])
	var flag byte
	for i := range 8 {
		flag = m[0] & 0x80
		if flag == 0x80 {
			fmt.Println(i)
		}
		if flag == 0 {
			fmt.Printf("ZERO")
		}
		m[0] = m[0] << 1
	}

}

// GetMessageFromString returns a Message which is the hash of the given string.
func GetMessageFromString(s string) Message {
	return sha256.Sum256([]byte(s))
}