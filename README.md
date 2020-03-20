# Implements the 3gpp related specifications
## milenage module
Implementation according to **TS 35.206**

> Usage
```go
package main

import (
    "fmt"
    "bytes"
    "encoding/hex"

    "github.com/vuppalac/go3gpp/milenage"
)

const (
	// Inputs
	OPC  = "cdc202d5123e20f62b6d676ac72cb318"
	K    = "465b5ce8b199b49faa5f0a2ee238a6bc"
	RAND = "000000000000000000000000000008a7"
	SQN  = "000000000015"
	AMF  = "8000"

	// Outputs
	RES  = "c30ca0658493835c"
	CK   = "1fd124a000b7a19e7fb17bbd9defb9bc"
	IK   = "5d62ae7a8f34508d5dafce8eff12caf7"
	AK   = "a3216fff22c8"
    AUTN = "a3216fff22dd8000aad7d3010fa706fb"
    
)

func TestMilenage(t *testing.T) {

	opc, _ := hex.DecodeString(OPC)
	k, _ := hex.DecodeString(K)
	rand, _ := hex.DecodeString(RAND)
	sqn, _ := hex.DecodeString(SQN)
	amf, _ := hex.DecodeString(AMF)

	macA, _ := milenage.F1(k, opc, rand, sqn, amf)
	res, ck, ik, ak, _ := milenage.F2345(k, opc, rand)

	// Generate AUTN
	sqnXorAK := make([]byte, 6)
	for i := 0; i < len(sqn); i++ {
		sqnXorAK[i] = sqn[i] ^ ak[i]
	}

	autn := append(append(sqnXorAK, amf...), macA...)

	var tests = []struct {
		Name string
		Want string
		Got  []byte
	}{
		{Name: "RES", Want: RES, Got: res},
		{Name: "CK", Want: CK, Got: ck},
		{Name: "IK", Want: IK, Got: ik},
		{Name: "AK", Want: AK, Got: ak},
		{Name: "AUTN", Want: AUTN, Got: autn},
	}

	for _, tt := range tests {
		t.Run(tt.Name, func(t *testing.T) {
			want, _ := hex.DecodeString(tt.Want)
			if !bytes.Equal(want, tt.Got) {
				t.Errorf("Want bytes: %v, Got bytes: %v", tt.Want, hex.EncodeToString(tt.Got))
			}
		})
	}
}

```