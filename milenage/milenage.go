package milenage

import (
	"crypto/aes"
)

// Milenage .
type Milenage struct {
	K    []byte
	OP   []byte
	OPc  []byte
	AMF  []byte
	SQN  []byte
	RAND []byte
}

// New function Creates new instance of Milenage struct, which calculates OPc from OP and K
func New(k, op, rand, sqn, amf []byte) (*Milenage, error) {

	opc, err := ComputeOPc(op, k)
	if err != nil {
		return nil, err
	}

	return NewWithOPc(k, opc, rand, sqn, amf), nil
}

// NewWithOPc function Creates new instance of Milenage struct using OPc ins
func NewWithOPc(k, opc, rand, sqn, amf []byte) *Milenage {

	m := &Milenage{
		K:    k,
		OPc:  opc,
		RAND: rand,
		SQN:  sqn,
		AMF:  amf,
	}

	return m
}

// ComputeOPc function calculate OPc based on OP and K
func ComputeOPc(op, k []byte) ([]byte, error) {
	opc := make([]byte, 16)

	opc, err := encrypt(op, k)

	if err != nil {
		return nil, err
	}

	for i := 0; i < len(op); i++ {
		opc[i] ^= op[i]
	}

	return opc, nil

}

// F1 function implements the F1 function of milenage algo defined in TS 35.205 and TS 35.206
func (m *Milenage) F1() ([]byte, error) {

	out1, err := m.f1base()

	if err != nil {
		return nil, err
	}

	maca := out1[:8]

	return maca, nil
}

// F2345 function implements the F2, F3, F4, F5 functions of milenage algo defined in TS 35.205 and TS 35.206
func (m *Milenage) F2345() (res, ck, ik, ak []byte, err error) {

	rInput := make([]byte, 16)
	tmp, _ := calcTemp(m.RAND, m.OPc, m.K)

	for i := 0; i < 16; i++ {
		rInput[i] = tmp[i] ^ m.OPc[i]
	}
	rInput[15] ^= 1

	out2, _ := encrypt(rInput, m.K)

	for i := 0; i < 16; i++ {
		out2[i] ^= m.OPc[i]
	}

	res = out2[8:]
	ak = out2[:6]

	// To obtain output block OUT3: XOR OPc and TEMP,
	// rotate by r3=32, and XOR on the constant c3 (which
	// is all zeroes except that the next to last bit is 1).
	for i := 0; i < 16; i++ {
		rInput[(i+12)%16] = tmp[i] ^ m.OPc[i]
	}
	rInput[15] ^= 2

	out3, _ := encrypt(rInput, m.K)
	ck = out3[:]

	// To obtain output block OUT4: XOR OPc and TEMP,
	// rotate by r4=64, and XOR on the constant c4 (which
	// is all zeroes except that the 2nd from last bit is 1).
	for i := 0; i < 16; i++ {
		rInput[(i+8)%16] = tmp[i] ^ m.OPc[i]
	}
	rInput[15] ^= 4

	out4, _ := encrypt(rInput, m.K)
	ik = out4[:]
	return
}

// F1Star function implements the F1* function of milenage algo defined in TS 35.205 and TS 35.206
func (m *Milenage) F1Star() ([]byte, error) {

	out1, err := m.f1base()

	if err != nil {
		return nil, err
	}

	macs := out1[8:]

	return macs, nil
}

// F5Star function implements the F5* function of milenage algo defined in TS 35.205 and TS 35.206
func (m *Milenage) F5Star() ([]byte, error) {
	rInput := make([]byte, 16)
	tmp, _ := calcTemp(m.RAND, m.OPc, m.K)

	for i := 0; i < 16; i++ {
		rInput[(i+4)%16] = tmp[i] ^ m.OPc[i]
	}
	rInput[15] ^= 8

	out5, _ := encrypt(rInput, m.K)

	for i := 0; i < 16; i++ {
		out5[i] ^= m.OPc[i]
	}

	ak := out5[:6]

	return ak, nil
}

func (m *Milenage) f1base() ([]byte, error) {
	rInput := make([]byte, 16)
	var in1 []byte

	tmp, err := calcTemp(m.RAND, m.OPc, m.K)
	if err != nil {
		return nil, err
	}

	// in1 := make([]byte, 16)
	// for i := 0; i < 6; i++ {
	// 	in1[i] = m.SQN[i]
	// 	in1[i+8] = m.SQN[i]
	// }
	// for i := 0; i < 2; i++ {
	// 	in1[i+6] = m.AMF[i]
	// 	in1[i+14] = m.AMF[i]
	// }

	in1 = append(in1, m.SQN...)
	in1 = append(in1, m.AMF...)
	in1 = append(in1, m.SQN...)
	in1 = append(in1, m.AMF...)

	// XOR op_c and in1, rotate by r1=64, and XOR
	// on the constant c1 (which is all zeroes)
	for i := 0; i < 16; i++ {
		rInput[(i+8)%16] = in1[i] ^ m.OPc[i]
	}

	// XOR on the value temp computed before

	for i := 0; i < 16; i++ {
		rInput[i] ^= tmp[i]
	}

	out1, err := encrypt(rInput, m.K)
	if err != nil {
		return nil, err
	}

	for i := 0; i < 16; i++ {
		out1[i] ^= m.OPc[i]
	}

	return out1, nil
}
func (m *Milenage) computeOPc() (err error) {
	m.OPc, err = ComputeOPc(m.OP, m.K)
	return
}

func encrypt(input, k []byte) ([]byte, error) {
	out := make([]byte, len(input))
	block, err := aes.NewCipher(k)

	if err != nil {
		return nil, err
	}

	block.Encrypt(out, input)
	return out, nil
}

func calcTemp(rand, opc, k []byte) ([]byte, error) {
	rInput := make([]byte, 16)
	for i := 0; i < len(rand); i++ {
		rInput[i] = rand[i] ^ opc[i]
	}

	tmp, err := encrypt(rInput, k)
	if err != nil {
		return nil, err
	}

	return tmp, nil
}
