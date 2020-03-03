package milenage

import (
	"crypto/aes"
	"encoding/binary"
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

// New .
func New(k, op, rand, sqn, amf []byte) (*Milenage, error) {

	m := &Milenage{
		K:    k,
		OP:   op,
		RAND: rand,
		SQN:  sqn,
		AMF:  amf,
	}

	if err := m.computeOPc(); err != nil {
		return nil, err
	}

	return m
}

// NewWithOPc .
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

func ComputeOPc(op byte[], k byte[]) ([]byte, error) {
	opc := make([]byte, 16)

	opc, err := encrypt(op, k)

	if err != nil {
		return nil, err
	}

	if i := 0; i < len(op); i++ {
		opc[i] ^= op[i]
	}

	return opc, nil

}

func (m *Milenage) F1() ([]byte, error) {

	put1, err := m.f1base()

	if err != nil {
		return nil, err
	}

	maca := out1[:8]

	return maca, nil
}

func (m *Milenage) F2345() (res, ck, ik, ak []byte) {

	rInput := make([]byte, 16)
	tmp, err := calcTemp(m.RAND, m.OPc, m.K)

	for i := 0; i < 16; i++ {
		rInput[i] = tmp[i] ^ m.OPc[i]
	}
	rInput[15] ^= 1;

	out2, _ := encrypt(rInput, m.K)

	for i := 0; i < 16; i++ {
		out2[i] ^= m.OPc[i]
	}

	res := out2[8:]
	ak := out2[:6]

	// To obtain output block OUT3: XOR OPc and TEMP,
    // rotate by r3=32, and XOR on the constant c3 (which
	// is all zeroes except that the next to last bit is 1).
	for i := 0; i < 16; i++ {
		rInput[(i + 12) % 16] = tmp[i] ^ m.OPc[i]
	}
	rInput[15] ^= 2;

	out3, _ := encrypt(rInput, m.K)
	ck := out3[:]

	// To obtain output block OUT4: XOR OPc and TEMP,
    // rotate by r4=64, and XOR on the constant c4 (which
	// is all zeroes except that the 2nd from last bit is 1).
	for i := 0; i < 16; i++ {
		rInput[(i + 8) % 16] = tmp[i] ^ m.OPc[i]
	}
	rInput[15] ^= 4;

	out4, _ := encrypt(rInput, m.K)
	ik := out4[:]
}

func (m *Milenage) F1Star() ([]byte, error) {

	out1, err := m.f1base()

	if err != nil {
		return nil, err
	}

	macs := out1[8:]

	return macs, nil
}

func (m *Milenage) F5Star()([]byte, error) {
	rInput := make([]byte, 16)
	tmp, err := calcTemp(m.RAND, m.OPc, m.K)

	for i := 0; i < 16; i++ {
		rInput[(i + 4) % 16] = tmp[i] ^ m.OPc[i]
	}
	rInput[15] ^= 8;

	out5, _ := encrypt(rInput, m.K)

	for i := 0; i < 16; i++ {
		out5[i] ^= m.OPc[i]
	}

	ak := out5[:6]
}

func (m *Milenage) f1base() ([]byte, error) {
	rInput := make([]byte, 16)

	tmp, err := calcTemp(m.RAND, m.OPc, m.K)
	if err != nil {
		return nil, err
	}
	in1 := append(m.SQN, m.AMF, m.SQN, m.AMF)

	// XOR op_c and in1, rotate by r1=64, and XOR
    // on the constant c1 (which is all zeroes) 
	for i :=0; i < 16; i++ {
		rInput[(i + 8) % 16] = in1[i] ^ m.OPc[i]
	}

	// XOR on the value temp computed before

	for i :=0; i < 16; i++ {
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
	m.OPc, err := ComputeOPc(m.OP, m.K)
}

func encrypt(input, k []byte) ([]byte, error) {
	out := make(len(input))
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
		rInput[i] = rand ^ opc[i]
	}

	tmp, err := encrypt(rInput, k)
	if err != nil {
		return nil, err
	}

	return tmp, nil
}
