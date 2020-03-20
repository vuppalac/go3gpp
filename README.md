# Implements the 3gpp related specifications
## milenage module
Implementation according to **TS 35.206**

> Usage
```go
macA, _ := F1(k, opc, rand, sqn, amf)
res, ck, ik, ak, _ := F2345(k, opc, rand)
```