## Examples Using Web Crypto Browser API with ReactJs

### Available Examples
- Asymmetric encryption with RSA
- Symmetric encryption with AES
- Generate Hash with Common DIGEST Algorithm

### Compatible Server side Package
- NodeJs https://github.com/telkomdev/crypsi
- Python https://github.com/telkomdev/pycrypsi
- Golang https://github.com/telkomdev/go-crypsi

### Golang Server side RSA and AES code example
```go
package main

import (
	"encoding/hex"
	"fmt"
	"github.com/telkomdev/go-crypsi/aesx"
	"github.com/telkomdev/go-crypsi/rsax"
	"io/ioutil"
	"os"
)

func main() {
	key256 := "kJjG$qMCzbzqW6WWge2ZHFD777gjERHO"

	res, err := aesx.DecryptWithAES256GCM([]byte(key256), []byte("1923cf8dcb4ab3039f2d95c01eb5517c0f887d9ab2130554f8f5fac8ba558a09de6722ef9fc9582b8056f38510dcd1d864"))
	if err != nil {
		fmt.Println(err)
	} else {
		fmt.Println(string(res))
	}

	fmt.Println("-------------")

	privateKeyFile, err := os.Open("./private.key")
	if err != nil {
		fmt.Println("error: open private.key")
		os.Exit(1)
	}

	defer func() { privateKeyFile.Close() }()

	privateKeyData, err := ioutil.ReadAll(privateKeyFile)
	if err != nil {
		fmt.Println("error: ReadAll private.key")
		os.Exit(1)
	}

	privateKey, err := rsax.LoadPrivateKey(privateKeyData)
	if err != nil {
		fmt.Println("error: LoadPrivateKey() private.key ", err)
		os.Exit(1)
	}

	encryptedData, _ := hex.DecodeString("7db9669cad0a3e699a285ffca744a377738e78afdf14b2d1a877f76067e9e049d63d71411d037f47219e398c9c11b632f2f95527f2f0d52c0295974e79baead1fcf6be3a3c8b522efa461cd4db19041dcb5c74c0077171f8a8bf839c81ffef178c8a1a94a168c8d2ee48271470c3a5ec202ca228f4aa7b8266cccba11a3f4178e9e878b1a1d7dd677f64427011f13ae9e9237a11654737e0bcbaf4fc8a9c0103d1cbc4ed313a5ce5919b0c24b952cc7423605df265671a6e4278696ebc5e4fab3380a52ed913368408ca73627eaa3f389f53c705edeb75bd9acb4c4b390c7486ca4f731d1a13024de5a19fcd4936d34cb4cf924c881a5fa8757ccd1cc1c73f4b")

	plainData, err := rsax.DecryptWithOAEPSha256(privateKey, encryptedData)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(string(plainData))

}

```

### NodeJs Server side RSA and AES code example
```javascript
const {aesEncryption, rsaEncryption, rsa} = require('crypsi');
const fs = require('fs');

const resAes256Gcm = aesEncryption.encryptWithAes256Gcm(
    'kJjG$qMCzbzqW6WWge2ZHFD777gjERHO',
    Buffer.from('wuriyanto')
);

console.log('resAes256Gcm: ', resAes256Gcm.toString('utf8'));
console.log('resAes256Gcm: ', resAes256Gcm.toString('hex'));
const res = aesEncryption.decryptWithAes256Gcm('kJjG$qMCzbzqW6WWge2ZHFD777gjERHO', Buffer.from('726d05e184d97f8d662a45a435e9ee542e0d9448fdb089c63bbefc7a0690a91447b70ff589891f9fed6bff78e86ec3', 'hex'));
console.log(res.toString());
// 6bda44c1d3b70a648e38e09be1f32bded6a1d13ca19b6d5a61e614a91e93c4c58aae33cfe8
// 0f94ca41cd99c84e4e75629170f4a193cac58563e18083f32e6808ac9660d8e1819f4d534c
// 6d9707b68b7088393f59b8cc52404044495c4e9e7d3b5a90e08e106534319fe40230b84d5e

const privateKeyBuf = fs.readFileSync('./private.key');
const publicKeyBuf = fs.readFileSync('./public.key');

const privateKey = rsa.loadPrivateKey(privateKeyBuf);
const publicKey = rsa.loadPublicKey(publicKeyBuf);

const rsaDecryptRes = rsaEncryption.decryptWithOaepSha256(privateKey, Buffer.from('0fd97924defac2f073d164258560bec227b63f4cfc71298c6c2686deb3ecee3d1b466fc1ac49613227aa15cddf01494f06b9c13a6616ee0726495756469c24200e2e2206fe839eb37d7202b588757a946fc5a9ea03bc4c60975474875e90b962adbc05ec2a04eedf05d89b404f67e6855282bb751cd9df6e5077ed15038e92b56014e834b0cfb21a19dcc5e1810f625ea76667c6f6e71723b6d134544b7a9500fe3dd69d93f47fc13f0b949c6a765ca44b24fcac3a10e276ac6bc3c354e89cf21a66efbc75b6035fbba12d134842a720acdd2dc6e6ee674a51b6870a31bfa639f3821d6e454eb39ace630c334d8a8e8140a0f59abc81606a48d7f9acbc6b6ef3', 'hex'));
console.log(rsaDecryptRes.toString());
```