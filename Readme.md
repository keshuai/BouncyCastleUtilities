# BouncyCastleUtilities

使用BouncyCastle进行非对称加密，ECC或RSA，简单快捷，开箱即可实用。

# 使用方法

ECC加密:

```
var bytes = ...

var keyPair = EccKeyTool.Generate();
var encoder = new EccEncoder(keyPair.publicKey);
var decoder = new EccDecoder(keyPair.privateKey);

var encoded = encoder.Code(bytes);
var decoded = decoder.Code(encoded);

var success = CompareBytes(bytes, decoded);

```

ECC签名

```
var bytes = ...

var keyPair = EccKeyTool.Generate();
var singer = new EccSinger(keyPair.privateKey);
var verifier = new EccVerifier(keyPair.privateKey);

var signature = singer.Sign(bytes);
var success = verifier.Verify(bytes, signature);

```



RSA加密:

```
var bytes = ...

var keyPair = RsaKeyTool.Generate();
var encoder = new RsaEncoder(keyPair.publicKey);
var decoder = new RsaDecoder(keyPair.privateKey);
var encoded = encoder.Code(bytes);
var decoded = decoder.Code(encoded);

var success = CompareBytes(bytes, decoded);
```

RSA签名:

```
var bytes = ...

var keyPair = RsaKeyTool.Generate();
var singer = new RsaSinger(keyPair.privateKey);
var verifier = new RsaVerifier(keyPair.privateKey);

var signature = singer.Sign(bytes);
var success = verifier.Verify(bytes, signature);

```



其它：

- ECC这里只能使用公钥加密，私钥解密，不能反过来。
- RSA这里可以使用公钥加密，私钥解密，也能反过来，私钥加密，公钥解密。
- 建议使用ECC
- 私钥切记不能暴漏出去，使用随机生成密钥对更好，这样写代码的程序员自己也没法解密。

依赖：

BouncyCastle：[https://github.com/bcgit/bc-csharp]: https://github.com/bcgit/bc-csharp



