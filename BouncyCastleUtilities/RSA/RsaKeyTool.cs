using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace BouncyCastleUtilities;

public class RsaKeyTool
{
    const int DefaultKeyLength = 2048;
    
    public static (RsaKeyParameters publicKey, RsaPrivateCrtKeyParameters privateKey) Generate(int keyLength = DefaultKeyLength)
    {
        var keyGenerator = new RsaKeyPairGenerator();
        keyGenerator.Init(new RsaKeyGenerationParameters(
            Org.BouncyCastle.Math.BigInteger.ValueOf(3),
            new Org.BouncyCastle.Security.SecureRandom(),
            keyLength,   //密钥长度  
            25)
        );

        var keyPair = keyGenerator.GenerateKeyPair();
        return ((RsaKeyParameters)keyPair.Public, (RsaPrivateCrtKeyParameters)keyPair.Private);
    }

    public static (byte[] publicKey, byte[] privateKey) GenerateAsBytes(int keyLength = DefaultKeyLength)
    {
        var keyPair = Generate(keyLength);
        return (PublicKey2Bytes(keyPair.publicKey), PrivateKey2Bytes(keyPair.privateKey));
    }
    
    public static (string publicKey, string privateKey) GenerateAsString(int keyLength = DefaultKeyLength)
    {
        var keyPair = GenerateAsBytes(keyLength);
        return (Convert.ToBase64String(keyPair.publicKey), Convert.ToBase64String(keyPair.privateKey));
    }

    public static byte[] PublicKey2Bytes(RsaKeyParameters publicKey)
    {
        var subjectPublicKeyInfo = SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(publicKey);
        var asn1ObjectPublic = subjectPublicKeyInfo.ToAsn1Object();
        return asn1ObjectPublic.GetEncoded("UTF-8");
    }
    
    public static byte[] PrivateKey2Bytes(RsaPrivateCrtKeyParameters privateKey)
    {
        var privateKeyInfo = PrivateKeyInfoFactory.CreatePrivateKeyInfo(privateKey);
        var asn1ObjectPrivate = privateKeyInfo.ToAsn1Object();
        return asn1ObjectPrivate.GetEncoded("UTF-8");
    }

    public static string PublicKey2String(RsaKeyParameters publicKey) => Convert.ToBase64String(PublicKey2Bytes(publicKey));
    public static string PrivateKey2String(RsaPrivateCrtKeyParameters privateKey) => Convert.ToBase64String(PrivateKey2Bytes(privateKey));
    
    public static RsaKeyParameters Bytes2PublicKey(byte[] keyBytes)
    {
        return (RsaKeyParameters)PublicKeyFactory.CreateKey(keyBytes);
    }
    
    public static RsaPrivateCrtKeyParameters Bytes2PrivateKey(byte[] keyBytes)
    {
        return (RsaPrivateCrtKeyParameters)PrivateKeyFactory.CreateKey(keyBytes);
    }
    
    public static RsaKeyParameters String2PublicKey(string keyString)
    {
        return Bytes2PublicKey(Convert.FromBase64String(keyString));
    }
    
    public static RsaPrivateCrtKeyParameters String2PrivateKey(string keyString)
    {
        return Bytes2PrivateKey(Convert.FromBase64String(keyString));
    }
}