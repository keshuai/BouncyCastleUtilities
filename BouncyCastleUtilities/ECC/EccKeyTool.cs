using Org.BouncyCastle.Asn1.Sec;
using Org.BouncyCastle.Crypto.EC;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC.Multiplier;
using Org.BouncyCastle.Security;

namespace BouncyCastleUtilities;

public class EccKeyTool
{
    public static (ECPublicKeyParameters publicKey, ECPrivateKeyParameters privateKey) Generate()
    {
        var keyPairGenerator = (ECKeyPairGenerator)GeneratorUtilities.GetKeyPairGenerator("EC");
        keyPairGenerator.Init(new ECKeyGenerationParameters(SecObjectIdentifiers.SecP256r1, new SecureRandom()));
        var pair = keyPairGenerator.GenerateKeyPair();
        return ((ECPublicKeyParameters)pair.Public, (ECPrivateKeyParameters)pair.Private);
    }
    
    public static (byte[] publicKey, byte[] privateKey) GenerateAsSBytes()
    {
        var pair = Generate();
        return (PublicKey2Bytes(pair.publicKey), PrivateKey2Bytes(pair.privateKey));
    }
    
    public static (string publicKey, string privateKey) GenerateAsString()
    {
        var pair = Generate();
        return (PublicKey2String(pair.publicKey), PrivateKey2String(pair.privateKey));
    }
    
    public static ECPublicKeyParameters GeneratePublicKeyByPrivateKey(ECPrivateKeyParameters privateKey)
    {
        var parameters = privateKey.Parameters;
        var q = new FixedPointCombMultiplier().Multiply(parameters.G, privateKey.D);
        return privateKey.PublicKeyParamSet != null ? new ECPublicKeyParameters(privateKey.AlgorithmName, q, privateKey.PublicKeyParamSet) : new ECPublicKeyParameters(privateKey.AlgorithmName, q, parameters);
    }
    
    public static byte[] PublicKey2Bytes(ECPublicKeyParameters publicKeyParameters)
    {
        var q = publicKeyParameters.Q;
        return Combine2Bytes(q.AffineXCoord.ToBigInteger().ToByteArray(), q.AffineYCoord.ToBigInteger().ToByteArray());
    }
    
    public static string PublicKey2String(ECPublicKeyParameters publicKeyParameters) => Convert.ToBase64String(PublicKey2Bytes(publicKeyParameters));

    public static ECPublicKeyParameters Bytes2PublicKey(byte[] publicKeyBytes)
    {
        (int offset1, int count1, int offset2, int count2) = SplitBytes(publicKeyBytes);
        var x = new BigInteger(1, publicKeyBytes, offset1, count1);
        var y = new BigInteger(1, publicKeyBytes, offset2, count2);

        var ecp = CustomNamedCurves.GetByOid(SecObjectIdentifiers.SecP256r1);
        var domainParameters = new ECDomainParameters(ecp.Curve, ecp.G, ecp.N, ecp.H, ecp.GetSeed());
        
        var q = domainParameters.Curve.ValidatePoint(x, y);
        return new ECPublicKeyParameters(q, domainParameters);
    }

    public static ECPublicKeyParameters String2PublicKey(string publicKeyString) => Bytes2PublicKey(Convert.FromBase64String(publicKeyString));
    
    public static byte[] PrivateKey2Bytes(ECPrivateKeyParameters privateKeyParameters) => privateKeyParameters.D.ToByteArray();
    
    public static string PrivateKey2String(ECPrivateKeyParameters privateKeyParameters) => Convert.ToBase64String(privateKeyParameters.D.ToByteArray());

    public static ECPrivateKeyParameters Bytes2PrivateKey(byte[] privateKeyBytes)
    {
        var ecp = CustomNamedCurves.GetByOid(SecObjectIdentifiers.SecP256r1);
        var domainParameters = new ECDomainParameters(ecp.Curve, ecp.G, ecp.N, ecp.H, ecp.GetSeed());
        return new ECPrivateKeyParameters(new BigInteger(1, privateKeyBytes), domainParameters);
    }

    public static ECPrivateKeyParameters String2PrivateKey(string privateKeyString) => Bytes2PrivateKey(Convert.FromBase64String(privateKeyString));

    private static byte[] Combine2Bytes(byte[] bytes1, byte[] bytes2)
    {
        if (bytes1.Length >= byte.MaxValue)
        {
            throw new Exception($"CombineSameLengthBytes: {bytes1.Length} != {bytes2.Length}");
        }

        var buffer = new byte[bytes1.Length + bytes2.Length + 1];
        Buffer.BlockCopy(bytes1, 0, buffer, 0, bytes1.Length);
        Buffer.BlockCopy(bytes2, 0, buffer, bytes1.Length, bytes2.Length);
        buffer[bytes1.Length + bytes2.Length] = (byte)bytes1.Length;
        
        return buffer;
    }
    
    private static (int offset1, int count1, int offset2, int count2) SplitBytes(byte[] bytes)
    {
        var bytes1Length = bytes[bytes.Length - 1];
        return (0, bytes1Length, bytes1Length, bytes.Length - 1 - bytes1Length);
    }
}