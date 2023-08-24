using System.Text;
using Org.BouncyCastle.Crypto.Parameters;

namespace BouncyCastleUtilities.Test;

public class EccTests
{
    [SetUp]
    public void Setup()
    {
    }

    [Test]
    public void TestKeyTool()
    {
        var keyPair = EccKeyTool.Generate();
        var publicKeyString = EccKeyTool.PublicKey2String(keyPair.publicKey);
        var privateKeyString = EccKeyTool.PrivateKey2String(keyPair.privateKey);

        var publicKeyString2 =  EccKeyTool.PublicKey2String(EccKeyTool.GeneratePublicKeyByPrivateKey(keyPair.privateKey));
        Assert.AreEqual(publicKeyString, publicKeyString2);

        var publicKey2 = EccKeyTool.String2PublicKey(publicKeyString2);
        var privateKey2 = EccKeyTool.String2PrivateKey(privateKeyString);
        
        Assert.AreEqual(true, TestCoderWithKey(publicKey2, privateKey2));
        Assert.AreEqual(true, TestSingerWithKey(publicKey2, privateKey2));
    }
    

    [Test]
    public void TestCoder()
    {
        var keyPair = EccKeyTool.Generate();
        Assert.AreEqual(true, TestCoderWithKey(keyPair.publicKey, keyPair.privateKey));
    }
    
    [Test]
    public void TestSinger()
    {
        var keyPair = EccKeyTool.Generate();
        Assert.AreEqual(true, TestSingerWithKey(keyPair.publicKey, keyPair.privateKey));
    }
    
    private static bool TestCoderWithKey(ECPublicKeyParameters publicKey, ECPrivateKeyParameters privateKey)
    {
        return CoderTest.TestCoder(new EccEncoder(publicKey), new EccDecoder(privateKey));
    }
    
    private static bool TestSingerWithKey(ECPublicKeyParameters publicKey, ECPrivateKeyParameters privateKey)
    {
        return CoderTest.TestSinger(new EccSigner(privateKey), new EccVerifier(publicKey));
    }
}