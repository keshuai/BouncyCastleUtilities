using Org.BouncyCastle.Crypto.Parameters;

namespace BouncyCastleUtilities.Test;

public class RsaTests
{
    [Test]
    public void TestCoder()
    {
        var keyPair = RsaKeyTool.Generate();
        Assert.AreEqual(true, TestCoderWithKey(keyPair.publicKey, keyPair.privateKey));
    }
    
    [Test]
    public void TestSinger()
    {
        var keyPair = RsaKeyTool.Generate();
        Assert.AreEqual(true, TestSingerWithKey(keyPair.publicKey, keyPair.privateKey));
    }
    
    private static bool TestCoderWithKey(RsaKeyParameters publicKey, RsaPrivateCrtKeyParameters privateKey)
    {
        return 
            CoderTest.TestCoder(new RsaEncoder(privateKey), new RsaDecoder(publicKey)) &&
            CoderTest.TestCoder(new RsaEncoder(publicKey), new RsaDecoder(privateKey));
    }
    
    private static bool TestSingerWithKey(RsaKeyParameters publicKey, RsaPrivateCrtKeyParameters privateKey)
    {
        return CoderTest.TestSinger(new RsaSigner(privateKey), new RsaVerifier(publicKey));
    }
}