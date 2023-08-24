using System.Text;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.X509;

namespace BouncyCastleUtilities.Demo;

public class EccDemo
{
    public static void Run()
    {
        try
        {
            Console.WriteLine(nameof(EccDemo));

            var keyPair = EccKeyTool.Generate();
            
            var keyPairAsString = EccKeyTool.GenerateAsString();
            Console.WriteLine($"publicKey: {keyPairAsString.publicKey}");
            Console.WriteLine($"privateKey: {keyPairAsString.privateKey}");

            var publicKey = EccKeyTool.String2PublicKey(keyPairAsString.publicKey);
            var privateKey = EccKeyTool.String2PrivateKey(keyPairAsString.privateKey);
            
            keyPair = (EccKeyTool.String2PublicKey(keyPairAsString.publicKey), EccKeyTool.String2PrivateKey(keyPairAsString.privateKey));
            
            var encoder = new EccEncoder(keyPair.publicKey);
            var decoder = new EccDecoder(keyPair.privateKey);
            
            DemoTest.TestCoder(encoder, decoder);
            DemoTest.TestSigner(new EccSigner(keyPair.privateKey), new EccVerifier(keyPair.publicKey));
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }
}