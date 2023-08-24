using System.Text;
using BouncyCastleUtilities;

namespace BouncyCastleUtilities.Demo;

public class RsaDemo
{
    public static void Run()
    {
        try
        {
            Console.WriteLine(nameof(RsaDemo));

            var keyPair = RsaKeyTool.Generate();
            
            var keyPairAsString = RsaKeyTool.GenerateAsString();
            Console.WriteLine($"publicKey: {keyPairAsString.publicKey}");
            Console.WriteLine($"privateKey: {keyPairAsString.privateKey}");
            
            keyPair = (RsaKeyTool.String2PublicKey(keyPairAsString.publicKey), RsaKeyTool.String2PrivateKey(keyPairAsString.privateKey));
            
            var encoder = new RsaEncoder(keyPair.privateKey);
            var decoder = new RsaDecoder(keyPair.publicKey);
            
            DemoTest.TestCoder(encoder, decoder);
            DemoTest.TestSigner(new RsaSigner(keyPair.privateKey), new RsaVerifier(keyPair.publicKey));
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }
}