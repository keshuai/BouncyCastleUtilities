namespace BouncyCastleUtilities.Demo;

public class DemoTest
{
    const string defaultTetsMessage = "Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !Hello encryption with BouncyCastle !";
    
    public static bool TestCoder(Coder encoder, Coder decoder)
    {
        return TestCoder(defaultTetsMessage, encoder, decoder);
    }
    
    public static bool TestCoder(string message, Coder encoder, Coder decoder)
    {
        //Console.WriteLine($"message: {message}");

        var bytes = System.Text.Encoding.UTF8.GetBytes(message);
        
        var encoded = encoder.Code(bytes);
        Console.WriteLine($"encoded.Length: {encoded.Length}");
        
        var decoded = decoder.Code(encoded);
        var message2 = System.Text.Encoding.UTF8.GetString(decoded);
        // Console.WriteLine($"message2: {message2}");

        var success = message == message2;
        Console.WriteLine($"TestCoder compare bytes: {CompareBytes(bytes, decoded)}");
        Console.WriteLine($"TestCoder success: {success}");
        
        return success;
    }

    static bool CompareBytes(byte[] bytes1, byte[] byte2)
    {
        if (bytes1.Length != byte2.Length)
        {
            return false;
        }

        for (int i = 0; i < bytes1.Length; i++)
        {
            if (bytes1[i] != byte2[i])
            {
                return false;
            }
        }

        return true;
    }

    public static bool TestSigner(Signer signer, Verifier verifier)
    {
        return TestSigner(defaultTetsMessage, signer, verifier);
    }
    
    public static bool TestSigner(string messsage, Signer signer, Verifier verifier)
    {
        var bytes = System.Text.Encoding.UTF8.GetBytes(messsage);
        var signature = signer.Sign(bytes);
        var success = verifier.Verify(bytes, signature);
        
        Console.WriteLine($"TestSigner success: {success}");
        return success;
    }
}