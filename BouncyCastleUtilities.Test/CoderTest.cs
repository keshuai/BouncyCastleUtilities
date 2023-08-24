namespace BouncyCastleUtilities.Test;

public class CoderTest
{
    private const int TestCount = 5;
    
    public static bool TestCoder(Coder encoder, Coder decoder)
    {
        for (var i = 0; i < TestCount; ++i)
        {
            if (!TestCoder(encoder, decoder, GenerateBytes(100, 10000)))
            {
                return false;
            }
        }

        return true;
    }

    public static bool TestSinger(Signer signer, Verifier verifier)
    {
        for (var i = 0; i < TestCount; ++i)
        {
            if (!TestSinger(signer, verifier, GenerateBytes(100, 10000)))
            {
                return false;
            }
        }

        return true;
    }

    private static byte[] GenerateBytes(int minLen, int maxLen)
    {
        var len = System.Security.Cryptography.RandomNumberGenerator.GetInt32(minLen, maxLen);
        return System.Security.Cryptography.RandomNumberGenerator.GetBytes(len);
    }

    private static bool TestCoder(Coder encoder, Coder decoder, byte[] bytes)
    {
        var encoded = encoder.Code(bytes);
        var decoded = decoder.Code(encoded);
        return CompareBytes(bytes, decoded);
    }
    
    private static bool TestSinger(Signer signer, Verifier verifier, byte[] bytes)
    {
        var signature = signer.Sign(bytes);
        return verifier.Verify(bytes, signature);
    }
    
    private static bool CompareBytes(byte[] bytes1, byte[] byte2)
    {
        var len1 = bytes1 == null ? 0 : bytes1.Length;
        var len2 = byte2 == null ? 0 : byte2.Length;
        
        if (len1 != len2)
        {
            return false;
        }

        for (int i = 0; i < len1; i++)
        {
            if (bytes1[i] != byte2[i])
            {
                return false;
            }
        }

        return true;
    }
}