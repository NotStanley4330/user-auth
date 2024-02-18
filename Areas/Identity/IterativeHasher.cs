using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by iterative SHA256 hashing.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class IterativeHasher : IPasswordHasher<IdentityUser>
{
    int iterations = 100000;

    /// <summary>
    /// Hash a password using iterative SHA256 hashing.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password)
    {
        byte[] passwordByteArray = Utils.StringToBytes(password);

        // Use a random 32-byte salt. Use a 32-byte digest.
        byte[] randomSalt = Utils.Get32ByteSalt();
        byte[] iterativeDigest = Utils.CombineByteArrays(randomSalt, passwordByteArray);
        
        // 100,000 iterations and the SHA256 algorithm.
        for (int i = 0; i < iterations; i++)
        {
            iterativeDigest = SHA256.HashData(iterativeDigest);
        }

        // Encode as "Base64(salt):Base64(digest)"
        return Utils.EncodeSaltAndDigest(randomSalt, iterativeDigest);
    }

    /// <summary>
    /// Verify that a password matches the hashed password.
    /// </summary>
    /// <param name="hashedPassword">Hashed password value stored when registering.</param>
    /// <param name="providedPassword">Password provided by user in login attempt.</param>
    /// <returns></returns>
    public PasswordVerificationResult VerifyHashedPassword(IdentityUser user, string hashedPassword, string providedPassword)
    {
        (byte[] recievedSalt, byte[] expectedDigest) = Utils.DecodeSaltAndDigest(hashedPassword);

        // compute hash of providedPassword
        byte[] recivedPasswordBytes = Utils.StringToBytes(providedPassword);
        byte[] recievedDigest = Utils.CombineByteArrays(recievedSalt, recivedPasswordBytes);
        for (int i = 0; i < iterations; i++)
        {
            recievedDigest = SHA256.HashData(recievedDigest);
        }

        if (expectedDigest.SequenceEqual(recievedDigest))
        {
            return PasswordVerificationResult.Success;
        }
        return PasswordVerificationResult.Failed;
    }
}