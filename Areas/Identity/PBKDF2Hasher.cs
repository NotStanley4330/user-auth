using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by PBKDF2.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class PBKDF2Hasher : IPasswordHasher<IdentityUser>
{
    int iterations = 100000;

    /// <summary>
    /// Hash a password using PBKDF2.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password)
    {
        byte[] passwordByteArray = Utils.StringToBytes(password);

        // Use a random 32-byte salt. Use a 32-byte digest.
        byte[] randSalt = Utils.Get32ByteSalt();

        // todo: Use 100,000 iterations and the SHA256 algorithm.
        byte[] sha256Digest = Rfc2898DeriveBytes.Pbkdf2(passwordByteArray, randSalt, iterations, HashAlgorithmName.SHA256, 32);

        // Encode as "Base64(salt):Base64(digest)"
        string encodedPassword = Utils.EncodeSaltAndDigest(randSalt, sha256Digest);

        return encodedPassword;
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

        // compute hash and derive digest
        byte[] recievedPasswordBytes = Utils.StringToBytes(providedPassword);
        byte[] derivedDigest = Rfc2898DeriveBytes.Pbkdf2(recievedPasswordBytes, recievedSalt, iterations, HashAlgorithmName.SHA256, 32);

        //verift whether the expected digest matches the derived one
        if (expectedDigest.SequenceEqual(derivedDigest))
        {
            return PasswordVerificationResult.Success;
        }
        return PasswordVerificationResult.Failed;
    }
}