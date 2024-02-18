using System.Security.Cryptography;
using Microsoft.AspNetCore.Identity;
using Konscious.Security.Cryptography;

namespace App.Areas.Identity;

/// <summary>
/// Password hasher backed by Argon2id.
/// </summary>
/// <remarks>
/// For reference, consider the <see href="https://github.com/aspnet/AspNetIdentity/blob/main/src/Microsoft.AspNet.Identity.Core/PasswordHasher.cs">default implementation</see>
/// </remarks>
internal class Argon2idHasher : IPasswordHasher<IdentityUser>
{

    /// <summary>
    /// Hash a password using Argon2id.
    /// </summary>
    /// <param name="password">Password to hash.</param>
    /// <returns>String containing all the information needed to verify the password in the future.</returns>
    public string HashPassword(IdentityUser user, string password)
    {
        byte[] passwordBytes = Utils.StringToBytes(password);

        // Use a random 32-byte salt and a 32-byte digest.
        byte[] randSalt = Utils.Get32ByteSalt();

        // Degrees of parallelism is 8, iterations is 4, and memory size is 128MB.
        var argon2ID = new Argon2id(passwordBytes)
        {
            DegreeOfParallelism = 8,
            Iterations = 4,
            MemorySize = 128 * 1024,
            Salt = randSalt
        };
        byte[] argonDigest = argon2ID.GetBytes(32);

        // Encode as "Base64(salt):Base64(digest)"
        return Utils.EncodeSaltAndDigest(randSalt, argonDigest);
    }

    /// <summary>
    /// Verify that a password matches the hashed password.
    /// </summary>
    /// <param name="hashedPassword">Hashed password value stored when registering.</param>
    /// <param name="providedPassword">Password provided by user in login attempt.</param>
    /// <returns></returns>
    public PasswordVerificationResult VerifyHashedPassword(IdentityUser user, string hashedPassword, string providedPassword)
    {
        (byte[] salt, byte[] expectedDigest) = Utils.DecodeSaltAndDigest(hashedPassword);

        // compute hash of the recieved password
        byte[] recievedPasswordByteArray = Utils.StringToBytes(providedPassword);

        // Degrees of parallelism is 8, iterations is 4, and memory size is 128MB.
        var argon2Recieved = new Argon2id(recievedPasswordByteArray)
        {
            DegreeOfParallelism = 8,
            Iterations = 4,
            MemorySize = 128 * 1024,
            Salt = salt
        };
        
        byte[] recievedDigest = argon2Recieved.GetBytes(32);

        if (expectedDigest.SequenceEqual(recievedDigest))
        {
            return PasswordVerificationResult.Success;
        }
        return PasswordVerificationResult.Failed;
    }
}