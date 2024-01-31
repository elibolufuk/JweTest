//https://www.scottbrady91.com/c-sharp/json-web-encryption-jwe-in-dotnet-core
using JweTest.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Net;
using System.Security.Cryptography;

namespace JweTest.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TokenController : ControllerBase
    {
        RSA encryptionKey = RSA.Create(3072); // public key for encryption, private key for decryption
        ECDsa signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); // private key for signing, public key for validation

        string encryptionKid = "8524e3e6674e494f85c5c775dcd602c5";
        string signingKid = "29b4adf8bcc941dc8ce40a6d0227b6d3";

        [HttpGet]
        [ProducesResponseType(typeof(TokenResponseModel), (int)HttpStatusCode.OK)]
        public async Task<IActionResult> Get()
        {
            var result = CreateAndValidateJwe();
            return Ok(result);
        }

        public TokenResponseModel CreateAndValidateJwe()
        {
            var privateSigningKey = new ECDsaSecurityKey(signingKey) { KeyId = signingKid };
            var publicEncryptionKey = new RsaSecurityKey(encryptionKey.ExportParameters(false)) { KeyId = encryptionKid };
            var token = CreateJwe(privateSigningKey, publicEncryptionKey);
            var result = new TokenResponseModel
            {
                Token = token
            };

            var privateEncryptionKey = new RsaSecurityKey(encryptionKey) { KeyId = encryptionKid };
            var publicSigningKey = new ECDsaSecurityKey(ECDsa.Create(signingKey.ExportParameters(false))) { KeyId = signingKid };
            var status = DecryptAndValidateJwe(token, privateEncryptionKey, publicSigningKey);
            return result;
        }

        private static string CreateJwe(SecurityKey signingKey, SecurityKey encryptionKey)
        {
            var handler = new JsonWebTokenHandler();

            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Audience = "api1",
                Issuer = "https://idp.example.com",
                Claims = new Dictionary<string, object> 
                {
                    { "id", "811e790749a24d8a8f766e1a44dca28a" },
                    { "name", "ufuk elibol" },
                    { "email", "ufuk.elibol@test.com" }
                },

                // private key for signing
                SigningCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.EcdsaSha256),

                // public key for encryption
                EncryptingCredentials = new EncryptingCredentials(encryptionKey, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512)
            };

            return handler.CreateToken(tokenDescriptor);
        }

        private static bool DecryptAndValidateJwe(string token, SecurityKey encryptionKey, SecurityKey signingKey)
        {
            var handler = new JsonWebTokenHandler();

            TokenValidationResult result = handler.ValidateToken(
                token,
                new TokenValidationParameters
                {
                    ValidAudience = "api1",
                    ValidIssuer = "https://idp.example.com",

                    // public key for signing
                    IssuerSigningKey = signingKey,

                    // private key for encryption
                    TokenDecryptionKey = encryptionKey
                });

            return result.IsValid;
        }
    }
}
