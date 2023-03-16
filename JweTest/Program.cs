//https://www.scottbrady91.com/c-sharp/json-web-encryption-jwe-in-dotnet-core

using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;


#region Cryptography

var encryptionKey = RSA.Create(3072); // public key for encryption, private key for decryption
var signingKey = ECDsa.Create(ECCurve.NamedCurves.nistP256); // private key for signing, public key for validation

var encryptionKid = "8524e3e6674e494f85c5c775dcd602c5";
var signingKid = "29b4adf8bcc941dc8ce40a6d0227b6d3";

var privateEncryptionKey = new RsaSecurityKey(encryptionKey) { KeyId = encryptionKid };
var publicEncryptionKey = new RsaSecurityKey(encryptionKey.ExportParameters(false)) { KeyId = encryptionKid };
var privateSigningKey = new ECDsaSecurityKey(signingKey) { KeyId = signingKid };
var publicSigningKey = new ECDsaSecurityKey(ECDsa.Create(signingKey.ExportParameters(false))) { KeyId = signingKid };


var handler = new JsonWebTokenHandler();

string token = handler.CreateToken(new SecurityTokenDescriptor
{
    Audience = "api1",
    Issuer = "https://idp.example.com",
    Claims = new Dictionary<string, object>
    {
        { "id", "654564" },
        { "username", "ufuk" },
        { "email", "ufuk.elibol@procat.com.tr" }
    },

    // private key for signing
    SigningCredentials = new SigningCredentials(
        privateSigningKey, SecurityAlgorithms.EcdsaSha256),

    // public key for encryption
    EncryptingCredentials = new EncryptingCredentials(
        publicEncryptionKey, SecurityAlgorithms.RsaOAEP, SecurityAlgorithms.Aes256CbcHmacSha512)
});


TokenValidationResult result = handler.ValidateToken(
    token,
    new TokenValidationParameters
    {
        ValidAudience = "api1",
        ValidIssuer = "https://idp.example.com",

        // public key for signing
        IssuerSigningKey = publicSigningKey,

        // private key for encryption
        TokenDecryptionKey = privateEncryptionKey
    });

#endregion

var builder = WebApplication.CreateBuilder(args);

#region AddAuthentication

builder.Services.AddAuthentication("jwt")
  .AddJwtBearer("jwt", options =>
  {
      options.Authority = "https://localhost:5000";
      options.Audience = "api1";
      options.TokenValidationParameters.TokenDecryptionKey = new RsaSecurityKey(encryptionKey);
  });

#endregion


// Add services to the container.

builder.Services.AddControllers();

var app = builder.Build();

// Configure the HTTP request pipeline.
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();
