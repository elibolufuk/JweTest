
using Microsoft.IdentityModel.Tokens;
using System.Security.Cryptography;

var builder = WebApplication.CreateBuilder(args);

#region AddAuthentication

builder.Services.AddAuthentication("jwt")
  .AddJwtBearer("jwt", options =>
  {
      options.Authority = "https://localhost:5000";
      options.Audience = "api1";
      options.TokenValidationParameters.TokenDecryptionKey = new RsaSecurityKey(RSA.Create(3072));//TokenController.Get.encryptionKey
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
