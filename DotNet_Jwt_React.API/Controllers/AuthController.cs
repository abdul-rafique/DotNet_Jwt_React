
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Xml;
using DotNet_Jwt_React.API.DTOs;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace DotNet_Jwt_React.API.Controllers;

[Route("api/auth")]
[ApiController]
public class AuthController : ControllerBase
{
    private static List<RefreshToken> refreshTokens = new();
    private readonly IConfiguration _config;

    public AuthController(IConfiguration config)
    {
        _config = config;
    }

    /// <summary>
    /// Authenticate user, Generate JWT and Refresh Tokens
    /// </summary>
    /// <param name="request"></param>
    /// <returns>200</returns>
    /// <remarks>
    /// Sample Request:
    /// 
    ///     POST /login
    ///     {
    ///         "username": "johndoe",
    ///         "password": "johndoe@123"
    ///     }
    ///     
    /// </remarks>
    [HttpPost("login")]
    [ProducesResponseType(statusCode: 200)]
    public IActionResult Login([FromBody] UserLogin request)
    {
        //Perform validation if neccessary

        var tokenString = GenerateJwtToken(request.Username);
        var refreshToken = GenerateRefreshToken(request.Username);

        return Ok(new
        {
            Token = tokenString,
            RefreshToken = refreshToken.Token
        });
    }

    /// <summary>
    /// Generate new JWT token
    /// </summary>
    /// <param name="request"></param>
    /// <returns></returns>
    /// <remarks>
    /// Sample Request:
    /// 
    ///     POST /refresh
    ///     {
    ///         "token": "expired JWT token"
    ///         "refreshToken": "valid refresh token generate by login"
    ///     }
    /// </remarks>
    [HttpPost("refresh")]
    public IActionResult Refresh([FromBody] TokenRequest request)
    {
        var principal = GetPrincipalFromExpiredToken(request.Token);

        if (principal == null)
        {
            return BadRequest("Invalid token");
        }

        var username = principal?.Identity?.Name;
        var storedRefreshToken = refreshTokens.FirstOrDefault(rt => rt.Username == username && rt.Token == request.RefreshToken);

        if (storedRefreshToken == null || storedRefreshToken.ExpiryDate < DateTime.UtcNow)
        {
            return Unauthorized("Invalid refresh token");
        }

        var newJwtToken = GenerateJwtToken(username);
        var newRefreshToken = GenerateRefreshToken(username);

        refreshTokens.Remove(storedRefreshToken);

        return Ok(new
        {
            Token = newJwtToken,
            RefreshToken = newRefreshToken.Token
        });
    }

    #region Helpers
    private string GenerateJwtToken(string username)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var issuerSigningKey = Encoding.ASCII.GetBytes(_config.GetValue<string>("Jwt:IssuerSigningKey"));
        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(new Claim[]{
                new(ClaimTypes.Name, username)
            }),
            Expires = DateTime.UtcNow.AddMinutes(15),
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(issuerSigningKey), SecurityAlgorithms.HmacSha256Signature)
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    private RefreshToken GenerateRefreshToken(string username)
    {
        var refreshToken = new RefreshToken
        {
            Token = Guid.NewGuid().ToString(),
            Username = username,
            ExpiryDate = DateTime.UtcNow.AddDays(7)
        };

        refreshTokens.Add(refreshToken);

        return refreshToken;
    }

    private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(_config.GetValue<string>("Jwt:IssuerSigningKey"));
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(key),
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = false
        };

        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken validatedToken);

        var jwtSecurityToken = validatedToken as JwtSecurityToken;
        if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
        {
            throw new SecurityTokenException("Invalid token");
        }

        return principal;
    }
    #endregion

}
