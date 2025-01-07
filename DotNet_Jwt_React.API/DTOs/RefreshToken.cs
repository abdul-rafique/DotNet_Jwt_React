namespace DotNet_Jwt_React.API.DTOs;

public class RefreshToken
{
    public string Token { get; set; }
    public string Username { get; set; }
    public DateTime ExpiryDate { get; set; }
}
