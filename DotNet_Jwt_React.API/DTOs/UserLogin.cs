using System.ComponentModel.DataAnnotations;

namespace DotNet_Jwt_React.API.DTOs;

public class UserLogin
{
    [Required]
    [MaxLength(48)]
    public string Username { get; set; }

    [Required]
    [MinLength(6)]
    [MaxLength(16)]
    public string Password { get; set; }
}
