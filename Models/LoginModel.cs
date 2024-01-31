using System.ComponentModel.DataAnnotations;

namespace ForgotPassword2.Controllers.Models
{
    public class LoginModel
    {
        [Required]
        public string? Email { get; set; }
        [Required]
        public string? Password { get; set; }
    }
}
