using System.ComponentModel.DataAnnotations;

namespace ForgotPassword2.Controllers.Models
{
    public class RegisterModel
    {
        [Required, StringLength(50)]
        public string? Email { get; set; }

        [Required, StringLength(50)]
        public string? phoneNumber { get; set; }

        [Required, StringLength(28)]
        public string? Password { get; set; }

        [Required, StringLength(28)]
        [Compare("Password", ErrorMessage = "The password and confirmation password do not match.")]
        public string? ConfirmPassword { get; set; }
    }
}
