namespace ForgotPassword2.Controllers.Models
{
    public class User
    {
        public int UserId { get; set; }

        public string? UserName { get; set; }

        public string? Email { get; set; }

        public string? Password { get; set; }

        public string? ResetToken { get; set; }

        public DateTime ResetTokenExpiry { get; set; }

    }
}
