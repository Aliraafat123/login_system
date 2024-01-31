namespace ForgotPassword2.Controllers.Models
{
    public class PasswordResetRequest
    {
        public string? Email { get; set; }

        public string? ResetToken { get; set; }

        public DateTime Timestamp { get; set; }
    }
}
