﻿namespace ForgotPassword2.Controllers.Models
{
    public class PasswordResetModel
    {
        public string? Email {  get; set; }
        public string? ResetToken { get; set; }
        public string? NewPassword { get; set; }
    }
}
