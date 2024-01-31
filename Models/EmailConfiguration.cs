namespace ForgotPassword2.Controllers.Models
{
    public class EmailConfiguration
    {
        
        
            public string? Form { get; set; }

            public int Port { get; set; }

            public string? SmtpServer { get; set; }

            public string? Password { get; set; }
            public string? UserName { get; set; }

            public string? DefaultSEnderEmail { get; set; }
            public bool UseSsl { get; set; }
    }
}
