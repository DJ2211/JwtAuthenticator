namespace JwtAuthenticator.Services;
public class EmailSender : IEmailSender
{
    private readonly ILogger<EmailSender> _logger;
    public EmailSender(ILogger<EmailSender> logger)
    {
        _logger = logger;
    }

    public Task SendEmailAsync(string toEmail, string subject, string message)
    {
        // In local development, log to console.
        // In production, plug in SendGrid, Resend, AWS SES, or SMTP here.
        _logger.LogInformation("================ EMAIL DISPATCH ================");
        _logger.LogInformation("To: {ToEmail}", toEmail);
        _logger.LogInformation("Subject: {Subject}", subject);
        _logger.LogInformation("Content: {Message}", message);
        _logger.LogInformation("===============================================");

        return Task.CompletedTask;
    }
}
