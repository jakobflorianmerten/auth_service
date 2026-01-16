package com.microservice.auth_service.services;

import com.microservice.auth_service.exceptions.EmailSendException;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.MimeMessage;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.stereotype.Service;

/**
 * Service für den Versand von E-Mails im Authentifizierungs-Flow.
 *
 * Versendet HTML-formatierte E-Mails für:
 * - E-Mail-Verifizierung nach Registrierung
 * - Passwort-Reset-Anfragen
 *
 * Verwendet Spring's JavaMailSender mit SMTP-Konfiguration aus application.yaml.
 * Bei Versandfehlern wird EmailSendException geworfen, die vom GlobalExceptionHandler
 * als 500 Internal Server Error behandelt wird.
 *
 * Konfiguration via application.yaml:
 * - spring.mail.username: Absender-Adresse
 * - spring.mail.host/port/password: SMTP-Server-Einstellungen
 *
 * @see com.microservice.auth_service.exceptions.EmailSendException
 * @see com.microservice.auth_service.exceptions.GlobalExceptionHandler
 */
@Slf4j
@Service
public class EmailService {

    private final JavaMailSender mailSender;

    @Value("${spring.mail.username}")
    private String fromEmail;

    public EmailService(JavaMailSender mailSender) {
        this.mailSender = mailSender;
    }

    /**
     * Versendet eine Verifizierungs-E-Mail nach der Registrierung.
     *
     * Die E-Mail enthält einen 6-stelligen Code, den der Benutzer
     * im Frontend eingeben muss, um seine E-Mail-Adresse zu bestätigen.
     *
     * @param toEmail          Empfänger-Adresse
     * @param verificationCode 6-stelliger Verifizierungscode
     * @throws EmailSendException wenn der Versand fehlschlägt
     */
    public void sendVerificationEmail(String toEmail, String verificationCode) {
        String subject = "Verify Your Email Address";
        String htmlContent = buildVerificationEmailContent(verificationCode);

        sendEmail(toEmail, subject, htmlContent);
        log.info("Verification email sent to: {}", toEmail);
    }

    /**
     * Versendet eine Passwort-Reset-E-Mail.
     *
     * Die E-Mail enthält einen Code, mit dem der Benutzer sein
     * Passwort zurücksetzen kann. Enthält Sicherheitshinweise.
     *
     * @param toEmail   Empfänger-Adresse
     * @param resetCode Passwort-Reset-Code
     * @throws EmailSendException wenn der Versand fehlschlägt
     */
    public void sendPasswordResetEmail(String toEmail, String resetCode) {
        String subject = "Reset Your Password";
        String htmlContent = buildPasswordResetEmailContent(resetCode);

        sendEmail(toEmail, subject, htmlContent);
        log.info("Password reset email sent to: {}", toEmail);
    }

    /**
     * Versendet eine HTML-E-Mail.
     *
     * @param toEmail     Empfänger-Adresse
     * @param subject     Betreff
     * @param htmlContent HTML-Inhalt
     * @throws EmailSendException wenn der Versand fehlschlägt
     */
    private void sendEmail(String toEmail, String subject, String htmlContent) {
        try {
            MimeMessage message = mailSender.createMimeMessage();
            MimeMessageHelper helper = new MimeMessageHelper(message, true, "UTF-8");

            helper.setFrom(fromEmail);
            helper.setTo(toEmail);
            helper.setSubject(subject);
            helper.setText(htmlContent, true);

            mailSender.send(message);
        } catch (MessagingException e) {
            log.error("Failed to send email to {}: {}", toEmail, e.getMessage());
            throw new EmailSendException("Failed to send email to " + toEmail, e);
        }
    }

    /**
     * Erstellt den HTML-Inhalt für Verifizierungs-E-Mails.
     *
     * @param verificationCode Verifizierungscode
     * @return HTML-String
     */
    private String buildVerificationEmailContent(String verificationCode) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .code-box {
                            background-color: #f5f5f5;
                            border: 2px dashed #007bff;
                            border-radius: 8px;
                            padding: 20px;
                            text-align: center;
                            margin: 20px 0;
                        }
                        .code {
                            font-size: 32px;
                            font-weight: bold;
                            letter-spacing: 8px;
                            color: #007bff;
                            font-family: 'Courier New', monospace;
                        }
                        .footer { margin-top: 30px; font-size: 12px; color: #666; }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h2>Welcome to Auth Service!</h2>
                        <p>Thank you for registering. Please verify your email address to activate your account.</p>
                        <p>Enter this verification code in your application:</p>
                        <div class="code-box">
                            <div class="code">%s</div>
                        </div>
                        <div class="footer">
                            <p>This code will expire in 24 hours.</p>
                            <p>If you didn't create an account, you can safely ignore this email.</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(verificationCode);
    }

    /**
     * Erstellt den HTML-Inhalt für Passwort-Reset-E-Mails.
     *
     * @param resetCode Passwort-Reset-Code
     * @return HTML-String
     */
    private String buildPasswordResetEmailContent(String resetCode) {
        return """
                <!DOCTYPE html>
                <html>
                <head>
                    <style>
                        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; }
                        .container { max-width: 600px; margin: 0 auto; padding: 20px; }
                        .code-box {
                            background-color: #fff3cd;
                            border: 2px dashed #ff6b6b;
                            border-radius: 8px;
                            padding: 20px;
                            text-align: center;
                            margin: 20px 0;
                        }
                        .code {
                            font-size: 32px;
                            font-weight: bold;
                            letter-spacing: 8px;
                            color: #ff6b6b;
                            font-family: 'Courier New', monospace;
                        }
                        .footer { margin-top: 30px; font-size: 12px; color: #666; }
                        .warning {
                            background-color: #fff3cd;
                            padding: 10px;
                            border-radius: 4px;
                            margin: 15px 0;
                        }
                    </style>
                </head>
                <body>
                    <div class="container">
                        <h2>Password Reset Request</h2>
                        <p>We received a request to reset your password. Use the code below to proceed:</p>
                        <div class="code-box">
                            <div class="code">%s</div>
                        </div>
                        <div class="warning">
                            <strong>Security Notice:</strong> If you didn't request a password reset, please ignore this email. Your password will remain unchanged.
                        </div>
                        <div class="footer">
                            <p>This code will expire in 1 hour.</p>
                            <p>For security reasons, never share this code with anyone.</p>
                        </div>
                    </div>
                </body>
                </html>
                """.formatted(resetCode);
    }
}