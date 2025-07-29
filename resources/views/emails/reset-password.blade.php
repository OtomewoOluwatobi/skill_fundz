<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Reset Your Password</title>
    <!--[if mso]>
    <noscript>
        <xml>
            <o:OfficeDocumentSettings>
                <o:PixelsPerInch>96</o:PixelsPerInch>
            </o:OfficeDocumentSettings>
        </xml>
    </noscript>
    <![endif]-->
</head>
<body style="margin:0; padding:0; background-color:#f5f5f5; font-family:Arial, sans-serif;">
    <table role="presentation" width="100%" cellspacing="0" cellpadding="0" border="0" style="background-color:#f5f5f5;">
        <tr>
            <td align="center" style="padding:40px 20px;">
                <table role="presentation" width="600" cellspacing="0" cellpadding="0" border="0" style="max-width:600px; background-color:#ffffff; border-radius:12px; box-shadow:0 4px 12px rgba(0,0,0,0.1);">
                    <tr>
                        <td style="padding:60px 40px 40px; text-align:center;">
                            <!-- Icon Section -->
                            <div style="margin-bottom: 30px;">
                                <svg
                                width="68px"
                                height="68px"
                                viewBox="0 0 24 24"
                                fill="none"
                                xmlns="http://www.w3.org/2000/svg"
                              >
                                <path
                                  d="M12 2C13.1 2 14 2.9 14 4V6H16C17.1 6 18 6.9 18 8V20C18 21.1 17.1 22 16 22H8C6.9 22 6 21.1 6 20V8C6 6.9 6.9 6 8 6H10V4C10 2.9 10.9 2 12 2Z"
                                  stroke="#DC2626"
                                  strokeWidth="2"
                                  fill="#FEF2F2"
                                />
                                <circle cx="12" cy="14" r="2" fill="#DC2626"/>
                                <path d="M12 16V18" stroke="#DC2626" strokeWidth="2" strokeLinecap="round"/>
                              </svg>
                            </div>
                            

                            <!-- Heading and Subtitle -->
                            <h1 style="margin:20px 0 20px; font-size:32px; font-weight:bold; color:#1f2937; line-height:1.2;">Reset Your Password</h1>
                            <p style="margin:0 0 40px; font-size:16px; color:#6b7280; line-height:1.5;">
                                Hi {{ $user->first_name }}, we received a request to reset your password. Click the button below to create a new password.
                            </p>

                            <!-- Reset Button Section -->
                            <div style="margin-bottom:30px;">
                                <a href="{{ $resetUrl }}" 
                                   style="display:inline-block; background-color:#dc2626; color:#ffffff; padding:16px 32px; text-decoration:none; border-radius:8px; font-weight:600; font-size:16px; margin-bottom:20px;">
                                    Reset Password
                                </a>
                            </div>

                            <!-- Manual Link Section -->
                            <div style="background-color:#f9fafb; border:1px solid #e5e7eb; border-radius:8px; padding:20px; margin-bottom:20px;">
                                <p style="margin:0 0 10px; font-size:14px; color:#374151; font-weight:600;">If the button doesn't work, copy and paste this link:</p>
                                <p style="margin:0; font-size:12px; color:#6b7280; word-break:break-all;">
                                    {{ $resetUrl }}
                                </p>
                            </div>

                            <!-- Expiration Notice -->
                            <div style="display:flex; align-items:center; justify-content:center; margin-bottom:20px;">
                                <p style="margin:0; font-size:16px; font-weight: normal; color:#6b7280;">This link is valid for 60 minutes only.</p>
                            </div>
                        </td>
                    </tr>

                    <!-- Footer Section -->
                    <tr>
                        <td style="padding:30px 40px; text-align:center; border-top:1px solid #e5e7eb;">
                            <p style="margin:0 0 10px; font-size:16px; color:#374151; font-weight:600;">Didn't request a password reset?</p>
                            <p style="margin:0; font-size:14px; color:#6b7280;">
                                Please ignore this email or 
                                <a href="mailto:support@skillfundz.com" style="color:#3b82f6; text-decoration:none;">contact support</a> if you have concerns.
                            </p>
                        </td>
                    </tr>

                    <!-- Company Footer -->
                    <tr>
                        <td style="padding:20px 40px; text-align:center; background-color:#f9fafb; border-radius:0 0 12px 12px;">
                            <p style="margin:0; font-size:12px; color:#9ca3af;">©️ {{ date('Y') }} SkillFundz. All rights reserved.</p>
                        </td>
                    </tr>
                </table>
            </td>
        </tr>
    </table>
</body>
</html>
