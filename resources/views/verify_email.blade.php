<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <title>Verify Your Email</title>
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
                            <div class="margin-bottom: 100px">
                                <svg
                                width="68px"
                                height="68px"
                                viewBox="0 0 24 24"
                                fill="none"
                                xmlns="http://www.w3.org/2000/svg"
                                
                              >
                                <path
                                  d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"
                                  stroke="#3B82F6"
                                  strokeWidth="2"
                                  fill="#EBF4FF"
                                />
                                <path d="m22 6-10 7L2 6" stroke="#3B82F6" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                                <circle cx="18" cy="8" r="6" fill="#3B82F6" stroke="#FFFFFF" strokeWidth="2" />
                                <path d="m15 8 2 2 4-4" stroke="#FFFFFF" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                              </svg>
                            </div>
                            

                            <!-- Heading and Subtitle -->
                            <h1 style="margin:20px 0 20px; font-size:32px; font-weight:bold; color:#1f2937; line-height:1.2;">Verify Your Email</h1>
                            <p style="margin:0 0 40px; font-size:16px; color:#6b7280; line-height:1.5;">
                                {{ $user->first_name }}, you're almost done! Just one more step to complete your registration.
                            </p>

                            <!-- Verification Button Section -->
                            <div style="margin-bottom:30px;">
                                <a href="{{ $verificationUrl }}" 
                                   style="display:inline-block; background-color:#3b82f6; color:#ffffff; padding:16px 32px; text-decoration:none; border-radius:8px; font-weight:600; font-size:16px; margin-bottom:20px;">
                                    Verify Email Address
                                </a>
                            </div>

                            <!-- Manual Link Section -->
                            <div style="background-color:#f9fafb; border:1px solid #e5e7eb; border-radius:8px; padding:20px; margin-bottom:20px;">
                                <p style="margin:0 0 10px; font-size:14px; color:#374151; font-weight:600;">If the button doesn't work, copy and paste this link:</p>
                                <p style="margin:0; font-size:12px; color:#6b7280; word-break:break-all;">
                                    {{ $verificationUrl }}
                                </p>
                            </div>

                            <!-- Expiration Notice -->
                            <div style="display:flex; align-items:center; justify-content:center; margin-bottom:20px;">
                                <p style="margin:0; font-size:16px; font-weight: normal; color:#6b7280;">This link is valid for 1 hour only.</p>
                            </div>
                        </td>
                    </tr>

                    <!-- Footer Section -->
                    <tr>
                        <td style="padding:30px 40px; text-align:center; border-top:1px solid #e5e7eb;">
                            <p style="margin:0 0 10px; font-size:16px; color:#374151; font-weight:600;">Didn't create an account?</p>
                            <p style="margin:0; font-size:14px; color:#6b7280;">
                                Please contact us immediately 
                                <a href="mailto:support@skillfundz.com" style="color:#3b82f6; text-decoration:none;">by clicking here</a>
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