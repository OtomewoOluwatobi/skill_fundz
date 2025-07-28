<?php

namespace App\Notifications;

use App\Models\User;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\URL;

class EmailVerificationNotification extends Notification implements ShouldQueue
{
    use Queueable;

    public $user;
    public $verificationUrl;

    /**
     * Create a new notification instance.
     */
    public function __construct(User $user)
    {
        $this->user = $user;
        $this->verificationUrl = $this->generateVerificationUrl();
    }

    /**
     * Get the notification's delivery channels.
     *
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['mail'];
    }

    /**
     * Get the mail representation of the notification.
     */
    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
                    ->subject('Verify Your Email Address - SkillFundz')
                    ->view('verify_email', [
                        'user' => $this->user,
                        'verificationUrl' => $this->verificationUrl,
                        'otp' => $this->user->otp
                    ]);
    }

    /**
     * Generate verification URL
     */
    private function generateVerificationUrl(): string
    {
        return url('/api/email/verify/' . $this->user->id . '/' . sha1($this->user->email));
    }

    /**
     * Get the array representation of the notification.
     *
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'title' => 'Email Verification Required',
            'message' => 'Please verify your email address to complete your registration.',
            'action_url' => $this->verificationUrl,
            'type' => 'email_verification'
        ];
    }
}
