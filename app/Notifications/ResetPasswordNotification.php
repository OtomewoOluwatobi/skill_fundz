<?php

namespace App\Notifications;

use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Carbon;

class ResetPasswordNotification extends Notification
{
    use Queueable;

    protected $token;

    /**
     * Create a new notification instance.
     */
    public function __construct($token)
    {
        $this->token = $token;
    }

    /**
     * Get the notification's delivery channels.
     *
     * @return array<int, string>
     */
    public function via($notifiable): array
    {
        return ['mail'];
    }

    /**
     * Get the mail representation of the notification.
     */
    public function toMail($notifiable): MailMessage
    {
        $resetUrl = url(env('FRONTEND_URL', 'http://newapp.test') . '/reset-password?token=' . $this->token . '&email=' . $notifiable->getEmailForPasswordReset());

        return (new MailMessage)
            ->subject('Reset Password - SkillFundz')
            ->view('emails.reset-password', [
            'user' => $notifiable,
            'resetUrl' => $resetUrl,
            'token' => $this->token
            ]);
    }
}
