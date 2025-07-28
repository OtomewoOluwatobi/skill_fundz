<?php

namespace App\Notifications;

use App\Models\User;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Notifications\Messages\MailMessage;
use Illuminate\Notifications\Notification;

class NewUserRegistered extends Notification implements ShouldQueue
{
    use Queueable;

    public $user;

    /**
     * Create a new notification instance.
     */
    public function __construct(User $user)
    {
        $this->user = $user;
    }

    /**
     * Get the notification's delivery channels.
     *
     * @return array<int, string>
     */
    public function via(object $notifiable): array
    {
        return ['mail', 'database'];
    }

    /**
     * Get the mail representation of the notification.
     */
    public function toMail(object $notifiable): MailMessage
    {
        return (new MailMessage)
                    ->subject('New User Registration - SkillFundz')
                    ->greeting('Hello Admin!')
                    ->line('A new user has registered on SkillFundz platform.')
                    ->line('**User Details:**')
                    ->line('Name: ' . $this->user->first_name . ' ' . $this->user->last_name)
                    ->line('Email: ' . $this->user->email)
                    ->line('Phone: ' . $this->user->phone_number)
                    ->line('Role: ' . ucfirst($this->user->getRoleNames()->first()))
                    ->line('Registration Date: ' . $this->user->created_at->format('M d, Y h:i A'))
                    ->action('View User', url('/admin/users/' . $this->user->id))
                    ->line('Please review the new user registration.');
    }

    /**
     * Get the array representation of the notification for database storage.
     *
     * @return array<string, mixed>
     */
    public function toArray(object $notifiable): array
    {
        return [
            'title' => 'New User Registration',
            'message' => $this->user->first_name . ' ' . $this->user->last_name . ' has registered as a ' . ucfirst($this->user->getRoleNames()->first()),
            'user_id' => $this->user->id,
            'user_name' => $this->user->first_name . ' ' . $this->user->last_name,
            'user_email' => $this->user->email,
            'user_role' => $this->user->getRoleNames()->first(),
            'action_url' => url('/admin/users/' . $this->user->id),
            'type' => 'user_registration'
        ];
    }
}
