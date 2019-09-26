<?php

namespace App\Models;

class DatabaseNotification extends \Illuminate\Notifications\DatabaseNotification
{
    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);
        $this->connection = config('database.default');
    }
}
