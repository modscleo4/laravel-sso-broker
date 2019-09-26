<?php

namespace App\Models;

class Permission extends \Spatie\Permission\Models\Permission
{
    public function __construct(array $attributes = [])
    {
        parent::__construct($attributes);
        $this->connection = config('database.default');
    }
}
