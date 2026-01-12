<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class IdsSignature extends Model
{
    protected $fillable = [
        'name',
        'description',
        'pattern',
        'category',
        'severity',
        'match_uri',
        'match_user_agent',
        'match_referer',
        'enabled',
    ];

    protected function casts(): array
    {
        return [
            'match_uri' => 'boolean',
            'match_user_agent' => 'boolean',
            'match_referer' => 'boolean',
            'enabled' => 'boolean',
        ];
    }
}
