<?php
// SPDX-FileCopyrightText: 2026 The Nikasha Authors
// SPDX-License-Identifier: Apache-2.0

namespace App\Util;

function slugify(string $s): string
{
    return strtolower(trim($s));
}

interface Renderer
{
    public function render(array $data): string;
}

class Page implements Renderer
{
    public function __construct(private string $title)
    {
    }

    public function render(array $data): string
    {
        $slug = slugify($this->title);
        return $this->wrap($slug) . Page::footer();
    }

    private function wrap(string $body): string
    {
        return \sprintf('<div>%s</div>', $body);
    }

    public static function footer(): string
    {
        return '';
    }
}

$page = new Page('Home');
echo $page?->render([]);
