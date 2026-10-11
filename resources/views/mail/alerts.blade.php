@php
    $fix = fn ($alert) => $alert->fixed_in === null
        ? 'no fixed version listed yet'
        : (str_starts_with($alert->fixed_in, '>') ? 'fixed after '.$md(substr($alert->fixed_in, 1)) : 'update to '.$md($alert->fixed_in).' or later');
    $advisory = fn ($alert) => $md($alert->title).($alert->cve ? ' · '.$alert->cve : '');
    // Written raw, so only http(s) URLs, with anything that could end the Markdown link encoded.
    $link = fn ($alert) => is_string($alert->link) && preg_match('#^https?://#i', $alert->link) === 1
        ? ' · [Advisory]('.str_replace([' ', '(', ')', '<', '>', '"', "'", '\\'], ['%20', '%28', '%29', '%3C', '%3E', '%22', '%27', '%5C'], $alert->link).')'
        : '';
@endphp
<x-mail::message>
# {{ $heading }}

{{ $intro }}

@foreach ($exploited as $alert)
<x-mail::panel>
**{{ $md($alert->package) }} {{ $md($alert->version) }}** · {{ $alert->severity->label() }} · exploited in the wild<br>
{{ $advisory($alert) }}{!! $link($alert) !!}<br>
In CISA's catalogue since {{ $alert->exploited_at?->format('j F Y') }}{{ $alert->kev_due_date ? '; US agencies must patch by '.$alert->kev_due_date->format('j F Y') : '' }}. **{{ ucfirst($fix($alert)) }}.**
</x-mail::panel>

@endforeach
@if ($others->isNotEmpty())
@if ($exploited->isNotEmpty())
## {{ $others->count() === 1 ? 'Also new' : 'Also' }}

@endif
@foreach ($others as $alert)
- **{{ $md($alert->package) }} {{ $md($alert->version) }}** · {{ $alert->severity->label() }} · {{ $fix($alert) }}<br>{{ $advisory($alert) }}{!! $link($alert) !!}
@endforeach

@endif
{{ $footer }}
</x-mail::message>
