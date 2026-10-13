@php
    use Ruvelo\SecurityAdvisories\Ecosystem;
    use Ruvelo\SecurityAdvisories\Severity;

    $counts = $report->counts();
    $exploited = $report->exploited();
    $headline = $exploited[0] ?? null;
    $short = fn (?string $url) => $url === null ? null : preg_replace('#^https?://(www\.)?#', '', $url);
    $fix = fn ($f) => $f->fixedIn === null ? null : (str_starts_with($f->fixedIn, '>') ? 'after '.substr($f->fixedIn, 1) : $f->fixedIn);
    $date = fn ($d) => $d?->format('j M Y');
@endphp
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Laravel Security Alerts · Know when a dependency turns dangerous</title>
    <meta name="description" content="Tells your Laravel app when a package it runs becomes vulnerable, and when a known flaw starts being exploited in the wild. Packagist, OSV and CISA KEV, no keys.">
    <style>
        :root {
            --sa-bg: #ffffff;
            --sa-subtle: #f8f8fc;
            --sa-muted: #f0f0f7;
            --sa-line: #e4e4ef;
            --sa-ink: #16162a;
            --sa-text-2: #4b4b63;
            --sa-text-3: #74748b;
            --sa-accent: #3d4eff;
            --sa-accent-2: #a78bfa;
            --sa-accent-ink: #2b38d6;
            --sa-accent-soft: #eef0ff;
            --sa-on-accent: #ffffff;
            --sa-night: #11111c;
            --sa-success: #167a4a;
            --sa-success-soft: #e8f8ef;
            --sa-warning: #b26a00;
            --sa-warning-soft: #fff4e0;
            --sa-danger: #e5384f;
            --sa-danger-ink: #c41e36;
            --sa-danger-soft: #fdecef;
            --sa-radius: 8px;
            --sa-radius-lg: 14px;
            --sa-sans: "Geist", ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, sans-serif;
            --sa-mono: "Geist Mono", ui-monospace, "SF Mono", "Cascadia Code", Menlo, Consolas, monospace;
            color-scheme: light;
        }
        @media (prefers-color-scheme: dark) {
            :root {
                --sa-bg: #11111c;
                --sa-subtle: #171725;
                --sa-muted: #1f1f30;
                --sa-line: #2a2a3f;
                --sa-ink: #f1f1f8;
                --sa-text-2: #b6b6cc;
                --sa-text-3: #8787a3;
                --sa-accent: #8f9bff;
                --sa-accent-2: #c4b5fd;
                --sa-accent-ink: #b3bbff;
                --sa-accent-soft: #1e2150;
                --sa-on-accent: #0b0b1a;
                --sa-night: #0b0b14;
                --sa-success: #74d6a2;
                --sa-success-soft: #0f2b1f;
                --sa-warning: #f5b04c;
                --sa-warning-soft: #2e2210;
                --sa-danger: #ff6b80;
                --sa-danger-ink: #ff8a9b;
                --sa-danger-soft: #331520;
                color-scheme: dark;
            }
        }
        *, *::before, *::after { box-sizing: border-box; }
        body { margin: 0; background: var(--sa-bg); color: var(--sa-ink); font: 15px/1.6 var(--sa-sans); -webkit-font-smoothing: antialiased; }
        body::before { content: ""; display: block; height: 3px; background: linear-gradient(90deg, var(--sa-accent), var(--sa-accent-2)); }
        a { color: var(--sa-accent); text-decoration: none; }
        a:hover { text-decoration: underline; text-underline-offset: 3px; }
        :focus-visible { outline: 2px solid var(--sa-accent); outline-offset: 2px; border-radius: 4px; }
        code, pre { font-family: var(--sa-mono); }
        h1, h2, h3 { font-weight: 600; letter-spacing: -.02em; line-height: 1.2; }

        .demo-banner { background: var(--sa-accent); color: var(--sa-on-accent); font: 500 .875rem/1.4 var(--sa-sans); padding: .55rem 16px; text-align: center; }
        .demo-banner a { color: inherit; font-weight: 700; text-decoration: underline; text-underline-offset: 2px; }

        .sa-wrap { max-width: 72rem; margin: 0 auto; padding: 0 24px; }
        .sa-bar { display: flex; align-items: center; gap: 1rem; padding: .9rem 0; border-bottom: 1px solid var(--sa-line); }
        .sa-brand { display: inline-flex; align-items: center; gap: .6rem; font-weight: 600; letter-spacing: -.01em; color: var(--sa-ink); }
        .sa-brand:hover { text-decoration: none; }
        .sa-brand .sa-by { color: var(--sa-text-3); font-weight: 500; }
        .sa-mark { display: grid; place-items: center; width: 1.75rem; height: 1.75rem; border-radius: 7px; background: linear-gradient(135deg, var(--sa-accent), var(--sa-accent-2)); color: #fff; font-size: .85rem; font-weight: 700; box-shadow: 0 4px 12px -4px color-mix(in srgb, var(--sa-accent) 60%, transparent); }
        .sa-bar nav { margin-left: auto; display: flex; gap: 1.25rem; font-size: .9rem; }
        .sa-bar nav a { color: var(--sa-text-2); }

        .sa-hero { display: grid; grid-template-columns: minmax(0, 1.1fr) minmax(0, .9fr); gap: 3rem; align-items: center; padding: 4rem 0 3rem; position: relative; }
        .sa-hero::before { content: ""; position: absolute; inset: 0 -24px auto; height: 22rem; z-index: -1; background-image: linear-gradient(var(--sa-line) 1px, transparent 1px), linear-gradient(90deg, var(--sa-line) 1px, transparent 1px); background-size: 44px 44px; -webkit-mask: linear-gradient(to bottom, rgb(0 0 0 / .55), transparent); mask: linear-gradient(to bottom, rgb(0 0 0 / .55), transparent); }
        .sa-eyebrow { display: inline-flex; align-items: center; gap: .5rem; font-size: .8rem; font-weight: 500; color: var(--sa-accent-ink); background: var(--sa-accent-soft); border-radius: 999px; padding: .25rem .75rem; }
        .sa-hero h1 { font-size: clamp(2.3rem, 4.6vw, 3.4rem); letter-spacing: -.045em; line-height: 1.04; margin: 1.1rem 0 1rem; }
        .sa-lede { font-size: 1.1rem; color: var(--sa-text-2); margin: 0 0 1.75rem; max-width: 34rem; }
        .sa-install { display: flex; align-items: center; gap: .75rem; flex-wrap: wrap; }
        .sa-install code { background: var(--sa-muted); border-radius: var(--sa-radius); padding: .7rem 1rem; font-size: .9rem; }
        .sa-install code::before { content: "$ "; color: var(--sa-text-3); }
        .sa-btn { display: inline-flex; align-items: center; font-weight: 500; font-size: .9rem; padding: .7rem 1.05rem; border-radius: var(--sa-radius); background: var(--sa-accent); color: var(--sa-on-accent); box-shadow: 0 8px 20px -10px color-mix(in srgb, var(--sa-accent) 80%, transparent); }
        .sa-btn:hover { background: var(--sa-accent-ink); text-decoration: none; }

        .sa-card { border: 1px solid var(--sa-line); border-radius: var(--sa-radius-lg); background: var(--sa-bg); box-shadow: 0 24px 60px -32px color-mix(in srgb, var(--sa-accent) 60%, transparent); overflow: hidden; }
        .sa-card-head { display: flex; align-items: center; justify-content: space-between; gap: .5rem; padding: .75rem 1rem; background: var(--sa-subtle); border-bottom: 1px solid var(--sa-line); font-size: .8rem; color: var(--sa-text-3); }
        .sa-card-head strong { color: var(--sa-ink); font-weight: 600; }
        .sa-card-body { padding: 1.1rem 1.1rem 1.2rem; }
        .sa-alert-pkg { display: flex; align-items: baseline; gap: .5rem; flex-wrap: wrap; font: 600 1.1rem/1.3 var(--sa-mono); letter-spacing: -.01em; margin: .6rem 0 .35rem; }
        .sa-alert-pkg span { color: var(--sa-text-3); font-weight: 400; font-size: .95rem; }
        .sa-alert-title { margin: 0 0 1rem; color: var(--sa-text-2); }
        .sa-facts { display: grid; grid-template-columns: auto 1fr; gap: .4rem 1rem; margin: 0; font-size: .875rem; }
        .sa-facts dt { color: var(--sa-text-3); }
        .sa-facts dd { margin: 0; font-weight: 500; min-width: 0; overflow-wrap: anywhere; }
        .sa-facts dd.is-fix { color: var(--sa-success); }

        .sa-chip { display: inline-flex; align-items: center; gap: .35rem; font-size: .72rem; font-weight: 500; line-height: 1.5; border-radius: 999px; padding: .1rem .55rem; background: var(--sa-accent-soft); color: var(--sa-accent-ink); white-space: nowrap; }
        .sa-chip.is-exploited { background: var(--sa-danger); color: #fff; font-weight: 600; }
        .sa-chip.is-exploited::before { content: ""; width: .4rem; height: .4rem; border-radius: 50%; background: currentColor; box-shadow: 0 0 0 3px rgb(255 255 255 / .3); }
        .sa-chip.is-critical { background: var(--sa-danger-soft); color: var(--sa-danger-ink); }
        .sa-chip.is-high { background: var(--sa-warning-soft); color: var(--sa-warning); }
        .sa-chip.is-medium { background: var(--sa-accent-soft); color: var(--sa-accent-ink); }
        .sa-chip.is-low, .sa-chip.is-unknown, .sa-chip.is-quiet { background: var(--sa-muted); color: var(--sa-text-2); }

        .sa-section { padding: 3rem 0; }
        .sa-section > h2 { font-size: 1.75rem; margin: 0 0 .5rem; }
        .sa-section > p { color: var(--sa-text-2); margin: 0 0 1.5rem; max-width: 46rem; }

        .sa-summary { display: flex; flex-wrap: wrap; align-items: center; gap: .5rem; margin: 0 0 1rem; font-size: .9rem; color: var(--sa-text-2); }
        .sa-summary strong { color: var(--sa-ink); font-weight: 600; margin-right: .25rem; }
        .sa-summary .sa-checked { margin-left: auto; color: var(--sa-text-3); font-size: .8rem; }

        .sa-table { width: 100%; border-collapse: separate; border-spacing: 0; border: 1px solid var(--sa-line); border-radius: var(--sa-radius-lg); overflow: hidden; font-size: .9rem; }
        .sa-table th { text-align: left; font-weight: 500; font-size: .78rem; color: var(--sa-text-3); background: var(--sa-subtle); padding: .65rem .9rem; border-bottom: 1px solid var(--sa-line); white-space: nowrap; }
        .sa-table td { padding: .8rem .9rem; border-bottom: 1px solid var(--sa-line); vertical-align: top; }
        .sa-table tr:last-child td { border-bottom: 0; }
        .sa-table tr.is-exploited td { background: color-mix(in srgb, var(--sa-danger-soft) 70%, transparent); }
        .sa-table tr.is-exploited td:first-child { box-shadow: inset 3px 0 0 var(--sa-danger); }
        .sa-pkg { font: 500 .85rem/1.4 var(--sa-mono); white-space: nowrap; }
        .sa-tags { display: flex; gap: .3rem; margin-top: .3rem; }
        .sa-version { font: .85rem/1.4 var(--sa-mono); color: var(--sa-text-2); white-space: nowrap; }
        .sa-fix { font: 500 .85rem/1.4 var(--sa-mono); color: var(--sa-success); white-space: nowrap; }
        .sa-none { color: var(--sa-text-3); }
        .sa-advisory a { color: var(--sa-ink); font-weight: 500; }
        .sa-advisory a:hover { color: var(--sa-accent); }
        .sa-meta { display: block; color: var(--sa-text-3); font-size: .78rem; margin-top: .2rem; }
        .sa-kev { display: block; color: var(--sa-danger-ink); font-size: .78rem; font-weight: 500; margin-top: .25rem; }

        .sa-night { background: var(--sa-night); color: #f1f1f8; border-radius: 20px; padding: 3rem; margin: 1rem 0 3rem; }
        .sa-night h2 { font-size: 1.75rem; margin: 0 0 .5rem; color: #fff; }
        .sa-night > p { color: #b6b6cc; margin: 0 0 2rem; max-width: 46rem; }
        .sa-night a { color: #b3bbff; }
        .sa-night code { color: #e4e4ef; }
        .sa-term { background: #171725; border: 1px solid #2a2a3f; border-radius: var(--sa-radius-lg); overflow: hidden; }
        .sa-term-head { display: flex; align-items: center; gap: .45rem; padding: .7rem 1rem; border-bottom: 1px solid #2a2a3f; font: 500 .78rem/1 var(--sa-sans); color: #8787a3; }
        .sa-term-head i { width: .6rem; height: .6rem; border-radius: 50%; background: #2a2a3f; }
        .sa-term-head span { margin-left: .5rem; font-family: var(--sa-mono); }
        .sa-term pre { margin: 0; padding: 1.1rem 1.2rem 1.3rem; font-size: .74rem; line-height: 1.22; overflow-x: auto; color: #e4e4ef; }
        .sa-term pre .prompt { color: #8787a3; }
        .sa-term .red { color: #ff6b80; } .sa-term .green { color: #74d6a2; } .sa-term .yellow { color: #f5b04c; } .sa-term .gray { color: #8787a3; } .sa-term .blue { color: #8f9bff; } .sa-term .b { font-weight: 700; }
        .sa-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 1rem; margin-top: 1.5rem; }
        .sa-tile { border: 1px solid #2a2a3f; border-radius: var(--sa-radius-lg); padding: 1rem 1.1rem; }
        .sa-tile h3 { margin: 0 0 .35rem; font-size: .95rem; color: #fff; }
        .sa-tile p { margin: 0; color: #b6b6cc; font-size: .875rem; }
        .sa-tile code { font-size: .8rem; }

        .sa-split { display: grid; grid-template-columns: minmax(0, .8fr) minmax(0, 1.2fr); gap: 2.5rem; align-items: start; }
        .sa-split h2 { font-size: 1.75rem; margin: 0 0 .5rem; }
        .sa-split > div > p { color: var(--sa-text-2); margin: 0 0 1rem; }
        .sa-list { margin: 0 0 1.25rem; padding: 0; list-style: none; display: grid; gap: .6rem; }
        .sa-list li { display: grid; grid-template-columns: 1.4rem minmax(0, 1fr); gap: .5rem; color: var(--sa-text-2); font-size: .925rem; }
        .sa-list li::before { content: ""; width: 1.4rem; height: 1.4rem; border-radius: 50%; background: var(--sa-accent-soft) url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%233d4eff' stroke-width='3' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M6 12.5l4 4 8-9'/%3E%3C/svg%3E") center / .8rem no-repeat; }
        .sa-mail { border: 1px solid var(--sa-line); border-radius: var(--sa-radius-lg); overflow: hidden; background: var(--sa-subtle); box-shadow: 0 24px 60px -32px color-mix(in srgb, var(--sa-accent) 60%, transparent); }
        .sa-mail-head { padding: .8rem 1rem; border-bottom: 1px solid var(--sa-line); font-size: .82rem; color: var(--sa-text-3); display: grid; gap: .15rem; background: var(--sa-bg); }
        .sa-mail-head strong { color: var(--sa-ink); font-weight: 600; font-size: .9rem; }
        .sa-mail iframe { display: block; width: 100%; height: 44rem; border: 0; background: #fafafa; }

        .sa-sources { width: 100%; border-collapse: collapse; font-size: .9rem; }
        .sa-sources th { text-align: left; font-weight: 500; font-size: .78rem; color: var(--sa-text-3); padding: .6rem .9rem; border-bottom: 1px solid var(--sa-line); }
        .sa-sources td { padding: .75rem .9rem; border-bottom: 1px solid var(--sa-line); vertical-align: top; color: var(--sa-text-2); }
        .sa-sources td:first-child { color: var(--sa-ink); font-weight: 500; white-space: nowrap; }
        .sa-sources tr:last-child td { border-bottom: 0; }
        .sa-tip { background: var(--sa-accent-soft); border-radius: var(--sa-radius-lg); padding: 1rem 1.2rem; color: var(--sa-text-2); font-size: .9rem; margin-top: 1.25rem; }
        .sa-tip strong { color: var(--sa-accent-ink); }

        .sa-foot { border-top: 1px solid var(--sa-line); color: var(--sa-text-3); font-size: .85rem; padding: 1.5rem 0 3rem; display: flex; flex-wrap: wrap; justify-content: space-between; gap: .5rem; }
        .sa-foot a { color: inherit; text-decoration: underline; text-underline-offset: 2px; }

        .sa-only { padding-top: 2rem; }
        .sa-only.sa-night { margin: 2rem 0; }

        @media (max-width: 60rem) {
            .sa-hero, .sa-split { grid-template-columns: minmax(0, 1fr); gap: 2rem; }
            .sa-hero { padding-top: 2.5rem; }
            .sa-grid { grid-template-columns: minmax(0, 1fr); }
        }
        @media (max-width: 47.99rem) {
            .sa-wrap { padding: 0 16px; }
            .sa-bar nav a:not(:last-child), .sa-brand .sa-by { display: none; }
            .sa-night { padding: 1.75rem 1.1rem; border-radius: var(--sa-radius-lg); margin-inline: -4px; }
            .sa-summary .sa-checked { margin-left: 0; width: 100%; }
            .sa-table, .sa-table tbody, .sa-table tr, .sa-table td { display: block; }
            .sa-table thead { display: none; }
            .sa-table { border: 0; border-radius: 0; overflow: visible; }
            .sa-table tr { border: 1px solid var(--sa-line); border-radius: var(--sa-radius-lg); margin-bottom: .75rem; padding: .5rem 0; overflow: hidden; }
            .sa-table tr.is-exploited { border-color: var(--sa-danger); }
            .sa-table tr.is-exploited td:first-child { box-shadow: none; }
            .sa-table td { border: 0; padding: .3rem .9rem; display: grid; grid-template-columns: 5.5rem minmax(0, 1fr); gap: .5rem; }
            .sa-table td::before { content: attr(data-label); color: var(--sa-text-3); font-size: .8rem; padding-top: .1rem; }
            .sa-table td.sa-advisory { display: block; padding-top: .5rem; }
            .sa-table td.sa-advisory::before { content: none; }
            .sa-pkg { white-space: normal; overflow-wrap: anywhere; }
            .sa-mail iframe { height: 36rem; }
        }
    </style>
</head>
<body>
<div class="sa-wrap">
    @if ($only !== 'terminal')
    <header class="sa-bar">
        <a class="sa-brand" href="/laravel-security-alerts/"><span class="sa-mark">S</span>Laravel Security Alerts <span class="sa-by">by Ruvelo</span></a>
        <nav>
            <a href="{{ $repo }}#configuration">Configuration</a>
            <a href="{{ $repo }}#for-developers">Developer guide</a>
            <a href="{{ $repo }}">GitHub</a>
        </nav>
    </header>
    @endif

    @if ($only === null)
    <section class="sa-hero">
        <div>
            <span class="sa-eyebrow">Exploited now, patch today</span>
            <h1>Know when a dependency turns dangerous.</h1>
            <p class="sa-lede">A daily check of the exact Composer and npm versions your Laravel app runs. It tells you once when one becomes vulnerable, and again, loudly, when attackers start exploiting it. Free sources, no keys, no configuration to start.</p>
            <div class="sa-install">
                <code>composer require ruvelo/laravel-security-alerts</code>
                <a class="sa-btn" href="{{ $repo }}#readme">Read the docs</a>
            </div>
        </div>

        @if ($headline)
        <div class="sa-card">
            <div class="sa-card-head"><strong>Halyard · this morning</strong><span>{{ now()->format('j M, H:i') }}</span></div>
            <div class="sa-card-body">
                <span class="sa-chip is-exploited">Exploited in the wild</span>
                <div class="sa-alert-pkg">{{ $headline->package }} <span>{{ $headline->installed }}</span></div>
                <p class="sa-alert-title">{{ $headline->title }}</p>
                <dl class="sa-facts">
                    <dt>Severity</dt><dd>{{ $headline->severity->label() }}@if ($headline->cve) · {{ $headline->cve }}@endif</dd>
                    <dt>In CISA KEV</dt><dd>since {{ $date($headline->exploited?->dateAdded) }}</dd>
                    <dt>Fix</dt><dd class="is-fix">Update to {{ $headline->fixedIn }} or later</dd>
                </dl>
            </div>
        </div>
        @endif
    </section>
    @endif

    @if ($only === null || $only === 'report')
    <section class="sa-section @if ($only) sa-only @endif" id="report">
        <h2>Halyard’s report</h2>
        <p>What the package found in the lockfiles of Halyard, a made-up billing app: {{ $report->packageCount(Ecosystem::Composer) }} Composer and {{ $report->packageCount(Ecosystem::Npm) }} npm packages, checked against real advisories. Exploited flaws come first, then by severity.</p>

        <div class="sa-summary">
            <strong>{{ count($report->findings) }} vulnerabilities</strong>
            @foreach ($counts as $kind => $count)
                <span class="sa-chip is-{{ $kind }}">{{ $count }} {{ $kind === 'exploited' ? 'exploited in the wild' : ($kind === 'not_rated' ? 'not rated' : $kind) }}</span>
            @endforeach
            <span class="sa-checked">Checked {{ now()->format('j F Y, H:i') }}, {{ Ruvelo\SecurityAlerts\SecurityAlerts::sourceLabel($report, true) }}</span>
        </div>

        <table class="sa-table">
            <thead>
                <tr>
                    <th scope="col">Severity</th>
                    <th scope="col">Package</th>
                    <th scope="col">Installed</th>
                    <th scope="col">Fixed in</th>
                    <th scope="col">Advisory</th>
                </tr>
            </thead>
            <tbody>
                @foreach ($report->findings as $f)
                    <tr class="{{ $f->isExploited() ? 'is-exploited' : '' }}">
                        <td data-label="Severity"><div>
                            @if ($f->isExploited())
                                <span class="sa-chip is-exploited">Exploited</span>
                            @else
                                <span class="sa-chip is-{{ $f->severity->value }}">{{ $f->severity->label() }}</span>
                            @endif
                        </div></td>
                        <td data-label="Package"><div>
                            <span class="sa-pkg">{{ $f->package }}</span>
                            @if ($f->ecosystem === Ecosystem::Npm || $f->isDev)
                                <div class="sa-tags">
                                    @if ($f->ecosystem === Ecosystem::Npm)<span class="sa-chip is-quiet">npm</span>@endif
                                    @if ($f->isDev)<span class="sa-chip is-quiet">dev</span>@endif
                                </div>
                            @endif
                        </div></td>
                        <td data-label="Installed"><div><span class="sa-version">{{ $f->installed }}</span></div></td>
                        <td data-label="Fixed in"><div>@if ($fix($f))<span class="sa-fix">{{ $fix($f) }}</span>@else<span class="sa-none">–</span>@endif</div></td>
                        <td class="sa-advisory">
                            @if ($f->link)<a href="{{ $f->link }}">{{ $f->title }}</a>@else{{ $f->title }}@endif
                            <span class="sa-meta">{{ collect([$f->cve, $short($f->link)])->filter()->implode(' · ') }}</span>
                            @if ($f->exploited)
                                <span class="sa-kev">In CISA’s catalogue since {{ $date($f->exploited->dateAdded) }}@if ($f->exploited->dueDate); US agencies had until {{ $date($f->exploited->dueDate) }} to patch @endif</span>
                            @endif
                        </td>
                    </tr>
                @endforeach
            </tbody>
        </table>
    </section>
    @endif

    @if ($only === null || $only === 'terminal')
    <section class="sa-night @if ($only) sa-only @endif" id="terminal">
        <h2>In your terminal, and in CI</h2>
        <p>The same report from <code>php artisan security-alerts:check</code>, rendered by the real command when this page was built. Add <code>--fail-on=exploited</code> to fail a pipeline, or <code>--json</code> to feed something else.</p>

        <div class="sa-term">
            <div class="sa-term-head"><i></i><i></i><i></i><span>halyard — zsh</span></div>
<pre><span class="prompt">$</span> php artisan security-alerts:check
{!! $terminal !!}</pre>
        </div>

        @if ($only === null)
        <div class="sa-grid">
            <div class="sa-tile">
                <h3>Daily, on its own</h3>
                <p>The check is scheduled for you at 07:00. Your scheduler just has to be running.</p>
            </div>
            <div class="sa-tile">
                <h3>Once per finding</h3>
                <p>Seen findings live in one small table, so a <code>cache:clear</code> never re-sends old alerts.</p>
            </div>
            <div class="sa-tile">
                <h3>Exit codes for CI</h3>
                <p><code>--fail-on=exploited|critical|high|medium|any</code> exits 1; an incomplete check exits 2.</p>
            </div>
        </div>
        @endif
    </section>
    @endif

    @if ($only === null)
    <section class="sa-section sa-split" id="mail">
        <div>
            <h2>The alert</h2>
            <p>One email for everything new, exploited first, through your own mailer and theme. Slack gets the same by webhook, and your own notifiables through any channel.</p>
            <ul class="sa-list">
                <li>Sent once per finding, and once more if it starts being exploited.</li>
                <li>Says what to update to, when CISA listed it and by when US agencies had to patch.</li>
                <li>Quiet otherwise: no daily “all clear”, unless you turn on the weekly digest.</li>
            </ul>
            <p>Want to react in code? <code>VulnerabilityFound</code>, <code>VulnerabilityExploited</code> and <code>VulnerabilityResolved</code> are events.</p>
        </div>
        <div class="sa-mail">
            <div class="sa-mail-head"><strong>{{ $mailSubject }}</strong><span>To maya@halyard.test, tom@halyard.test</span></div>
            <iframe src="/laravel-security-alerts/mail/" title="The alert email, as sent" loading="lazy"></iframe>
        </div>
    </section>

    <section class="sa-section" id="sources">
        <h2>Where it looks, and what it sends</h2>
        <p>No account or key. By default the check asks <a href="https://valtry.co.uk/docs/api/advisories">Valtry’s Advisory API</a>, which serves the same Packagist, OSV and CISA data from one signed answer, and uses the public feeds below whenever Valtry can’t answer. Set <code>SECURITY_ALERTS_SOURCE=public</code> to never contact it. Answers are cached, so running the command twice is instant.</p>
        <table class="sa-sources">
            <thead><tr><th scope="col">Source</th><th scope="col">For</th><th scope="col">What leaves your server</th></tr></thead>
            <tbody>
                <tr><td>Valtry Advisory API (default)</td><td>Composer and npm packages, and which advisories are exploited</td><td>Package names only, never versions; answers are signed and checked</td></tr>
                <tr><td>Packagist (fallback, or <code>public</code>)</td><td>Composer packages: the advisories <code>composer audit</code> reads</td><td>Package names, in one POST</td></tr>
                <tr><td>OSV.dev (fallback, or <code>public</code>)</td><td>npm packages from <code>package-lock.json</code>, if you have one</td><td>Package names and versions, like <code>npm audit</code></td></tr>
                <tr><td>CISA KEV (fallback, or <code>public</code>)</td><td>Which CVEs are being exploited in the wild</td><td>Nothing: the catalogue is downloaded whole</td></tr>
            </tbody>
        </table>
        <div class="sa-tip"><strong>Nothing about your app</strong> is sent: no URL, no environment, no code. Versions never leave your server on the default path; on the public feeds, npm versions go to OSV as with <code>npm audit</code>. This demo was built from recorded answers of the public feeds.</div>
    </section>

    <footer class="sa-foot">
        <span>Built by <a href="https://github.com/francoisbultez">François Bultez</a> at <a href="https://github.com/Ruvelo">Ruvelo</a>. MIT licence.</span>
        <span>Advisories from <a href="https://packagist.org">Packagist</a>, <a href="https://osv.dev">OSV.dev</a> and <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog">CISA</a>.</span>
    </footer>
    @endif
</div>
</body>
</html>
