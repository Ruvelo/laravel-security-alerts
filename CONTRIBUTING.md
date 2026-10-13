# Contributing to Laravel Security Alerts

Thanks for helping! Wrong matches, docs fixes and features are all welcome.

## Before you start

- **A finding that's wrong, or one that's missing:** [open an issue](https://github.com/Ruvelo/laravel-security-alerts/issues/new/choose) with the package, the installed version from your lockfile, and the advisory (its `PKSA-`, `GHSA-` or CVE ID). If the advisory itself is wrong, it's best fixed upstream, in the [GitHub Advisory Database](https://github.com/github/advisory-database) or [FriendsOfPHP/security-advisories](https://github.com/FriendsOfPHP/security-advisories).
- **Features:** open an issue first if it's more than a small change, so we can agree on the shape before you spend time on it.
- **Security issues:** don't open an issue. See [SECURITY.md](https://github.com/Ruvelo/.github/blob/main/SECURITY.md).

## Setup

You need PHP 8.3+ and Composer. Tests use an in-memory SQLite database and never touch the network.

```bash
git clone https://github.com/<you>/laravel-security-alerts && cd laravel-security-alerts
composer install
composer check
```

`composer check` runs exactly what CI runs:

| Command | What it does |
|---|---|
| `composer test` | PHPUnit, through Orchestra Testbench |
| `composer lint` | Code style check (Laravel Pint) |
| `composer format` | Fix code style |
| `composer analyse` | Static analysis (PHPStan level 8 with Larastan) |
| `composer demo` | Build the static demo into `build/` |

## The fixtures

`tests/fixtures` holds real answers from Packagist, OSV and CISA, recorded for the lockfiles of Halyard, the made-up app in the demo. `Http::preventStrayRequests()` is on in every test, and the package's PSR-18 client is bound to one that sends through the Http facade: a test that reaches the network fails. The Valtry path is tested with answers signed by a key made for the test.

- To test a new case, change the lockfile in the test (`$this->lockfile('composer', [...])`) or one feed's answer (`$this->feed('www.cisa.gov/*', Http::response([...]))`) rather than the shared fixtures.
- If you refresh the fixtures, record real responses, keep the KEV catalogue trimmed, and update the counts the tests and README expect.

## Making a change

1. Branch from `main`.
2. Write a test that fails without your change. Feature tests live in `tests/Feature`, unit tests in `tests/Unit`.
3. Keep the public API stable: `SecurityAlerts`, `Report`, `Finding`, the enums, the model and its factory, the events, the command's options and exit codes, config keys and the JSON shape. If you must change one, say so in the PR.
4. Keep it quiet: no change should make the package send an alert it already sent.
5. Run `composer format` and `composer check`.
6. Add a line under **Unreleased** in [CHANGELOG.md](CHANGELOG.md).
7. Open the pull request.

## Where things live

```
src/SecurityAlerts.php        The API: scan(), check(), open(), lastCheck(), notifyUsing()
src/Scanner.php               Lockfiles in, Report out
src/Lockfiles/                composer.lock and package-lock.json readers
src/Scanner.php                wires ruvelo/security-advisories to the config, Guzzle and the cache
src/Versions.php              Constraint matching and fixed versions
src/Recorder.php              The one place alerts are written, and where events fire
src/Notifier.php              Who gets told, and marking alerts as sent
src/Notifications/            The alert and the weekly digest (mail and Slack)
src/Console/                  security-alerts:check and security-alerts:digest
src/Integrations/             Pulse card and Health check (optional)
src/Mcp/                      The MCP server and tool (optional)
resources/boost/guidelines/   Laravel Boost guidelines for coding agents; keep them in step with the API
demo/                         The demo page (deployed to GitHub Pages), its build script and screenshots
```

## Style

- `declare(strict_types=1)` everywhere, typed properties and return types.
- No `@phpstan-ignore` or baseline entries: fix the cause.
- Comments explain *why*, not *what*.
- Optional integrations stay optional: in `suggest`, guarded with `class_exists()`, and in `require-dev` for the tests.
- The demo follows the [Ruvelo house style](https://github.com/Ruvelo/.github/blob/main/BRAND.md): CSS variables, no build step, light and dark.

By contributing you agree that your work is released under the [MIT license](LICENSE) and that you'll follow the [code of conduct](https://github.com/Ruvelo/.github/blob/main/CODE_OF_CONDUCT.md).
