<x-pulse::card :cols="$cols" :rows="$rows" :class="$class">
    <x-pulse::card-header
        name="Security alerts"
        details="{{ $lastCheck ? 'checked '.$lastCheck['checked_at']->diffForHumans() : 'not checked yet' }}"
    >
        <x-slot:icon>
            <x-pulse::icons.information-circle />
        </x-slot:icon>
    </x-pulse::card-header>

    <x-pulse::scroll :expand="$expand">
        @if ($alerts->isEmpty())
            <x-pulse::no-results />
        @else
            <x-pulse::table>
                <colgroup>
                    <col width="100%" />
                    <col width="0%" />
                    <col width="0%" />
                </colgroup>
                <x-pulse::thead>
                    <tr>
                        <x-pulse::th>Package and advisory</x-pulse::th>
                        <x-pulse::th class="text-right">Fixed in</x-pulse::th>
                        <x-pulse::th class="text-right">Severity</x-pulse::th>
                    </tr>
                </x-pulse::thead>
                <tbody>
                    @foreach ($alerts->take(100) as $alert)
                        <tr wire:key="{{ $alert->key }}-spacer" class="h-2 first:h-0"></tr>
                        <tr wire:key="{{ $alert->key }}-row">
                            <x-pulse::td class="max-w-[1px]">
                                <code class="block text-xs text-gray-900 dark:text-gray-100 truncate" title="{{ $alert->package }} {{ $alert->version }}">
                                    {{ $alert->package }} {{ $alert->version }}
                                </code>
                                <p class="mt-1 text-xs text-gray-500 dark:text-gray-400 truncate" title="{{ $alert->title }}">
                                    @if ($alert->link)<a href="{{ $alert->link }}" target="_blank" rel="noopener noreferrer" class="security-alerts-link">{{ $alert->title }}</a>@else{{ $alert->title }}@endif
                                </p>
                            </x-pulse::td>
                            <x-pulse::td numeric class="text-gray-700 dark:text-gray-300 font-bold">
                                {{ $alert->fixed_in ?? '–' }}
                            </x-pulse::td>
                            <x-pulse::td numeric class="font-bold {{ $alert->isExploited() ? 'security-alerts-exploited' : 'text-gray-700 dark:text-gray-300' }}">
                                <span title="{{ $alert->isExploited() ? 'In CISA KEV since '.$alert->exploited_at?->toDateString() : '' }}">{{ $alert->isExploited() ? 'Exploited' : $alert->severity->label() }}</span>
                            </x-pulse::td>
                        </tr>
                    @endforeach
                </tbody>
            </x-pulse::table>
        @endif
    </x-pulse::scroll>
</x-pulse::card>
