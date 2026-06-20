<?php

/**
 * Minimal coverage-floor gate for CI.
 *
 * Usage: php tests/coverage-floor.php <clover.xml> <minPercent>
 * Exits non-zero when line coverage is below the floor.
 */

$file = $argv[1] ?? 'coverage/clover.xml';
$floor = (float) ($argv[2] ?? 60);

if (! is_file($file)) {
    fwrite(STDERR, "Coverage report not found: {$file}\n");
    exit(1);
}

$xml = simplexml_load_file($file);
if ($xml === false) {
    fwrite(STDERR, "Could not parse coverage report: {$file}\n");
    exit(1);
}

$metrics = $xml->project->metrics ?? null;
if ($metrics === null) {
    fwrite(STDERR, "No metrics in coverage report.\n");
    exit(1);
}

$statements = (int) $metrics['statements'];
$covered = (int) $metrics['coveredstatements'];
$percent = $statements > 0 ? ($covered / $statements) * 100 : 0.0;

printf("Line coverage: %.2f%% (floor %.2f%%)\n", $percent, $floor);

if ($percent + 0.0001 < $floor) {
    fwrite(STDERR, "Coverage below floor.\n");
    exit(1);
}

exit(0);
