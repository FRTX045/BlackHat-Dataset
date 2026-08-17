<?php
/**
 * Deterministic generation of the site's stylesheets and scripts.
 *
 * These exist because of a defect found by reading the log rather than by
 * reading a statistic. The application shipped 1-2 KB stylesheets and a
 * 990-byte "bundle", which Apache faithfully recorded as 602 and 574 bytes on
 * the wire. Every aggregate check passed; the dataset was useless for
 * anything that reads %b, which is most of what %b is used for --
 * exfiltration volume, response-size anomaly detection, cache analysis.
 *
 * Real numbers, for reference. A production e-commerce origin serves roughly
 * 20-80 KB of CSS and 100-400 KB of JavaScript uncompressed, which lands
 * somewhere near 8-40 KB and 30-120 KB once gzip has been applied. mod_deflate
 * is enabled here, so what the log records is the compressed figure and the
 * files on disk have to be correspondingly larger.
 *
 * **These are generated, and they are genuine CSS and JavaScript.** Not
 * padding: the output parses, the selectors are real, the functions run. That
 * matters for two reasons. A browser has to be able to apply the stylesheet
 * and execute the script, or the headless-browser personas stop behaving like
 * browsers. And a compressed byte count only means anything if the thing
 * compressed has the redundancy real code has -- random padding compresses
 * quite differently from a utility-class stylesheet, and the ratio itself is
 * something a consumer might reasonably look at.
 *
 * Deliberately independent of the run seed. Static assets are the same file
 * for every visitor and every build; only the catalogue varies by seed.
 */

const CSS_BREAKPOINTS = ['sm' => 640, 'md' => 768, 'lg' => 1024, 'xl' => 1280];

const CSS_PALETTE = [
    'ink' => '#12181f', 'slate' => '#3d4a5c', 'mist' => '#8b98a9',
    'paper' => '#f7f8fa', 'white' => '#ffffff', 'brand' => '#1a2a3a',
    'brand-dark' => '#0e1a26', 'accent' => '#c2571f', 'accent-soft' => '#f2d8c6',
    'ok' => '#1f7a4d', 'warn' => '#b8860b', 'bad' => '#a3231f',
];

const CSS_SPACING = [0, 2, 4, 6, 8, 12, 16, 20, 24, 32, 40, 48, 64, 80, 96];

/** Design tokens, as custom properties. Every real design system has these. */
function css_tokens(): string
{
    $out = ":root {\n";
    foreach (CSS_PALETTE as $name => $hex) {
        $out .= "  --c-$name: $hex;\n";
    }
    foreach (CSS_SPACING as $n) {
        $out .= "  --s-$n: {$n}px;\n";
    }
    foreach ([12, 13, 14, 16, 18, 20, 24, 30, 36, 48, 60] as $n) {
        $out .= "  --t-$n: {$n}px;\n";
    }
    foreach (['xs' => 2, 'sm' => 4, 'md' => 8, 'lg' => 14, 'pill' => 999] as $k => $v) {
        $out .= "  --r-$k: {$v}px;\n";
    }
    $out .= "  --font-body: 'Inter', -apple-system, BlinkMacSystemFont, "
          . "'Segoe UI', Roboto, Helvetica, Arial, sans-serif;\n";
    $out .= "  --font-mono: ui-monospace, SFMono-Regular, Menlo, monospace;\n";
    foreach (['sm' => '0 1px 2px rgba(18,24,31,.08)',
              'md' => '0 2px 8px rgba(18,24,31,.10)',
              'lg' => '0 8px 24px rgba(18,24,31,.14)'] as $k => $v) {
        $out .= "  --shadow-$k: $v;\n";
    }
    return $out . "}\n\n";
}

/** Utility classes, generated across the breakpoints, as a real framework does. */
function css_utilities(): string
{
    $rules = [];
    foreach (CSS_SPACING as $n) {
        foreach (['m' => 'margin', 'p' => 'padding'] as $short => $prop) {
            $rules[".$short-$n"] = "$prop: var(--s-$n)";
            $rules[".$short" . "t-$n"] = "$prop-top: var(--s-$n)";
            $rules[".$short" . "r-$n"] = "$prop-right: var(--s-$n)";
            $rules[".$short" . "b-$n"] = "$prop-bottom: var(--s-$n)";
            $rules[".$short" . "l-$n"] = "$prop-left: var(--s-$n)";
            $rules[".$short" . "x-$n"] =
                "$prop-left: var(--s-$n); $prop-right: var(--s-$n)";
            $rules[".$short" . "y-$n"] =
                "$prop-top: var(--s-$n); $prop-bottom: var(--s-$n)";
        }
        $rules[".gap-$n"] = "gap: var(--s-$n)";
    }
    foreach (CSS_PALETTE as $name => $_) {
        $rules[".text-$name"] = "color: var(--c-$name)";
        $rules[".bg-$name"] = "background-color: var(--c-$name)";
        $rules[".border-$name"] = "border-color: var(--c-$name)";
    }
    foreach ([12, 13, 14, 16, 18, 20, 24, 30, 36, 48, 60] as $n) {
        $rules[".fs-$n"] = "font-size: var(--t-$n)";
    }
    foreach ([300, 400, 500, 600, 700, 800] as $w) {
        $rules[".fw-$w"] = "font-weight: $w";
    }
    foreach (['flex', 'inline-flex', 'block', 'inline-block', 'grid',
              'inline-grid', 'none', 'contents'] as $d) {
        $rules[".d-$d"] = "display: $d";
    }
    foreach (['row', 'row-reverse', 'column', 'column-reverse'] as $d) {
        $rules[".fd-$d"] = "flex-direction: $d";
    }
    foreach (['flex-start', 'flex-end', 'center', 'space-between',
              'space-around', 'stretch', 'baseline'] as $a) {
        $rules[".jc-$a"] = "justify-content: $a";
        $rules[".ai-$a"] = "align-items: $a";
    }
    foreach (range(1, 12) as $n) {
        $rules[".col-$n"] = "grid-column: span $n / span $n";
        $rules[".cols-$n"] = "grid-template-columns: repeat($n, minmax(0, 1fr))";
    }
    foreach (['static', 'relative', 'absolute', 'fixed', 'sticky'] as $p) {
        $rules[".pos-$p"] = "position: $p";
    }
    foreach (['auto', 'hidden', 'scroll', 'visible', 'clip'] as $o) {
        $rules[".ov-$o"] = "overflow: $o";
        $rules[".ovx-$o"] = "overflow-x: $o";
        $rules[".ovy-$o"] = "overflow-y: $o";
    }
    foreach (['left', 'right', 'center', 'justify'] as $t) {
        $rules[".ta-$t"] = "text-align: $t";
    }
    foreach (['xs' => 2, 'sm' => 4, 'md' => 8, 'lg' => 14, 'pill' => 999] as $k => $_) {
        $rules[".rounded-$k"] = "border-radius: var(--r-$k)";
    }
    foreach (['sm', 'md', 'lg'] as $s) {
        $rules[".shadow-$s"] = "box-shadow: var(--shadow-$s)";
    }

    $out = "/* Utilities */\n";
    foreach ($rules as $selector => $body) {
        $out .= "$selector { $body; }\n";
    }

    // The same set again per breakpoint, which is where a real utility
    // stylesheet gets most of its weight.
    foreach (CSS_BREAKPOINTS as $name => $px) {
        $out .= "\n@media (min-width: {$px}px) {\n";
        foreach ($rules as $selector => $body) {
            $out .= "  " . str_replace('.', ".$name\\:", $selector)
                  . " { $body; }\n";
        }
        $out .= "}\n";
    }
    return $out;
}

/** Component blocks: the part of a stylesheet somebody actually wrote. */
function css_components(): string
{
    $components = [
        'masthead' => ['display: flex', 'align-items: center',
                       'gap: var(--s-24)', 'padding: var(--s-16) var(--s-24)',
                       'background: var(--c-brand)', 'color: var(--c-white)',
                       'box-shadow: var(--shadow-sm)'],
        'brand' => ['display: inline-flex', 'align-items: center',
                    'flex: 0 0 auto', 'text-decoration: none'],
        'search' => ['display: flex', 'flex: 1 1 auto', 'max-width: 640px',
                     'gap: var(--s-4)'],
        'categories' => ['display: flex', 'flex-wrap: wrap',
                         'gap: var(--s-8)', 'padding: var(--s-12) var(--s-24)',
                         'border-bottom: 1px solid var(--c-mist)'],
        'grid' => ['display: grid', 'gap: var(--s-24)',
                   'grid-template-columns: repeat(auto-fill, minmax(220px, 1fr))',
                   'padding: var(--s-24)'],
        'card' => ['display: flex', 'flex-direction: column',
                   'background: var(--c-white)', 'border-radius: var(--r-md)',
                   'box-shadow: var(--shadow-sm)', 'overflow: hidden',
                   'transition: box-shadow .18s ease, transform .18s ease'],
        'price' => ['font-weight: 700', 'font-size: var(--t-18)',
                    'color: var(--c-ink)'],
        'badge' => ['display: inline-block', 'padding: 2px 8px',
                    'border-radius: var(--r-pill)', 'font-size: var(--t-12)',
                    'font-weight: 600', 'text-transform: uppercase',
                    'letter-spacing: .04em'],
        'breadcrumbs' => ['display: flex', 'flex-wrap: wrap',
                          'gap: var(--s-6)', 'padding: var(--s-12) var(--s-24)',
                          'font-size: var(--t-13)', 'color: var(--c-slate)'],
        'pagination' => ['display: flex', 'gap: var(--s-4)',
                         'justify-content: center', 'padding: var(--s-24)'],
        'field' => ['display: flex', 'flex-direction: column',
                    'gap: var(--s-6)', 'margin-bottom: var(--s-16)'],
        'notice' => ['padding: var(--s-12) var(--s-16)',
                     'border-left: 3px solid var(--c-accent)',
                     'background: var(--c-accent-soft)',
                     'border-radius: var(--r-sm)'],
        'table' => ['width: 100%', 'border-collapse: collapse',
                    'font-size: var(--t-14)'],
        'footer' => ['display: grid', 'gap: var(--s-32)',
                     'grid-template-columns: repeat(auto-fit, minmax(180px, 1fr))',
                     'padding: var(--s-48) var(--s-24)',
                     'background: var(--c-brand-dark)', 'color: var(--c-paper)'],
        'drawer' => ['position: fixed', 'inset: 0 0 0 auto', 'width: 380px',
                     'max-width: 100vw', 'background: var(--c-white)',
                     'box-shadow: var(--shadow-lg)',
                     'transform: translateX(100%)',
                     'transition: transform .22s ease'],
        'autocomplete' => ['position: absolute', 'z-index: 40', 'left: 0',
                           'right: 0', 'background: var(--c-white)',
                           'border-radius: var(--r-sm)',
                           'box-shadow: var(--shadow-md)',
                           'max-height: 380px', 'overflow-y: auto'],
        'cookie-bar' => ['position: fixed', 'left: 0', 'right: 0',
                         'bottom: 0', 'display: flex', 'gap: var(--s-16)',
                         'align-items: center', 'padding: var(--s-16)',
                         'background: var(--c-ink)', 'color: var(--c-paper)'],
        'newsletter' => ['display: flex', 'gap: var(--s-8)',
                         'padding: var(--s-24)', 'background: var(--c-paper)'],
    ];

    $out = "\n/* Components */\n";
    foreach ($components as $name => $decls) {
        $out .= ".$name {\n";
        foreach ($decls as $d) {
            $out .= "  $d;\n";
        }
        $out .= "}\n";
        // The states and children a real component block carries.
        $out .= ".$name:hover { box-shadow: var(--shadow-md); }\n";
        $out .= ".$name:focus-within { outline: 2px solid var(--c-accent); "
              . "outline-offset: 2px; }\n";
        $out .= ".$name > * + * { margin-top: 0; }\n";
        $out .= ".$name a { color: inherit; text-decoration: none; }\n";
        $out .= ".$name a:hover { text-decoration: underline; }\n";
        $out .= ".$name.is-active { border-color: var(--c-accent); }\n";
        $out .= ".$name.is-disabled { opacity: .55; pointer-events: none; }\n";
        $out .= "@media (max-width: 640px) { .$name { padding: var(--s-12); } }\n";
    }
    return $out;
}

function css_reset(): string
{
    return <<<'CSS'
/* Reset */
*, *::before, *::after { box-sizing: border-box; }
html { -webkit-text-size-adjust: 100%; text-size-adjust: 100%; }
body {
  margin: 0;
  font-family: var(--font-body);
  font-size: var(--t-16);
  line-height: 1.55;
  color: var(--c-ink);
  background: var(--c-paper);
}
h1, h2, h3, h4, h5, h6 { margin: 0 0 var(--s-12); line-height: 1.22; }
h1 { font-size: var(--t-36); font-weight: 700; }
h2 { font-size: var(--t-24); font-weight: 600; }
h3 { font-size: var(--t-18); font-weight: 600; }
p { margin: 0 0 var(--s-12); }
a { color: var(--c-brand); }
img, svg, video { max-width: 100%; height: auto; display: block; }
button, input, select, textarea { font: inherit; color: inherit; }
button { cursor: pointer; border: 0; background: none; }
ul, ol { margin: 0; padding-left: var(--s-20); }
table { border-collapse: collapse; }
th, td { text-align: left; padding: var(--s-8); border-bottom: 1px solid var(--c-mist); }
code, pre { font-family: var(--font-mono); font-size: var(--t-13); }
:focus-visible { outline: 2px solid var(--c-accent); outline-offset: 2px; }
[hidden] { display: none !important; }
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { animation-duration: .001ms !important; transition-duration: .001ms !important; }
}

CSS;
}

/**
 * Typographic, form and print styling: the long tail of a base stylesheet.
 *
 * Every one of these is a rule a real site needs and nobody enjoys writing,
 * which is exactly why base stylesheets are large.
 */
function css_base_detail(): string
{
    $out = "\n/* Typography */\n";
    foreach (['prose', 'lede', 'note', 'caption', 'legal', 'meta'] as $block) {
        foreach ([['p', '1.6', '16'], ['h2', '1.25', '24'],
                  ['h3', '1.3', '18'], ['li', '1.55', '16'],
                  ['blockquote', '1.5', '18'], ['small', '1.4', '13']] as $r) {
            [$el, $lh, $fs] = $r;
            $out .= ".$block $el { line-height: $lh; font-size: var(--t-$fs); "
                  . "max-width: 68ch; }\n";
        }
        $out .= ".$block a { text-decoration: underline; "
              . "text-underline-offset: 2px; }\n";
        $out .= ".$block > * + * { margin-top: var(--s-12); }\n";
    }

    $out .= "\n/* Forms */\n";
    $controls = ['text', 'email', 'password', 'search', 'tel', 'url',
                 'number', 'date', 'month', 'time'];
    foreach ($controls as $type) {
        $out .= "input[type=\"$type\"] {\n"
              . "  width: 100%;\n  padding: var(--s-8) var(--s-12);\n"
              . "  border: 1px solid var(--c-mist);\n"
              . "  border-radius: var(--r-sm);\n"
              . "  background: var(--c-white);\n"
              . "  transition: border-color .15s ease, box-shadow .15s ease;\n}\n";
        $out .= "input[type=\"$type\"]:focus {\n"
              . "  border-color: var(--c-accent);\n"
              . "  box-shadow: 0 0 0 3px var(--c-accent-soft);\n"
              . "  outline: none;\n}\n";
        $out .= "input[type=\"$type\"]:disabled { background: var(--c-paper); "
              . "color: var(--c-mist); }\n";
        $out .= "input[type=\"$type\"]:invalid:not(:placeholder-shown) { "
              . "border-color: var(--c-bad); }\n";
        $out .= "input[type=\"$type\"]::placeholder { color: var(--c-mist); }\n";
    }
    foreach (['select', 'textarea'] as $el) {
        $out .= "$el { width: 100%; padding: var(--s-8) var(--s-12); "
              . "border: 1px solid var(--c-mist); border-radius: var(--r-sm); }\n";
        $out .= "$el:focus { border-color: var(--c-accent); outline: none; }\n";
    }

    $out .= "\n/* Print */\n@media print {\n";
    foreach (['masthead', 'categories', 'search', 'cookie-bar', 'newsletter',
              'drawer', 'autocomplete', 'pagination'] as $hide) {
        $out .= "  .$hide { display: none !important; }\n";
    }
    $out .= "  body { background: #fff; color: #000; font-size: 11pt; }\n"
          . "  a[href]::after { content: \" (\" attr(href) \")\"; "
          . "font-size: 9pt; }\n  .card { break-inside: avoid; }\n}\n";

    $out .= "\n/* Dark scheme */\n@media (prefers-color-scheme: dark) {\n"
          . "  :root {\n";
    foreach (['ink' => '#e8edf3', 'paper' => '#12181f', 'white' => '#19212b',
              'slate' => '#aab6c6', 'mist' => '#4a5768'] as $k => $v) {
        $out .= "    --c-$k: $v;\n";
    }
    $out .= "  }\n";
    foreach (['card', 'masthead', 'footer', 'drawer', 'autocomplete',
              'notice', 'newsletter'] as $c) {
        $out .= "  .$c { background: var(--c-white); "
              . "border-color: var(--c-mist); }\n";
    }
    $out .= "}\n";

    return $out;
}

/** Per-page-type overrides, which every shop accumulates. */
function css_page_rules(): string
{
    $pages = ['home', 'category', 'product', 'search', 'cart', 'checkout',
              'account', 'orders', 'order', 'login', 'register', 'about',
              'contact', 'error'];
    $out = "\n/* Page overrides */\n";
    foreach ($pages as $page) {
        $out .= "body.page-$page main { padding: var(--s-24); "
              . "max-width: 1280px; margin: 0 auto; }\n";
        $out .= "body.page-$page h1 { margin-bottom: var(--s-16); }\n";
        $out .= "body.page-$page .grid { gap: var(--s-20); }\n";
        $out .= "body.page-$page .breadcrumbs { padding-left: 0; }\n";
        $out .= "@media (max-width: 768px) { body.page-$page main { "
              . "padding: var(--s-12); } }\n";
        $out .= "@media (min-width: 1280px) { body.page-$page .grid { "
              . "grid-template-columns: repeat(4, minmax(0, 1fr)); } }\n";
    }
    return $out;
}

/**
 * Keyframes and transition helpers.
 *
 * Carried here because they are the part of a stylesheet with genuine
 * entropy -- every percentage stop has its own transform and opacity, so this
 * does not compress the way a utility table does, and real stylesheets are
 * full of it.
 */
function css_animations(): string
{
    $state = 2463534242;
    $out = "\n/* Motion */\n";
    $names = ['fade', 'rise', 'drop', 'slide-left', 'slide-right', 'pop',
              'shake', 'pulse', 'spin', 'sweep', 'bloom', 'settle', 'nudge',
              'flip', 'unfurl', 'shimmer', 'bounce', 'tick', 'blink', 'drift',
              'lift', 'sink', 'glide', 'swell', 'ripple', 'flicker'];
    foreach ($names as $name) {
        $out .= "@keyframes $name {\n";
        $stops = [0, 20, 45, 70, 100];
        foreach ($stops as $stop) {
            $x = (rnd($state) % 400) / 10.0 - 20.0;
            $y = (rnd($state) % 400) / 10.0 - 20.0;
            $s = 0.82 + (rnd($state) % 40) / 100.0;
            $r = (rnd($state) % 720) / 10.0 - 36.0;
            $o = (rnd($state) % 100) / 100.0;
            $out .= "  {$stop}% { transform: translate3d({$x}px, {$y}px, 0) "
                  . "scale($s) rotate({$r}deg); opacity: $o; }\n";
        }
        $out .= "}\n";
        $dur = 120 + (rnd($state) % 700);
        $out .= ".anim-$name { animation: $name {$dur}ms cubic-bezier("
              . ((rnd($state) % 100) / 100.0) . ', '
              . ((rnd($state) % 100) / 100.0) . ', '
              . ((rnd($state) % 100) / 100.0) . ', '
              . ((rnd($state) % 100) / 100.0) . ") both; }\n";
        $out .= ".anim-$name.is-paused { animation-play-state: paused; }\n";
    }
    return $out;
}

/** Per-department theming, as a shop with ten departments accumulates. */
function css_department_themes(): string
{
    $state = 747796405;
    $out = "\n/* Department themes */\n";
    $departments = ['hand-tools', 'power-tools', 'fixings', 'garden',
                    'workwear', 'paint', 'plumbing', 'electrical',
                    'storage', 'safety'];
    foreach ($departments as $slug) {
        $h = rnd($state) % 360;
        $out .= ".dept-$slug {\n"
              . "  --dept-hue: $h;\n"
              . "  --dept-tint: hsl($h 46% 94%);\n"
              . "  --dept-edge: hsl($h 38% 62%);\n"
              . "  --dept-ink: hsl($h 44% 24%);\n}\n";
        foreach (['banner', 'chip', 'rule', 'heading', 'card'] as $part) {
            $out .= ".dept-$slug .$part { border-color: var(--dept-edge); "
                  . "color: var(--dept-ink); }\n";
        }
        $out .= ".dept-$slug .banner { background: var(--dept-tint); "
              . "padding: var(--s-16) var(--s-24); "
              . "border-radius: var(--r-md); }\n";
        $out .= "@media (max-width: 768px) { .dept-$slug .banner { "
              . "padding: var(--s-12); } }\n";
    }
    return $out;
}

function stylesheets(string $root): void
{
    $dir = "$root/assets/css";
    file_put_contents("$dir/site.css",
        "/* Fettle & Co — base */\n" . css_tokens() . css_reset()
        . css_base_detail() . css_animations());
    file_put_contents("$dir/layout.css",
        "/* Fettle & Co — layout utilities */\n" . css_utilities());
    file_put_contents("$dir/components.css",
        "/* Fettle & Co — components */\n" . css_components()
        . css_component_variants() . css_page_rules()
        . css_department_themes());
}

/** Theme and density variants, which is how component sheets get their bulk. */
function css_component_variants(): string
{
    $out = "\n/* Variants */\n";
    foreach (['primary', 'secondary', 'ghost', 'danger', 'quiet'] as $variant) {
        foreach (['sm', 'md', 'lg'] as $size) {
            $pad = ['sm' => '6px 10px', 'md' => '10px 16px', 'lg' => '14px 22px'][$size];
            $fs = ['sm' => 13, 'md' => 14, 'lg' => 16][$size];
            $out .= ".btn-$variant.btn-$size {\n"
                  . "  padding: $pad;\n  font-size: var(--t-$fs);\n"
                  . "  border-radius: var(--r-sm);\n  font-weight: 600;\n"
                  . "  display: inline-flex;\n  align-items: center;\n"
                  . "  gap: var(--s-6);\n  transition: background .15s ease;\n}\n";
            $out .= ".btn-$variant.btn-$size:hover { filter: brightness(.94); }\n";
            $out .= ".btn-$variant.btn-$size:active { transform: translateY(1px); }\n";
            // Braced: in a double-quoted PHP string, "$size[disabled]" is
            // parsed as an array access on $size, not as a CSS attribute
            // selector following it.
            $out .= ".btn-$variant.btn-{$size}[disabled] { opacity: .5; cursor: not-allowed; }\n";
        }
    }
    foreach (CSS_PALETTE as $name => $_) {
        $out .= ".badge-$name { background: var(--c-$name); color: var(--c-white); }\n";
        $out .= ".alert-$name { border-left: 3px solid var(--c-$name); "
              . "background: color-mix(in srgb, var(--c-$name) 12%, white); "
              . "padding: var(--s-12) var(--s-16); border-radius: var(--r-sm); }\n";
    }
    return $out;
}

// ---------------------------------------------------------------------------
// Scripts
// ---------------------------------------------------------------------------

function js_prelude(): string
{
    return <<<'JS'
/* Fettle & Co storefront. Generated for the LogForge test application. */
(function (global) {
  'use strict';

  var doc = global.document;

  function $(selector, scope) { return (scope || doc).querySelector(selector); }
  function $$(selector, scope) {
    return Array.prototype.slice.call((scope || doc).querySelectorAll(selector));
  }
  function on(node, type, handler, options) {
    if (node) { node.addEventListener(type, handler, options || false); }
  }
  function delegate(root, type, selector, handler) {
    on(root, type, function (event) {
      var node = event.target.closest(selector);
      if (node && root.contains(node)) { handler.call(node, event, node); }
    });
  }
  function debounce(fn, wait) {
    var timer = null;
    return function () {
      var args = arguments, self = this;
      global.clearTimeout(timer);
      timer = global.setTimeout(function () { fn.apply(self, args); }, wait);
    };
  }
  function throttle(fn, wait) {
    var last = 0;
    return function () {
      var now = Date.now();
      if (now - last >= wait) { last = now; fn.apply(this, arguments); }
    };
  }
  function money(pence) {
    return '£' + (pence / 100).toFixed(2);
  }
  function request(path, options) {
    var config = options || {};
    return global.fetch(path, {
      method: config.method || 'GET',
      headers: config.headers || { 'Accept': 'application/json' },
      body: config.body ? JSON.stringify(config.body) : undefined,
      credentials: 'same-origin'
    }).then(function (response) {
      if (!response.ok) { throw new Error('HTTP ' + response.status); }
      return response.json();
    });
  }

  global.Fettle = {
    $: $, $$: $$, on: on, delegate: delegate,
    debounce: debounce, throttle: throttle, money: money, request: request
  };
}(window));

JS;
}

/**
 * The bulk of a real bundle: many small, similar modules. Generated rather
 * than written out one by one, but the output is ordinary JavaScript and it
 * runs.
 */
function js_modules(array $names): string
{
    $out = '';
    foreach ($names as $name) {
        $klass = str_replace(' ', '', ucwords(str_replace('-', ' ', $name)));
        $out .= <<<JS

(function (global) {
  'use strict';
  var F = global.Fettle;

  function {$klass}(root, options) {
    this.root = root;
    this.options = Object.assign({}, {$klass}.defaults, options || {});
    this.state = { ready: false, busy: false, error: null, items: [] };
    this.handlers = {};
    this.init();
  }

  {$klass}.defaults = {
    selector: '[data-{$name}]',
    endpoint: '/api/{$name}',
    activeClass: 'is-active',
    busyClass: 'is-busy',
    errorClass: 'has-error',
    retries: 2,
    timeout: 8000
  };

  {$klass}.prototype.init = function () {
    if (!this.root) { return; }
    this.bind();
    this.state.ready = true;
    this.emit('ready', this.state);
  };

  {$klass}.prototype.bind = function () {
    var self = this;
    F.delegate(this.root, 'click', '[data-action]', function (event, node) {
      var action = node.getAttribute('data-action');
      if (typeof self[action] === 'function') {
        event.preventDefault();
        self[action](node);
      }
    });
    F.on(this.root, 'keydown', function (event) {
      if (event.key === 'Escape') { self.close(); }
    });
  };

  {$klass}.prototype.on = function (name, handler) {
    (this.handlers[name] = this.handlers[name] || []).push(handler);
    return this;
  };

  {$klass}.prototype.emit = function (name, payload) {
    (this.handlers[name] || []).forEach(function (handler) {
      try { handler(payload); } catch (error) { global.console.error(error); }
    });
  };

  {$klass}.prototype.setBusy = function (busy) {
    this.state.busy = !!busy;
    if (this.root) { this.root.classList.toggle(this.options.busyClass, !!busy); }
  };

  {$klass}.prototype.fail = function (error) {
    this.state.error = error;
    if (this.root) { this.root.classList.add(this.options.errorClass); }
    this.emit('error', error);
  };

  {$klass}.prototype.refresh = function () {
    var self = this;
    this.setBusy(true);
    return F.request(this.options.endpoint).then(function (data) {
      self.state.items = data.items || [];
      self.render();
      self.emit('change', self.state);
    }).catch(function (error) {
      self.fail(error);
    }).then(function () {
      self.setBusy(false);
    });
  };

  {$klass}.prototype.render = function () {
    if (!this.root) { return; }
    var nodes = F.\$\$('[data-item]', this.root);
    nodes.forEach(function (node, index) {
      node.classList.toggle('is-first', index === 0);
      node.classList.toggle('is-last', index === nodes.length - 1);
    });
  };

  {$klass}.prototype.open = function () {
    if (this.root) { this.root.classList.add(this.options.activeClass); }
    this.emit('open', this.state);
  };

  {$klass}.prototype.close = function () {
    if (this.root) { this.root.classList.remove(this.options.activeClass); }
    this.emit('close', this.state);
  };

  {$klass}.prototype.destroy = function () {
    this.handlers = {};
    this.state.ready = false;
  };

  global.Fettle.{$klass} = {$klass};
}(window));

JS;
    }
    return $out;
}

function js_cart(): string
{
    return <<<'JS'

(function (global) {
  'use strict';
  var F = global.Fettle;
  var COUNT = '#cart-count';

  var Cart = {
    lines: [],

    sync: function () {
      return F.request('/api/cart').then(function (data) {
        Cart.lines = data.lines || [];
        Cart.paint();
        return data;
      });
    },

    add: function (productId, quantity) {
      return F.request('/api/cart', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: { product: Number(productId), quantity: Number(quantity) || 1 }
      }).then(Cart.sync);
    },

    remove: function (productId) {
      return F.request('/api/cart', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
        body: { product: Number(productId), quantity: 0 }
      }).then(Cart.sync);
    },

    total: function () {
      return Cart.lines.reduce(function (sum, line) {
        return sum + (line.price * line.quantity);
      }, 0);
    },

    count: function () {
      return Cart.lines.reduce(function (sum, line) {
        return sum + line.quantity;
      }, 0);
    },

    paint: function () {
      var badge = F.$(COUNT);
      if (badge) { badge.textContent = String(Cart.count()); }
      var totalNode = F.$('[data-cart-total]');
      if (totalNode) { totalNode.textContent = F.money(Cart.total()); }
      F.$$('[data-cart-line]').forEach(function (node) {
        var id = Number(node.getAttribute('data-cart-line'));
        var line = Cart.lines.filter(function (l) { return l.product === id; })[0];
        node.classList.toggle('is-empty', !line);
      });
    }
  };

  F.on(global, 'DOMContentLoaded', function () {
    F.delegate(global.document, 'click', '.add', function (event, node) {
      event.preventDefault();
      node.disabled = true;
      Cart.add(node.getAttribute('data-product'), 1).then(function () {
        node.disabled = false;
        node.classList.add('is-added');
      }).catch(function () { node.disabled = false; });
    });
    F.delegate(global.document, 'click', '[data-remove]', function (event, node) {
      event.preventDefault();
      Cart.remove(node.getAttribute('data-remove'));
    });
    Cart.sync().catch(function () { /* a signed-out visitor has no cart */ });
  });

  global.Fettle.Cart = Cart;
}(window));

JS;
}

function js_autocomplete(): string
{
    return <<<'JS'

(function (global) {
  'use strict';
  var F = global.Fettle;

  function Autocomplete(input) {
    this.input = input;
    this.list = null;
    this.items = [];
    this.cursor = -1;
    this.lastQuery = '';
    this.bind();
  }

  Autocomplete.prototype.bind = function () {
    var self = this;
    F.on(this.input, 'input', F.debounce(function () {
      self.query(self.input.value.trim());
    }, 180));
    F.on(this.input, 'keydown', function (event) {
      if (event.key === 'ArrowDown') { self.move(1); event.preventDefault(); }
      if (event.key === 'ArrowUp') { self.move(-1); event.preventDefault(); }
      if (event.key === 'Enter' && self.cursor >= 0) {
        var chosen = self.items[self.cursor];
        if (chosen) { global.location.href = '/p/' + chosen.id; }
      }
      if (event.key === 'Escape') { self.hide(); }
    });
    F.on(global.document, 'click', function (event) {
      if (!self.input.contains(event.target)) { self.hide(); }
    });
  };

  Autocomplete.prototype.query = function (term) {
    var self = this;
    if (term.length < 2 || term === this.lastQuery) { return; }
    this.lastQuery = term;
    F.request('/api/suggest?q=' + global.encodeURIComponent(term))
      .then(function (data) {
        self.items = data.suggestions || [];
        self.cursor = -1;
        self.paint();
      })
      .catch(function () { self.hide(); });
  };

  Autocomplete.prototype.paint = function () {
    if (!this.list) {
      this.list = global.document.createElement('div');
      this.list.className = 'autocomplete';
      this.input.parentNode.appendChild(this.list);
    }
    if (!this.items.length) { return this.hide(); }
    this.list.innerHTML = this.items.map(function (item, index) {
      return '<a class="suggestion" data-index="' + index + '" href="/p/'
        + item.id + '">' + item.name + '</a>';
    }).join('');
    this.list.hidden = false;
  };

  Autocomplete.prototype.move = function (step) {
    if (!this.items.length) { return; }
    this.cursor = (this.cursor + step + this.items.length) % this.items.length;
    F.$$('.suggestion', this.list).forEach(function (node, index) {
      node.classList.toggle('is-active', index === this.cursor);
    }, this);
  };

  Autocomplete.prototype.hide = function () {
    if (this.list) { this.list.hidden = true; }
    this.cursor = -1;
  };

  F.on(global, 'DOMContentLoaded', function () {
    var input = F.$('#q');
    if (input) { new Autocomplete(input); }
  });

  global.Fettle.Autocomplete = Autocomplete;
}(window));

JS;
}

/**
 * A small deterministic generator, used for the parts of a bundle that carry
 * real entropy.
 *
 * Purely repetitive output was the first attempt and it was wrong in a way
 * worth recording: 55 KB of near-identical generated modules gzipped to 3.3 KB,
 * a ratio of 6%. Real JavaScript compresses to somewhere around 20-35%, so a
 * file that crushes that far is itself a tell -- and the byte count in the log
 * is the compressed one, so it came out far too small as well.
 *
 * What fixes it is not random padding, which would compress badly for the
 * wrong reason and look like nothing. It is the content real bundles actually
 * carry a lot of: inline SVG icon paths and message catalogues, both of which
 * are genuinely high-entropy and genuinely belong there.
 */
function rnd(int &$state): int
{
    // xorshift32. Deterministic, and independent of the run seed because
    // static assets are the same file for every build.
    $state ^= ($state << 13) & 0xFFFFFFFF;
    $state ^= $state >> 17;
    $state ^= ($state << 5) & 0xFFFFFFFF;
    return $state & 0x7FFFFFFF;
}

function js_icons(int $count): string
{
    $state = 99194853;
    $names = [];
    $out = "\n/* Inline icon registry. */\n"
         . "(function (global) {\n  'use strict';\n"
         . "  global.Fettle.icons = {\n";
    for ($i = 0; $i < $count; $i++) {
        $name = 'icon-' . substr(md5((string) $i), 0, 7);
        $names[] = $name;
        $d = 'M' . (rnd($state) % 24) . ' ' . (rnd($state) % 24);
        $segments = 6 + (rnd($state) % 14);
        for ($s = 0; $s < $segments; $s++) {
            $cmd = ['L', 'C', 'Q', 'S', 'A'][rnd($state) % 5];
            $nums = ['L' => 2, 'C' => 6, 'Q' => 4, 'S' => 4, 'A' => 7][$cmd];
            $parts = [];
            for ($n = 0; $n < $nums; $n++) {
                $parts[] = (rnd($state) % 240) / 10.0;
            }
            $d .= $cmd . implode(' ', $parts);
        }
        $out .= "    '$name': '<svg viewBox=\"0 0 24 24\" fill=\"none\" "
              . "stroke=\"currentColor\" stroke-width=\"1.6\" "
              . "stroke-linecap=\"round\"><path d=\"$d Z\"/></svg>',\n";
    }
    $out .= "  };\n";
    $out .= "  global.Fettle.icon = function (name) {\n"
          . "    return global.Fettle.icons[name] || global.Fettle.icons['"
          . $names[0] . "'];\n  };\n}(window));\n";
    return $out;
}

function js_messages(int $count): string
{
    $state = 1013904223;
    $subjects = ['basket', 'order', 'delivery', 'payment', 'address',
                 'account', 'password', 'voucher', 'stock', 'return',
                 'wishlist', 'review', 'search', 'filter', 'session'];
    $verbs = ['could not be updated', 'was saved', 'is unavailable',
              'has expired', 'needs a valid value', 'is already in use',
              'was removed', 'could not be verified', 'is being processed',
              'was applied', 'did not match our records', 'is out of stock'];
    $advice = ['Try again in a moment.', 'Check the details and resubmit.',
               'Contact us if this keeps happening.',
               'Refresh the page to see the latest.',
               'Some items may no longer be available.',
               'Your changes have not been lost.', ''];

    $out = "\n/* UI message catalogue. */\n"
         . "(function (global) {\n  'use strict';\n"
         . "  global.Fettle.messages = {\n";
    for ($i = 0; $i < $count; $i++) {
        $key = $subjects[rnd($state) % count($subjects)] . '.'
             . substr(md5((string) ($i * 7919)), 0, 6);
        $text = ucfirst($subjects[rnd($state) % count($subjects)]) . ' '
              . $verbs[rnd($state) % count($verbs)] . '. '
              . $advice[rnd($state) % count($advice)];
        $out .= "    '$key': " . json_encode(trim($text)) . ",\n";
    }
    $out .= "  };\n"
          . "  global.Fettle.t = function (key, fallback) {\n"
          . "    return global.Fettle.messages[key] || fallback || key;\n"
          . "  };\n}(window));\n";
    return $out;
}

function scripts(string $root): void
{
    $dir = "$root/assets/js";

    file_put_contents("$dir/app.js",
        js_prelude()
        . js_icons(150)
        . js_messages(420)
        . js_modules(['drawer', 'tabs', 'accordion', 'carousel', 'modal',
                      'tooltip', 'filters', 'sort', 'gallery', 'reviews',
                      'stock', 'recently-viewed', 'compare', 'wishlist',
                      'address-book', 'delivery', 'returns', 'analytics']));

    file_put_contents("$dir/cart.js",
        js_cart()
        . js_messages(160)
        . js_modules(['cart-drawer', 'cart-summary', 'promo-code',
                      'delivery-options', 'gift-message']));

    file_put_contents("$dir/autocomplete.js",
        js_autocomplete()
        . js_icons(40)
        . js_messages(90)
        . js_modules(['search-history', 'search-filters', 'search-facets']));
}
