use indoc::indoc;
use mago_allocator::Arena;
use schemars::JsonSchema;

use mago_reporting::Annotation;
use mago_reporting::Issue;
use mago_reporting::Level;
use mago_span::HasSpan;
use mago_syntax::cst::Argument;
use mago_syntax::cst::Expression;
use mago_syntax::cst::FunctionCall;
use mago_syntax::cst::Literal;
use mago_syntax::cst::Node;
use mago_syntax::cst::NodeKind;

use crate::category::Category;
use crate::context::LintContext;
use crate::integration::Integration;
use crate::requirements::RuleRequirements;
use crate::rule::Config;
use crate::rule::LintRule;
use crate::rule::utils::call::function_call_matches_any;
use crate::rule_meta::RuleMeta;
use crate::settings::RuleSettings;

const SCRIPT_FUNCTIONS: &[&str] = &["wp_enqueue_script", "wp_register_script"];
const STYLE_FUNCTIONS: &[&str] = &["wp_enqueue_style", "wp_register_style"];

/// Parameter slots shared by the four functions: `$handle`, `$src`, `$deps`, `$ver`, and the
/// fifth parameter (`$args`/`$in_footer` for scripts, `$media` for styles).
const SLOT_COUNT: usize = 5;
const SRC_SLOT: usize = 1;
const VER_SLOT: usize = 3;
const FIFTH_SLOT: usize = 4;

#[derive(Debug, Clone)]
pub struct EnqueuedResourceParametersRule {
    meta: &'static RuleMeta,
    cfg: EnqueuedResourceParametersConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct EnqueuedResourceParametersConfig {
    pub level: Level,
}

impl Default for EnqueuedResourceParametersConfig {
    fn default() -> Self {
        Self { level: Level::Warning }
    }
}

impl Config for EnqueuedResourceParametersConfig {
    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for EnqueuedResourceParametersRule {
    type Config = EnqueuedResourceParametersConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "Enqueued Resource Parameters",
            code: "enqueued-resource-parameters",
            description: indoc! {"
                Checks calls to `wp_enqueue_script()`, `wp_register_script()`, `wp_enqueue_style()`,
                and `wp_register_style()` that register a resource by `$src`:

                - The `$ver` (version) parameter should be an explicit value. When it is missing or
                  literally `false`, WordPress falls back to its own core version, so browsers and
                  CDNs are not cache-busted when the asset changes; `null` disables versioning
                  entirely.
                - For scripts, the fifth parameter (`$args`/`$in_footer`) should be passed
                  explicitly: by default the script is printed in the `<head>`, where it blocks
                  rendering.
            "},
            good_example: indoc! {r"
                <?php

                wp_enqueue_script('my-script', 'https://example.com/js/app.js', [], '1.2.3', true);
                wp_enqueue_style('my-style', 'https://example.com/css/app.css', [], '1.2.3');

                // Registering by handle only is fine.
                wp_enqueue_script('jquery');
            "},
            bad_example: indoc! {r"
                <?php

                // No version, and no explicit in_footer decision.
                wp_enqueue_script('my-script', 'https://example.com/js/app.js', []);

                // `false` falls back to the WordPress core version.
                wp_enqueue_style('my-style', 'https://example.com/css/app.css', [], false);
            "},
            category: Category::BestPractices,
            requirements: RuleRequirements::Integration(Integration::WordPress),
        };

        &META
    }

    fn targets() -> &'static [NodeKind] {
        const TARGETS: &[NodeKind] = &[NodeKind::FunctionCall];

        TARGETS
    }

    fn build(settings: &RuleSettings<Self::Config>) -> Self {
        Self { meta: Self::meta(), cfg: settings.config }
    }

    fn check<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, node: Node<'_, 'arena>)
    where
        A: Arena,
    {
        let Node::FunctionCall(function_call) = node else {
            return;
        };

        let Some(is_script) = enqueue_call_is_script(ctx, function_call) else {
            return;
        };

        // Map each argument onto its parameter slot; bail out conservatively when the
        // call shape cannot be proven (spreads, unknown named arguments, ...).
        let Some(slots) = collect_argument_slots(function_call, is_script) else {
            return;
        };

        // Registering by handle only (no `$src`) is perfectly fine.
        if slots[SRC_SLOT].is_none() {
            return;
        }

        match slots[VER_SLOT] {
            None => {
                let issue = Issue::new(self.cfg.level(), "Enqueued resource is missing the `$ver` (version) parameter")
                    .with_code(self.meta.code)
                    .with_annotation(
                        Annotation::primary(function_call.span()).with_message("No version passed for this resource"),
                    )
                    .with_note(
                        "Without a version, WordPress falls back to its core version, so browsers and CDNs are not cache-busted when the asset itself changes.",
                    )
                    .with_help("Pass the asset's own version string as the 4th (`$ver`) argument.");

                ctx.collector.report(issue);
            }
            Some(version) => {
                let version = version.unparenthesized();

                if let Expression::Literal(literal @ (Literal::False(_) | Literal::Null(_))) = version {
                    let (what, effect) = match literal {
                        Literal::False(_) => ("`false`", "WordPress falls back to its core version"),
                        _ => ("`null`", "no version is added at all"),
                    };

                    let issue = Issue::new(
                        self.cfg.level(),
                        format!("Enqueued resource version is explicitly {what}"),
                    )
                    .with_code(self.meta.code)
                    .with_annotation(
                        Annotation::primary(version.span())
                            .with_message(format!("With {what} as the version, {effect}")),
                    )
                    .with_note(
                        "Browsers and CDNs use the version query string to cache-bust; it should change when the asset changes.",
                    )
                    .with_help("Pass the asset's own version string as the 4th (`$ver`) argument.");

                    ctx.collector.report(issue);
                }
            }
        }

        if is_script && slots[FIFTH_SLOT].is_none() {
            let issue = Issue::new(self.cfg.level(), "Enqueued script does not set `$in_footer` explicitly")
                .with_code(self.meta.code)
                .with_annotation(
                    Annotation::primary(function_call.span())
                        .with_message("No `$args`/`$in_footer` argument passed for this script"),
                )
                .with_note("By default, scripts are printed in the `<head>`, where they block page rendering.")
                .with_help(
                    "Pass an explicit 5th argument: `true` (or `['in_footer' => true]`) to load the script in the footer, or `false` to keep it in the head deliberately.",
                );

            ctx.collector.report(issue);
        }
    }
}

/// Determines whether the call targets one of the enqueue/register functions.
///
/// Returns `Some(true)` for the script functions, `Some(false)` for the style functions,
/// and `None` for anything else.
fn enqueue_call_is_script<'arena, A>(ctx: &LintContext<'_, 'arena, A>, call: &FunctionCall<'arena>) -> Option<bool>
where
    A: Arena,
{
    if function_call_matches_any(ctx, call, SCRIPT_FUNCTIONS).is_some() {
        return Some(true);
    }

    if function_call_matches_any(ctx, call, STYLE_FUNCTIONS).is_some() {
        return Some(false);
    }

    // Handle fully qualified calls to the global functions, e.g. `\wp_enqueue_script(...)`.
    if let Expression::Identifier(identifier) = call.function
        && identifier.is_fully_qualified()
    {
        let name = identifier.value();
        let name = name.strip_prefix(b"\\").unwrap_or(name);

        if memchr::memchr(b'\\', name).is_none() {
            if SCRIPT_FUNCTIONS.iter().any(|function| name.eq_ignore_ascii_case(function.as_bytes())) {
                return Some(true);
            }

            if STYLE_FUNCTIONS.iter().any(|function| name.eq_ignore_ascii_case(function.as_bytes())) {
                return Some(false);
            }
        }
    }

    None
}

/// Maps the call's arguments onto the five parameter slots.
///
/// Returns `None` (conservative bail-out) when the argument shape cannot be proven:
/// spread arguments, more arguments than parameters, unrecognized named arguments,
/// or a slot filled twice.
fn collect_argument_slots<'ast, 'arena>(
    call: &'ast FunctionCall<'arena>,
    is_script: bool,
) -> Option<[Option<&'ast Expression<'arena>>; SLOT_COUNT]> {
    let mut slots: [Option<&'ast Expression<'arena>>; SLOT_COUNT] = [None; SLOT_COUNT];
    let mut next_positional = 0;

    for argument in call.argument_list.arguments.iter() {
        if argument.is_unpacked() {
            return None;
        }

        let slot = match argument {
            Argument::Positional(_) => {
                let slot = next_positional;
                next_positional += 1;
                slot
            }
            Argument::Named(named) => parameter_slot(named.name.value, is_script)?,
        };

        if slot >= SLOT_COUNT || slots[slot].is_some() {
            return None;
        }

        slots[slot] = Some(argument.value());
    }

    Some(slots)
}

/// Resolves a named argument to its parameter slot, or `None` for unknown names.
///
/// Names are matched case-insensitively to stay lenient, mirroring how function names
/// are matched elsewhere in this crate.
fn parameter_slot(name: &[u8], is_script: bool) -> Option<usize> {
    if name.eq_ignore_ascii_case(b"handle") {
        Some(0)
    } else if name.eq_ignore_ascii_case(b"src") {
        Some(SRC_SLOT)
    } else if name.eq_ignore_ascii_case(b"deps") {
        Some(2)
    } else if name.eq_ignore_ascii_case(b"ver") {
        Some(VER_SLOT)
    } else if is_script && (name.eq_ignore_ascii_case(b"args") || name.eq_ignore_ascii_case(b"in_footer")) {
        // `$in_footer` was renamed to `$args` in WordPress 6.3.
        Some(FIFTH_SLOT)
    } else if !is_script && name.eq_ignore_ascii_case(b"media") {
        Some(FIFTH_SLOT)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::EnqueuedResourceParametersRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    test_lint_success! {
        name = script_with_version_and_in_footer,
        rule = EnqueuedResourceParametersRule,
        code = indoc! {r"
            <?php

            wp_enqueue_script('my-script', 'https://example.com/js/app.js', [], '1.2.3', true);
            wp_register_script('other', 'https://example.com/js/other.js', [], '2.0.0', ['in_footer' => true]);
        "}
    }

    test_lint_success! {
        name = style_with_version,
        rule = EnqueuedResourceParametersRule,
        code = indoc! {r"
            <?php

            wp_enqueue_style('my-style', 'https://example.com/css/app.css', [], '1.2.3');
            wp_register_style('other', 'https://example.com/css/other.css', [], '1.0', 'print');
        "}
    }

    test_lint_success! {
        name = enqueue_by_handle_only,
        rule = EnqueuedResourceParametersRule,
        code = indoc! {r"
            <?php

            wp_enqueue_script('jquery');
            wp_enqueue_style('common');
        "}
    }

    test_lint_success! {
        name = dynamic_version_values_are_fine,
        rule = EnqueuedResourceParametersRule,
        code = indoc! {r"
            <?php

            wp_enqueue_script('a', $src, [], $version, true);
            wp_enqueue_script('b', $src, [], MY_PLUGIN_VERSION, true);
            wp_enqueue_script('c', $src, [], filemtime($path), true);
            wp_enqueue_style('d', $src, [], '20240101');
            wp_enqueue_style('e', $src, [], 1.5);
        "}
    }

    test_lint_success! {
        name = spread_arguments_bail_out,
        rule = EnqueuedResourceParametersRule,
        code = indoc! {r"
            <?php

            wp_enqueue_script(...$args);
            wp_enqueue_script('my-script', ...$rest);
        "}
    }

    test_lint_success! {
        name = unknown_named_argument_bails_out,
        rule = EnqueuedResourceParametersRule,
        code = indoc! {r"
            <?php

            wp_enqueue_script('my-script', src: $src, unknown: true);
        "}
    }

    test_lint_success! {
        name = named_arguments_with_version_and_footer,
        rule = EnqueuedResourceParametersRule,
        code = indoc! {r"
            <?php

            wp_enqueue_script('my-script', $src, ver: '1.2.3', in_footer: true);
            wp_enqueue_style('my-style', $src, ver: '1.2.3');
        "}
    }

    test_lint_success! {
        name = mixed_case_named_arguments_are_recognized,
        rule = EnqueuedResourceParametersRule,
        code = indoc! {r"
            <?php

            wp_enqueue_script('my-script', $src, Ver: '1.2.3', In_Footer: true);
            wp_enqueue_style('my-style', $src, VER: '1.2.3');
        "}
    }

    test_lint_success! {
        name = unrelated_function_is_ignored,
        rule = EnqueuedResourceParametersRule,
        code = indoc! {r"
            <?php

            my_enqueue_script('my-script', $src);
        "}
    }

    test_lint_failure! {
        name = script_missing_version_and_footer,
        rule = EnqueuedResourceParametersRule,
        count = 2,
        code = indoc! {r"
            <?php

            wp_enqueue_script('my-script', 'https://example.com/js/app.js', []);
        "}
    }

    test_lint_failure! {
        name = script_with_false_version,
        rule = EnqueuedResourceParametersRule,
        count = 1,
        code = indoc! {r"
            <?php

            wp_register_script('my-script', 'https://example.com/js/app.js', [], false, true);
        "}
    }

    test_lint_failure! {
        name = script_with_null_version,
        rule = EnqueuedResourceParametersRule,
        count = 1,
        code = indoc! {r"
            <?php

            wp_enqueue_script('my-script', 'https://example.com/js/app.js', [], null, true);
        "}
    }

    test_lint_failure! {
        name = style_missing_version,
        rule = EnqueuedResourceParametersRule,
        count = 1,
        code = indoc! {r"
            <?php

            wp_enqueue_style('my-style', 'https://example.com/css/app.css');
        "}
    }

    test_lint_failure! {
        name = style_with_false_version,
        rule = EnqueuedResourceParametersRule,
        count = 1,
        code = indoc! {r"
            <?php

            wp_register_style('my-style', 'https://example.com/css/app.css', [], false);
        "}
    }

    test_lint_failure! {
        name = script_missing_in_footer_only,
        rule = EnqueuedResourceParametersRule,
        count = 1,
        code = indoc! {r"
            <?php

            wp_enqueue_script('my-script', 'https://example.com/js/app.js', [], '1.2.3');
        "}
    }

    test_lint_failure! {
        name = fully_qualified_call_is_checked,
        rule = EnqueuedResourceParametersRule,
        count = 1,
        code = indoc! {r"
            <?php

            \wp_enqueue_style('my-style', 'https://example.com/css/app.css');
        "}
    }

    test_lint_failure! {
        name = uppercase_call_is_checked,
        rule = EnqueuedResourceParametersRule,
        count = 1,
        code = indoc! {r"
            <?php

            WP_Enqueue_Style('my-style', 'https://example.com/css/app.css');
        "}
    }

    test_lint_failure! {
        name = named_ver_false_is_flagged,
        rule = EnqueuedResourceParametersRule,
        count = 1,
        code = indoc! {r"
            <?php

            wp_enqueue_style('my-style', $src, ver: false);
        "}
    }

    test_lint_failure! {
        name = uppercase_named_ver_false_is_flagged,
        rule = EnqueuedResourceParametersRule,
        count = 1,
        code = indoc! {r"
            <?php

            wp_enqueue_style('my-style', $src, VER: false);
        "}
    }

    test_lint_failure! {
        name = parenthesized_false_version_is_flagged,
        rule = EnqueuedResourceParametersRule,
        count = 1,
        code = indoc! {r"
            <?php

            wp_enqueue_style('my-style', $src, [], (false));
        "}
    }
}
