use indoc::indoc;
use mago_allocator::Arena;
use schemars::JsonSchema;

use mago_reporting::Annotation;
use mago_reporting::Issue;
use mago_reporting::Level;
use mago_span::Span;
use mago_syntax::cst::Argument;
use mago_syntax::cst::Expression;
use mago_syntax::cst::FunctionCall;
use mago_syntax::cst::Literal;
use mago_syntax::cst::Node;
use mago_syntax::cst::NodeKind;
use mago_syntax::cst::StringPart;

use crate::category::Category;
use crate::context::LintContext;
use crate::integration::Integration;
use crate::requirements::RuleRequirements;
use crate::rule::Config;
use crate::rule::LintRule;
use crate::rule::utils::call::function_call_matches_any;
use crate::rule_meta::RuleMeta;
use crate::settings::RuleSettings;

/// Functions that *define* a hook name. Subscribing functions (`add_action`,
/// `add_filter`, `remove_action`, `remove_filter`) are intentionally not
/// included: subscribing to an existing (possibly third-party) hook is not
/// this plugin's naming choice.
const HOOK_DEFINING_FUNCTIONS: &[&str] = &["do_action", "apply_filters"];

#[derive(Debug, Clone)]
pub struct ValidHookNameRule {
    meta: &'static RuleMeta,
    cfg: ValidHookNameConfig,
}

#[derive(Debug, Clone, Eq, PartialEq, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct ValidHookNameConfig {
    pub level: Level,
    /// Extra characters (e.g. `"/."`) that are accepted as word delimiters in
    /// addition to underscores. Namespaced hooks like `myplugin/loaded` are
    /// common, so this mirrors the WPCS escape hatch.
    pub additional_word_delimiters: String,
}

impl Default for ValidHookNameConfig {
    fn default() -> Self {
        Self { level: Level::Warning, additional_word_delimiters: String::new() }
    }
}

impl Config for ValidHookNameConfig {
    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for ValidHookNameRule {
    type Config = ValidHookNameConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "Valid Hook Name",
            code: "valid-hook-name",
            description: indoc! {"
                Ensures that hook names defined via `do_action()` or `apply_filters()`
                follow the WordPress naming conventions: lowercase letters, numbers,
                and underscores as word separators.

                Only the literal parts of a hook name are validated; dynamic parts of
                interpolated hook names (e.g. `\"myplugin_{$type}_saved\"`) are ignored.

                Additional word delimiters (such as `/` or `.` for namespaced hooks
                like `myplugin/loaded`) can be allowed via the
                `additional-word-delimiters` option.
            "},
            good_example: indoc! {r#"
                <?php

                do_action('myplugin_post_saved', $post_id);
                $value = apply_filters('myplugin_option_value', $value);
            "#},
            bad_example: indoc! {r#"
                <?php

                do_action('MyPlugin_Post_Saved', $post_id);
                $value = apply_filters('myplugin-option-value', $value);
            "#},
            category: Category::Consistency,
            requirements: RuleRequirements::Integration(Integration::WordPress),
        };

        &META
    }

    fn targets() -> &'static [NodeKind] {
        const TARGETS: &[NodeKind] = &[NodeKind::FunctionCall];

        TARGETS
    }

    fn build(settings: &RuleSettings<Self::Config>) -> Self {
        Self { meta: Self::meta(), cfg: settings.config.clone() }
    }

    fn check<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, node: Node<'_, 'arena>)
    where
        A: Arena,
    {
        let Node::FunctionCall(function_call) = node else {
            return;
        };

        if !is_hook_defining_call(ctx, function_call) {
            return;
        }

        let Some(Argument::Positional(first_argument)) = function_call.argument_list.arguments.first() else {
            return;
        };

        match first_argument.value {
            Expression::Literal(Literal::String(string_literal)) => {
                if let Some(value) = string_literal.value {
                    self.validate_hook_name(ctx, value, string_literal.span, false);
                }
            }
            Expression::CompositeString(composite_string) => {
                // Only the literal parts are validated; dynamic parts are fine.
                for part in composite_string.parts() {
                    if let StringPart::Literal(literal_part) = part {
                        self.validate_hook_name(ctx, literal_part.raw, literal_part.span, true);
                    }
                }
            }
            _ => {
                // Non-literal hook names (variables, constants, concatenations)
                // are not validated.
            }
        }
    }
}

impl ValidHookNameRule {
    fn validate_hook_name<A>(&self, ctx: &mut LintContext<'_, '_, A>, name: &[u8], span: Span, raw: bool)
    where
        A: Arena,
    {
        let additional_delimiters = self.cfg.additional_word_delimiters.as_bytes();

        let mut has_uppercase = false;
        let mut invalid_delimiters: Vec<u8> = Vec::new();

        let mut index = 0;
        while index < name.len() {
            let byte = name[index];

            // In raw (unparsed) literal parts of interpolated strings, skip
            // escape sequences such as `\n`, `\$`, `\x41`, `\101`, or
            // `\u{1F600}` to avoid false positives.
            if raw && byte == b'\\' {
                index = skip_escape_sequence(name, index);
                continue;
            }

            if byte.is_ascii_uppercase() {
                has_uppercase = true;
            } else if !byte.is_ascii_lowercase()
                && !byte.is_ascii_digit()
                && byte != b'_'
                && byte.is_ascii()
                && !additional_delimiters.contains(&byte)
            {
                if !invalid_delimiters.contains(&byte) {
                    invalid_delimiters.push(byte);
                }
            }

            index += 1;
        }

        if has_uppercase {
            ctx.collector.report(
                Issue::new(self.cfg.level(), "Hook names should be lowercase.")
                    .with_code(self.meta.code)
                    .with_annotation(
                        Annotation::primary(span).with_message("This hook name contains uppercase characters"),
                    )
                    .with_note("WordPress hook names conventionally use only lowercase letters.")
                    .with_help("Use lowercase letters in the hook name."),
            );
        }

        if !invalid_delimiters.is_empty() {
            let characters =
                invalid_delimiters.iter().map(|byte| format!("`{}`", *byte as char)).collect::<Vec<_>>().join(", ");

            ctx.collector.report(
                Issue::new(self.cfg.level(), "Words in hook names should be separated by underscores.")
                    .with_code(self.meta.code)
                    .with_annotation(
                        Annotation::primary(span)
                            .with_message(format!("This hook name uses {characters} as a word separator")),
                    )
                    .with_note("WordPress hook names conventionally use underscores between words.")
                    .with_help(
                        "Replace the punctuation with underscores, or allow specific delimiters via the `additional-word-delimiters` option.",
                    ),
            );
        }
    }
}

/// Returns the index of the first byte after the escape sequence starting at
/// the backslash at `backslash`. Handles the PHP double-quoted string escapes:
/// `\x` + up to 2 hex digits, `\u{...}` through the closing brace, octal
/// `\NNN` (up to 3 digits), and single-character escapes (`\n`, `\$`, ...).
fn skip_escape_sequence(bytes: &[u8], backslash: usize) -> usize {
    let marker_index = backslash + 1;

    let Some(marker) = bytes.get(marker_index) else {
        // A trailing backslash; nothing more to skip.
        return marker_index;
    };

    match marker {
        b'x' => {
            // `\x` followed by up to 2 hexadecimal digits.
            let mut index = marker_index + 1;
            let mut digits = 0;
            while digits < 2 && bytes.get(index).is_some_and(u8::is_ascii_hexdigit) {
                index += 1;
                digits += 1;
            }

            index
        }
        b'u' if bytes.get(marker_index + 1) == Some(&b'{') => {
            // `\u{...}`: skip through the closing brace.
            let mut index = marker_index + 2;
            while index < bytes.len() && bytes[index] != b'}' {
                index += 1;
            }

            // Include the closing brace if present.
            if index < bytes.len() { index + 1 } else { index }
        }
        b'0'..=b'7' => {
            // Octal escape: up to 3 octal digits.
            let mut index = marker_index;
            let mut digits = 0;
            while digits < 3 && matches!(bytes.get(index), Some(b'0'..=b'7')) {
                index += 1;
                digits += 1;
            }

            index
        }
        // Single-character escape (`\n`, `\t`, `\$`, `\\`, a lone `\u`, ...).
        _ => marker_index + 1,
    }
}

fn is_hook_defining_call<'arena, A>(ctx: &LintContext<'_, 'arena, A>, call: &FunctionCall<'arena>) -> bool
where
    A: Arena,
{
    if function_call_matches_any(ctx, call, HOOK_DEFINING_FUNCTIONS).is_some() {
        return true;
    }

    // Handle fully-qualified calls in the global namespace (e.g. `\do_action(...)`).
    if let Expression::Identifier(identifier) = call.function
        && identifier.is_fully_qualified()
        && let Some(stripped) = identifier.value().strip_prefix(b"\\")
    {
        return HOOK_DEFINING_FUNCTIONS.iter().any(|name| stripped.eq_ignore_ascii_case(name.as_bytes()));
    }

    false
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::ValidHookNameRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    test_lint_success! {
        name = lowercase_hook_name_is_valid,
        rule = ValidHookNameRule,
        code = indoc! {r"
            <?php

            do_action('myplugin_post_saved', $post_id);
        "}
    }

    test_lint_success! {
        name = lowercase_filter_name_is_valid,
        rule = ValidHookNameRule,
        code = indoc! {r"
            <?php

            $value = apply_filters('myplugin_option_value', $value);
        "}
    }

    test_lint_success! {
        name = digits_and_underscores_are_valid,
        rule = ValidHookNameRule,
        code = indoc! {r"
            <?php

            do_action('myplugin_v2_loaded');
        "}
    }

    test_lint_success! {
        name = subscribing_functions_are_not_flagged,
        rule = ValidHookNameRule,
        code = indoc! {r"
            <?php

            add_action('Third-Party.Hook', 'my_callback');
            add_filter('Another/Hook', 'my_callback');
            remove_action('Bad Name', 'my_callback');
            remove_filter('Bad-Name', 'my_callback');
        "}
    }

    test_lint_success! {
        name = dynamic_parts_are_ignored,
        rule = ValidHookNameRule,
        code = indoc! {r#"
            <?php

            do_action("myplugin_{$type}_saved", $post_id);
        "#}
    }

    test_lint_success! {
        name = non_literal_hook_name_is_ignored,
        rule = ValidHookNameRule,
        code = indoc! {r"
            <?php

            do_action($hook_name, $post_id);
        "}
    }

    test_lint_success! {
        name = additional_word_delimiters_are_allowed,
        rule = ValidHookNameRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.valid_hook_name.config.additional_word_delimiters = "/.".to_string();
        },
        code = indoc! {r"
            <?php

            do_action('myplugin/loaded');
            $value = apply_filters('myplugin.option.value', $value);
        "}
    }

    test_lint_success! {
        name = escape_sequences_in_interpolated_names_are_not_flagged,
        rule = ValidHookNameRule,
        code = indoc! {r#"
            <?php

            do_action("myplugin_\x67ood_{$type}");
        "#}
    }

    test_lint_failure! {
        name = uppercase_hook_name_is_flagged,
        rule = ValidHookNameRule,
        count = 1,
        code = indoc! {r"
            <?php

            do_action('MyPlugin_Post_Saved', $post_id);
        "}
    }

    test_lint_failure! {
        name = hyphen_separator_is_flagged,
        rule = ValidHookNameRule,
        count = 1,
        code = indoc! {r"
            <?php

            $value = apply_filters('myplugin-option-value', $value);
        "}
    }

    test_lint_failure! {
        name = space_separator_is_flagged,
        rule = ValidHookNameRule,
        count = 1,
        code = indoc! {r"
            <?php

            do_action('myplugin post saved');
        "}
    }

    test_lint_failure! {
        name = period_is_flagged_by_default,
        rule = ValidHookNameRule,
        count = 1,
        code = indoc! {r"
            <?php

            do_action('myplugin.loaded');
        "}
    }

    test_lint_failure! {
        name = uppercase_and_hyphen_are_flagged_separately,
        rule = ValidHookNameRule,
        count = 2,
        code = indoc! {r"
            <?php

            do_action('MyPlugin-Loaded');
        "}
    }

    test_lint_failure! {
        name = literal_parts_of_interpolated_names_are_validated,
        rule = ValidHookNameRule,
        count = 1,
        code = indoc! {r#"
            <?php

            do_action("MyPlugin_{$type}_saved", $post_id);
        "#}
    }

    test_lint_failure! {
        name = fully_qualified_call_is_checked,
        rule = ValidHookNameRule,
        count = 1,
        code = indoc! {r"
            <?php

            \do_action('MyPlugin_Loaded');
        "}
    }

    test_lint_success! {
        name = unicode_escape_in_interpolated_name_is_not_flagged,
        rule = ValidHookNameRule,
        code = indoc! {r#"
            <?php

            do_action("\u{1F600}_hook_{$type}");
        "#}
    }

    test_lint_success! {
        name = hex_escapes_in_interpolated_name_are_not_flagged,
        rule = ValidHookNameRule,
        code = indoc! {r#"
            <?php

            do_action("\x41\x42_hook_{$type}");
        "#}
    }

    test_lint_success! {
        name = octal_escape_in_interpolated_name_is_not_flagged,
        rule = ValidHookNameRule,
        code = indoc! {r#"
            <?php

            do_action("\101\102_hook_{$type}");
        "#}
    }

    test_lint_failure! {
        name = bad_delimiter_next_to_escapes_is_still_flagged,
        rule = ValidHookNameRule,
        count = 1,
        code = indoc! {r#"
            <?php

            do_action("\u{1F600}-hook_{$type}");
        "#}
    }
}
