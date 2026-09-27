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
const HOOK_DEFINING_FUNCTIONS: &[&str] =
    &["do_action", "apply_filters", "do_action_ref_array", "apply_filters_ref_array"];

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
    fn default_enabled() -> bool {
        false
    }

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
                    self.validate_hook_name(ctx, value, string_literal.span);
                }
            }
            Expression::CompositeString(composite_string) => {
                // Only the literal parts are validated; dynamic parts are fine.
                for part in composite_string.parts() {
                    if let StringPart::Literal(literal_part) = part
                        && let Some(value) = literal_part.value
                    {
                        self.validate_hook_name(ctx, value, literal_part.span);
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
    fn validate_hook_name<A>(&self, ctx: &mut LintContext<'_, '_, A>, name: &[u8], span: Span)
    where
        A: Arena,
    {
        let additional_delimiters = self.cfg.additional_word_delimiters.as_bytes();

        let mut has_uppercase = false;
        let mut invalid_delimiters: Vec<u8> = Vec::new();

        for &byte in name {
            if byte.is_ascii_uppercase() {
                has_uppercase = true;
            } else if !byte.is_ascii_lowercase()
                && !byte.is_ascii_digit()
                && byte != b'_'
                // Non-ASCII bytes (e.g. UTF-8 letters) are not treated as delimiters.
                && byte.is_ascii()
                && !additional_delimiters.contains(&byte)
                && !invalid_delimiters.contains(&byte)
            {
                invalid_delimiters.push(byte);
            }
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
            let characters = invalid_delimiters
                .iter()
                .map(|byte| format!("`{}`", (*byte as char).escape_default()))
                .collect::<Vec<_>>()
                .join(", ");

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

    test_lint_failure! {
        name = hex_escaped_uppercase_is_flagged,
        rule = ValidHookNameRule,
        count = 1,
        code = indoc! {r#"
            <?php

            do_action("\x41\x42_hook_{$type}");
        "#}
    }

    test_lint_failure! {
        name = octal_escaped_uppercase_is_flagged,
        rule = ValidHookNameRule,
        count = 1,
        code = indoc! {r#"
            <?php

            do_action("\101\102_hook_{$type}");
        "#}
    }

    test_lint_failure! {
        name = escaped_backslash_in_interpolated_name_is_flagged,
        rule = ValidHookNameRule,
        count = 1,
        code = indoc! {r#"
            <?php

            do_action("myplugin\\action_{$id}");
        "#}
    }

    test_lint_failure! {
        name = ref_array_dispatchers_are_checked,
        rule = ValidHookNameRule,
        count = 2,
        code = indoc! {r"
            <?php

            do_action_ref_array('MyPlugin_Loaded', [$post]);
            apply_filters_ref_array('myplugin-value', [$value]);
        "}
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
