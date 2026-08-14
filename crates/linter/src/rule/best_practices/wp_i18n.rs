use indoc::indoc;
use mago_allocator::Arena;
use schemars::JsonSchema;

use mago_reporting::Annotation;
use mago_reporting::Issue;
use mago_reporting::Level;
use mago_span::HasSpan;
use mago_syntax::cst::Argument;
use mago_syntax::cst::Expression;
use mago_syntax::cst::Literal;
use mago_syntax::cst::Node;
use mago_syntax::cst::NodeKind;

use crate::category::Category;
use crate::context::LintContext;
use crate::integration::Integration;
use crate::requirements::RuleRequirements;
use crate::rule::Config;
use crate::rule::LintRule;
use crate::rule_meta::RuleMeta;
use crate::scope::FunctionLikeScope;
use crate::settings::RuleSettings;

/// Describes which arguments of a WordPress translation function must be literal strings.
struct I18nFunction {
    /// The function name, matched case-sensitively.
    name: &'static str,
    /// Indices of translatable text arguments (two entries for singular/plural pairs).
    text_args: &'static [usize],
    /// Index of the gettext context argument, if the function takes one.
    context_arg: Option<usize>,
    /// Index of the text-domain argument.
    domain_arg: usize,
}

const I18N_FUNCTIONS: &[I18nFunction] = &[
    I18nFunction { name: "__", text_args: &[0], context_arg: None, domain_arg: 1 },
    I18nFunction { name: "_e", text_args: &[0], context_arg: None, domain_arg: 1 },
    I18nFunction { name: "_x", text_args: &[0], context_arg: Some(1), domain_arg: 2 },
    I18nFunction { name: "_ex", text_args: &[0], context_arg: Some(1), domain_arg: 2 },
    I18nFunction { name: "_n", text_args: &[0, 1], context_arg: None, domain_arg: 3 },
    I18nFunction { name: "_nx", text_args: &[0, 1], context_arg: Some(3), domain_arg: 4 },
    I18nFunction { name: "_n_noop", text_args: &[0, 1], context_arg: None, domain_arg: 2 },
    I18nFunction { name: "_nx_noop", text_args: &[0, 1], context_arg: Some(2), domain_arg: 3 },
    I18nFunction { name: "esc_html__", text_args: &[0], context_arg: None, domain_arg: 1 },
    I18nFunction { name: "esc_html_e", text_args: &[0], context_arg: None, domain_arg: 1 },
    I18nFunction { name: "esc_html_x", text_args: &[0], context_arg: Some(1), domain_arg: 2 },
    I18nFunction { name: "esc_attr__", text_args: &[0], context_arg: None, domain_arg: 1 },
    I18nFunction { name: "esc_attr_e", text_args: &[0], context_arg: None, domain_arg: 1 },
    I18nFunction { name: "esc_attr_x", text_args: &[0], context_arg: Some(1), domain_arg: 2 },
    I18nFunction { name: "translate", text_args: &[0], context_arg: None, domain_arg: 1 },
];

#[derive(Debug, Clone)]
pub struct WpI18nRule {
    meta: &'static RuleMeta,
    cfg: WpI18nConfig,
}

#[derive(Debug, Clone, Eq, PartialEq, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct WpI18nConfig {
    pub level: Level,
    pub text_domains: Vec<String>,
}

impl Default for WpI18nConfig {
    fn default() -> Self {
        Self { level: Level::Warning, text_domains: Vec::new() }
    }
}

impl Config for WpI18nConfig {
    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for WpI18nRule {
    type Config = WpI18nConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "WordPress I18n",
            code: "wp-i18n",
            description: indoc! {"
                Validates calls to the WordPress translation functions (`__`, `_e`, `_x`, `_n`,
                `esc_html__`, and friends).

                Translatable text and gettext context arguments must be literal strings so that
                translation tools such as `xgettext` and WP-CLI's `i18n make-pot` can extract them.
                Every call must also pass a literal text domain, and for the plural functions the
                singular and plural strings should use consistent printf-style placeholders.

                The `text-domains` option can be set to a list of allowed text domains; when
                non-empty, any other literal text domain is reported.
            "},
            good_example: indoc! {r#"
                <?php

                $greeting = __('Hello, World!', 'my-plugin');
                $label = _x('Post', 'noun', 'my-plugin');
                $count = sprintf(_n('%d item', '%d items', $number, 'my-plugin'), $number);
            "#},
            bad_example: indoc! {r#"
                <?php

                $greeting = __("Hello, $name!", 'my-plugin'); // interpolated text
                $label = __('Post');                          // missing text domain
                $count = _n('%d item', 'many items', $number, 'my-plugin'); // mismatched placeholders
            "#},
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
        Self { meta: Self::meta(), cfg: settings.config.clone() }
    }

    fn check<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, node: Node<'_, 'arena>)
    where
        A: Arena,
    {
        let Node::FunctionCall(function_call) = node else {
            return;
        };

        let Some(function) = match_i18n_function(function_call.function) else {
            return;
        };

        // Do not flag calls inside the definition of a wrapper function or method
        // that is itself named like a translation function (e.g. a custom `__()`
        // shim that forwards to `translate()`).
        if let Some(FunctionLikeScope::Function(name, _) | FunctionLikeScope::Method(name, _)) =
            ctx.scope.get_function_like_scope()
            && is_i18n_function_name(name)
        {
            return;
        }

        // Only reason about plain positional arguments; bail out on named or
        // spread arguments to avoid false positives.
        if function_call
            .argument_list
            .arguments
            .iter()
            .any(|argument| !matches!(argument, Argument::Positional(positional) if positional.ellipsis.is_none()))
        {
            return;
        }

        let positional_argument = |index: usize| -> Option<&'arena Expression<'arena>> {
            function_call.argument_list.arguments.iter().nth(index).map(|argument| match argument {
                Argument::Positional(positional) => positional.value,
                Argument::Named(named) => named.value,
            })
        };

        for &index in function.text_args {
            if let Some(expression) = positional_argument(index)
                && as_literal_string(expression).is_none()
            {
                let issue = Issue::new(self.cfg.level(), "Translatable text must be a literal string")
                    .with_code(self.meta.code)
                    .with_annotation(
                        Annotation::primary(expression.span())
                            .with_message(format!("This argument to `{}()` is not a literal string", function.name)),
                    )
                    .with_note(
                        "Translation tools statically extract translatable strings from the source code; variables, concatenations, and interpolations cannot be extracted.",
                    )
                    .with_help("Pass a single-quoted or double-quoted literal string without variables, and use `sprintf()` for dynamic values.");

                ctx.collector.report(issue);
            }
        }

        if let Some(context_index) = function.context_arg
            && let Some(expression) = positional_argument(context_index)
            && as_literal_string(expression).is_none()
        {
            let issue = Issue::new(self.cfg.level(), "Translation context must be a literal string")
                .with_code(self.meta.code)
                .with_annotation(
                    Annotation::primary(expression.span())
                        .with_message(format!("The context argument to `{}()` is not a literal string", function.name)),
                )
                .with_note(
                    "The gettext context is extracted statically by translation tools and must be a literal string.",
                )
                .with_help("Pass the context as a literal string, e.g. `'noun'`.");

            ctx.collector.report(issue);
        }

        match positional_argument(function.domain_arg) {
            None => {
                let issue = Issue::new(self.cfg.level(), "Missing text domain in translation function call")
                    .with_code(self.meta.code)
                    .with_annotation(
                        Annotation::primary(function_call.span())
                            .with_message(format!("This call to `{}()` does not pass a text domain", function.name)),
                    )
                    .with_note("Without a text domain, WordPress falls back to the `default` (core) domain and the string will not be translated with your plugin or theme.")
                    .with_help("Pass your plugin or theme text domain as the last argument, e.g. `'my-plugin'`.");

                ctx.collector.report(issue);
            }
            Some(expression) => match as_literal_string(expression) {
                None => {
                    let issue = Issue::new(self.cfg.level(), "Text domain must be a literal string")
                        .with_code(self.meta.code)
                        .with_annotation(Annotation::primary(expression.span()).with_message(format!(
                            "The text domain argument to `{}()` is not a literal string",
                            function.name
                        )))
                        .with_note("Translation tools match strings to a text domain statically; a dynamic text domain cannot be resolved.")
                        .with_help("Pass the text domain as a literal string, e.g. `'my-plugin'`.");

                    ctx.collector.report(issue);
                }
                Some(domain) => {
                    if !self.cfg.text_domains.is_empty()
                        && !self.cfg.text_domains.iter().any(|allowed| allowed.as_bytes() == domain)
                    {
                        let issue = Issue::new(self.cfg.level(), "Unexpected text domain in translation function call")
                            .with_code(self.meta.code)
                            .with_annotation(Annotation::primary(expression.span()).with_message(format!(
                                "The text domain `{}` is not in the configured list",
                                String::from_utf8_lossy(domain)
                            )))
                            .with_note(
                                "The `text-domains` option restricts which text domains may be used in this project.",
                            )
                            .with_help(format!(
                                "Use one of the configured text domains: {}.",
                                self.cfg
                                    .text_domains
                                    .iter()
                                    .map(|domain| format!("`{domain}`"))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ));

                        ctx.collector.report(issue);
                    }
                }
            },
        }

        if let [singular_index, plural_index] = *function.text_args
            && let Some(singular_expression) = positional_argument(singular_index)
            && let Some(plural_expression) = positional_argument(plural_index)
            && let Some(singular) = as_literal_string(singular_expression)
            && let Some(plural) = as_literal_string(plural_expression)
        {
            let singular_placeholders = extract_placeholders(singular);
            let plural_placeholders = extract_placeholders(plural);

            if !is_placeholder_subset(&singular_placeholders, &plural_placeholders)
                && !is_placeholder_subset(&plural_placeholders, &singular_placeholders)
            {
                let issue = Issue::new(self.cfg.level(), "Mismatched placeholders between singular and plural strings")
                    .with_code(self.meta.code)
                    .with_annotation(
                        Annotation::primary(singular_expression.span())
                            .with_message("The singular string uses different placeholders"),
                    )
                    .with_annotation(
                        Annotation::secondary(plural_expression.span())
                            .with_message("...than the plural string"),
                    )
                    .with_note("Singular and plural strings are formatted with the same arguments, so their printf-style placeholders must be compatible.")
                    .with_help("Use the same placeholders in both strings, preferring numbered placeholders such as `%1$s` when there is more than one.");

                ctx.collector.report(issue);
            }
        }
    }
}

/// Matches a function-name expression against the known WordPress translation functions.
///
/// Names are compared case-sensitively. Both unqualified calls (`__('...')`) and
/// leading-backslash fully-qualified calls (`\__('...')`) are matched; calls qualified
/// with a namespace (`Foo\__('...')`) are not.
fn match_i18n_function(function: &Expression<'_>) -> Option<&'static I18nFunction> {
    let Expression::Identifier(identifier) = function else {
        return None;
    };

    let value = identifier.value();
    let name = value.strip_prefix(b"\\".as_slice()).unwrap_or(value);
    if name.contains(&b'\\') {
        return None;
    }

    I18N_FUNCTIONS.iter().find(|function| function.name.as_bytes() == name)
}

/// Checks whether a declared function or method name matches one of the
/// WordPress translation function names.
fn is_i18n_function_name(name: &[u8]) -> bool {
    let name = match memchr::memrchr(b'\\', name) {
        Some(position) => &name[position + 1..],
        None => name,
    };

    I18N_FUNCTIONS.iter().any(|function| function.name.as_bytes() == name)
}

/// Returns the parsed value of the expression if it is a literal string.
fn as_literal_string<'arena>(expression: &Expression<'arena>) -> Option<&'arena [u8]> {
    match expression {
        Expression::Literal(Literal::String(string_literal)) => string_literal.value,
        _ => None,
    }
}

/// Extracts printf-style placeholder tokens (e.g. `%s`, `%d`, `%1$s`) from a string,
/// ignoring the escaped percent sign `%%`.
fn extract_placeholders(text: &[u8]) -> Vec<Vec<u8>> {
    const SPECIFIERS: &[u8] = b"bcdeEfFgGosuxX";

    let mut placeholders = Vec::new();
    let mut index = 0;

    while index < text.len() {
        if text[index] != b'%' {
            index += 1;
            continue;
        }

        if text.get(index + 1) == Some(&b'%') {
            index += 2;
            continue;
        }

        let start = index;
        let mut cursor = index + 1;

        // Optional argument position, e.g. the `1$` in `%1$s`.
        let digits_start = cursor;
        while cursor < text.len() && text[cursor].is_ascii_digit() {
            cursor += 1;
        }
        if cursor == digits_start || text.get(cursor) != Some(&b'$') {
            cursor = digits_start;
        } else {
            cursor += 1;
        }

        if cursor < text.len() && SPECIFIERS.contains(&text[cursor]) {
            cursor += 1;
            placeholders.push(text[start..cursor].to_vec());
            index = cursor;
        } else {
            index += 1;
        }
    }

    placeholders
}

/// Checks whether the placeholder tokens in `subset` are contained in `superset`,
/// comparing as multisets: every distinct token in `subset` must appear in
/// `superset` with the same number of occurrences.
///
/// Requiring equal counts (rather than `<=`) for tokens present on the `subset`
/// side is what catches multiplicity mismatches: with a plain `<=` sub-multiset
/// check, `'%s of %s'` vs `'%s items'` would still be accepted through the
/// reverse subset direction (one `%s` <= two `%s`). Tokens absent from `subset`
/// remain allowed, so `'One item'` vs `'%d items'` is still accepted.
fn is_placeholder_subset(subset: &[Vec<u8>], superset: &[Vec<u8>]) -> bool {
    subset.iter().all(|placeholder| count_occurrences(subset, placeholder) == count_occurrences(superset, placeholder))
}

/// Counts how many times `token` occurs in `tokens`.
fn count_occurrences(tokens: &[Vec<u8>], token: &[u8]) -> usize {
    tokens.iter().filter(|candidate| candidate.as_slice() == token).count()
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::WpI18nRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    test_lint_success! {
        name = literal_text_and_domain,
        rule = WpI18nRule,
        code = indoc! {r"
            <?php

            $greeting = __('Hello, World!', 'my-plugin');
            esc_html_e('Welcome', 'my-plugin');
        "}
    }

    test_lint_success! {
        name = context_functions_with_literals,
        rule = WpI18nRule,
        code = indoc! {r"
            <?php

            $label = _x('Post', 'noun', 'my-plugin');
            _ex('Book', 'verb', 'my-plugin');
            $attr = esc_attr_x('Draft', 'post status', 'my-plugin');
        "}
    }

    test_lint_success! {
        name = plural_with_matching_placeholders,
        rule = WpI18nRule,
        code = indoc! {r"
            <?php

            $text = _n('%d item', '%d items', $count, 'my-plugin');
            $pair = _n_noop('%s post', '%s posts', 'my-plugin');
            $ctx = _nx('%1$s file', '%1$s files', $count, 'uploads', 'my-plugin');
        "}
    }

    test_lint_success! {
        name = singular_without_placeholder_is_allowed,
        rule = WpI18nRule,
        code = indoc! {r"
            <?php

            $text = _n('One item', '%d items', $count, 'my-plugin');
        "}
    }

    test_lint_success! {
        name = fully_qualified_call_with_literals,
        rule = WpI18nRule,
        code = indoc! {r"
            <?php

            $greeting = \__('Hello', 'my-plugin');
        "}
    }

    test_lint_success! {
        name = unrelated_function_is_ignored,
        rule = WpI18nRule,
        code = indoc! {r"
            <?php

            $value = my_helper($variable);
            $other = sprintf('%s items', $count);
        "}
    }

    test_lint_failure! {
        name = variable_text_is_flagged,
        rule = WpI18nRule,
        count = 1,
        code = indoc! {r"
            <?php

            $greeting = __($message, 'my-plugin');
        "}
    }

    test_lint_failure! {
        name = concatenated_text_is_flagged,
        rule = WpI18nRule,
        count = 1,
        code = indoc! {r"
            <?php

            $greeting = __('Hello, ' . $name, 'my-plugin');
        "}
    }

    test_lint_failure! {
        name = interpolated_text_is_flagged,
        rule = WpI18nRule,
        count = 1,
        code = indoc! {r#"
            <?php

            _e("Hello, $name!", 'my-plugin');
        "#}
    }

    test_lint_failure! {
        name = non_literal_context_is_flagged,
        rule = WpI18nRule,
        count = 1,
        code = indoc! {r"
            <?php

            $label = _x('Post', $context, 'my-plugin');
        "}
    }

    test_lint_failure! {
        name = missing_text_domain_is_flagged,
        rule = WpI18nRule,
        count = 1,
        code = indoc! {r"
            <?php

            $greeting = __('Hello, World!');
        "}
    }

    test_lint_failure! {
        name = missing_plural_domain_is_flagged,
        rule = WpI18nRule,
        count = 1,
        code = indoc! {r"
            <?php

            $text = _n('%d item', '%d items', $count);
        "}
    }

    test_lint_failure! {
        name = non_literal_domain_is_flagged,
        rule = WpI18nRule,
        count = 1,
        code = indoc! {r"
            <?php

            $greeting = __('Hello, World!', $domain);
        "}
    }

    test_lint_failure! {
        name = mismatched_placeholders_are_flagged,
        rule = WpI18nRule,
        count = 1,
        code = indoc! {r"
            <?php

            $text = _n('%s item', '%d items', $count, 'my-plugin');
        "}
    }

    test_lint_failure! {
        name = placeholder_multiplicity_mismatch_is_flagged,
        rule = WpI18nRule,
        count = 1,
        code = indoc! {r"
            <?php

            $text = _n('%s of %s', '%s items', $count, 'my-plugin');
        "}
    }

    test_lint_success! {
        name = matching_placeholder_counts_are_allowed,
        rule = WpI18nRule,
        code = indoc! {r"
            <?php

            $text = _n('%s of %s item', '%s of %s items', $count, 'my-plugin');
        "}
    }

    test_lint_success! {
        name = escaped_percent_is_not_a_placeholder,
        rule = WpI18nRule,
        code = indoc! {r"
            <?php

            $text = _n('100%% of %d item', '100%% of %d items', $count, 'my-plugin');
        "}
    }

    test_lint_success! {
        name = allowed_text_domain,
        rule = WpI18nRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.wp_i18n.config.text_domains = vec!["my-plugin".to_string()];
        },
        code = indoc! {r"
            <?php

            $greeting = __('Hello, World!', 'my-plugin');
        "}
    }

    test_lint_failure! {
        name = unexpected_text_domain_is_flagged,
        rule = WpI18nRule,
        count = 1,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.wp_i18n.config.text_domains = vec!["my-plugin".to_string()];
        },
        code = indoc! {r"
            <?php

            $greeting = __('Hello, World!', 'other-plugin');
        "}
    }

    test_lint_success! {
        name = wrapper_function_definition_is_exempt,
        rule = WpI18nRule,
        code = indoc! {r"
            <?php

            function __($text, $domain = 'default') {
                return translate($text, $domain);
            }
        "}
    }

    test_lint_success! {
        name = wrapper_method_definition_is_exempt,
        rule = WpI18nRule,
        code = indoc! {r"
            <?php

            class Translator {
                public function _e($text, $domain = 'default') {
                    _e($text, $domain);
                }
            }
        "}
    }

    test_lint_success! {
        name = translate_method_call_is_ignored,
        rule = WpI18nRule,
        code = indoc! {r"
            <?php

            $result = $translator->translate($key);
            $other = Translator::translate($key);
        "}
    }

    test_lint_success! {
        name = spread_arguments_are_ignored,
        rule = WpI18nRule,
        code = indoc! {r"
            <?php

            $greeting = __(...$args);
        "}
    }

    test_lint_failure! {
        name = multiple_problems_are_all_reported,
        rule = WpI18nRule,
        count = 2,
        code = indoc! {r"
            <?php

            $greeting = __($message);
        "}
    }
}
