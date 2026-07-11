use indoc::indoc;
use mago_allocator::Arena;
use schemars::JsonSchema;

use mago_reporting::Annotation;
use mago_reporting::Issue;
use mago_reporting::Level;
use mago_span::HasSpan;
use mago_syntax::cst::Call;
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
use crate::rule::utils::call::function_call_matches;
use crate::rule::utils::call::function_call_matches_any;
use crate::rule_meta::RuleMeta;
use crate::settings::RuleSettings;

#[derive(Debug, Clone)]
pub struct NoUnescapedOutputRule {
    meta: &'static RuleMeta,
    cfg: NoUnescapedOutputConfig,
}

#[derive(Debug, Clone, Eq, PartialEq, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct NoUnescapedOutputConfig {
    pub level: Level,
    pub custom_escaping_functions: Vec<String>,
    pub custom_auto_escaped_functions: Vec<String>,
}

impl Default for NoUnescapedOutputConfig {
    fn default() -> Self {
        Self { level: Level::Error, custom_escaping_functions: Vec::new(), custom_auto_escaped_functions: Vec::new() }
    }
}

impl Config for NoUnescapedOutputConfig {
    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for NoUnescapedOutputRule {
    type Config = NoUnescapedOutputConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "No Unescaped Output",
            code: "no-unescaped-output",
            description: indoc! {"
                This rule ensures that any variable or function call that is output directly to the page is
                properly escaped. All data must be escaped before printing to prevent Cross-Site Scripting (XSS)
                vulnerabilities.
            "},
            good_example: indoc! {r#"
                <?php

                echo esc_html( $user_comment );
                ?>
                <a href="<?php echo esc_url( $user_provided_url ); ?>">Link</a>
            "#},
            bad_example: indoc! {r"
                <?php

                // This is a major XSS vulnerability.
                echo $_GET['user_comment'];
            "},
            category: Category::Security,
            requirements: RuleRequirements::Integration(Integration::WordPress),
        };

        &META
    }

    fn targets() -> &'static [NodeKind] {
        const TARGETS: &[NodeKind] =
            &[NodeKind::Echo, NodeKind::EchoTag, NodeKind::PrintConstruct, NodeKind::FunctionCall];

        TARGETS
    }

    fn build(settings: &RuleSettings<Self::Config>) -> Self {
        Self { meta: Self::meta(), cfg: settings.config.clone() }
    }

    fn check<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, node: Node<'_, 'arena>)
    where
        A: Arena,
    {
        match node {
            Node::Echo(echo) => {
                // Check each expression in the echo statement
                for expression in &echo.values {
                    if needs_escaping_with_context(expression, Some(ctx), &self.cfg) {
                        self.report_unescaped_output(ctx, expression.span(), "echo statement");
                    }
                }
            }
            Node::EchoTag(echo_tag) => {
                // Check each expression in the echo statement
                for expression in &echo_tag.values {
                    if needs_escaping_with_context(expression, Some(ctx), &self.cfg) {
                        self.report_unescaped_output(ctx, expression.span(), "echo tag");
                    }
                }
            }
            // Check the print construct expression
            Node::PrintConstruct(print_construct)
                if needs_escaping_with_context(print_construct.value, Some(ctx), &self.cfg) =>
            {
                self.report_unescaped_output(ctx, print_construct.value.span(), "print statement");
            }
            Node::FunctionCall(function_call) => {
                // Check printf function - only flag if it has exactly one argument (the format string)
                if function_call.argument_list.arguments.len() == 1
                    && function_call_matches(ctx, function_call, "printf")
                    && let Some(first_arg) =
                        function_call.argument_list.arguments.first().map(mago_syntax::cst::Argument::value)
                    && needs_escaping_with_context(first_arg, Some(ctx), &self.cfg)
                {
                    self.report_unescaped_output(ctx, first_arg.span(), "printf function");
                }
            }
            _ => {}
        }
    }
}

impl NoUnescapedOutputRule {
    fn report_unescaped_output<A>(&self, ctx: &mut LintContext<'_, '_, A>, span: mago_span::Span, context: &str)
    where
        A: Arena,
    {
        let issue = Issue::new(self.cfg.level(), "All output should be escaped to prevent XSS vulnerabilities")
            .with_code(self.meta.code)
            .with_annotation(Annotation::primary(span).with_message(format!("Unescaped output in {context}")))
            .with_note("Unescaped data can lead to Cross-Site Scripting vulnerabilities")
            .with_help("Use `esc_html()`, `esc_attr()`, `esc_url()`, etc.");

        ctx.collector.report(issue);
    }
}

/// Check if an expression needs escaping before output (with context)
fn needs_escaping_with_context<A>(
    expr: &Expression,
    ctx: Option<&LintContext<'_, '_, A>>,
    cfg: &NoUnescapedOutputConfig,
) -> bool
where
    A: Arena,
{
    match expr {
        // Literal strings and numbers are generally safe
        Expression::Literal(Literal::String(_)) => false,
        Expression::Literal(Literal::Integer(_)) => false,
        Expression::Literal(Literal::Float(_)) => false,
        // Variables are potentially unsafe
        Expression::Variable(_) => true,
        // Array access is potentially unsafe
        Expression::ArrayAccess(_) => true,
        // Function calls - check if it's already an escaping function
        Expression::Call(Call::Function(function_call)) => {
            if let Some(context) = ctx {
                !is_escaping_function_call(context, function_call)
                    && !is_custom_safe_function_call(context, function_call, cfg)
            } else {
                // Fallback: if no context, check by identifier value
                if let Expression::Identifier(function_name) = function_call.function {
                    !is_escaping_function(function_name.value()) && !is_custom_safe_function(function_name.value(), cfg)
                } else {
                    true
                }
            }
        }
        // Method calls and property access are potentially unsafe
        Expression::Call(_) => true,
        Expression::Access(_) => true,
        // Binary operations might be unsafe
        Expression::Binary(binary) => {
            needs_escaping_with_context(binary.lhs, ctx, cfg) || needs_escaping_with_context(binary.rhs, ctx, cfg)
        }
        // Conditional expressions might be unsafe
        Expression::Conditional(conditional) => {
            (if let Some(then_expr) = conditional.then {
                needs_escaping_with_context(then_expr, ctx, cfg)
            } else {
                false
            }) || needs_escaping_with_context(conditional.r#else, ctx, cfg)
        }
        // Other expressions are potentially unsafe
        _ => true,
    }
}

/// Check if a function call is a `WordPress` escaping function
fn is_escaping_function_call<A>(ctx: &LintContext<'_, '_, A>, function_call: &FunctionCall) -> bool
where
    A: Arena,
{
    let escaping_functions = [
        "esc_html",
        "esc_attr",
        "esc_url",
        "esc_js",
        "esc_textarea",
        "esc_xml",
        "sanitize_text_field",
        "sanitize_email",
        "sanitize_url",
        "wp_kses",
        "wp_kses_post",
    ];

    for func_name in escaping_functions {
        if function_call_matches(ctx, function_call, func_name) {
            return true;
        }
    }

    false
}

/// Check if a function call matches one of the user-configured safe functions:
/// custom escaping functions (treated like `esc_html()` etc.) or custom
/// auto-escaped functions (their return value is already escaped).
fn is_custom_safe_function_call<A>(
    ctx: &LintContext<'_, '_, A>,
    function_call: &FunctionCall,
    cfg: &NoUnescapedOutputConfig,
) -> bool
where
    A: Arena,
{
    if cfg.custom_escaping_functions.is_empty() && cfg.custom_auto_escaped_functions.is_empty() {
        return false;
    }

    if function_call_matches_any(ctx, function_call, &cfg.custom_escaping_functions).is_some()
        || function_call_matches_any(ctx, function_call, &cfg.custom_auto_escaped_functions).is_some()
    {
        return true;
    }

    // `function_call_matches_any` compares names verbatim, so it misses
    // fully-qualified references at the call site (e.g. `\my_esc()`) and
    // configured names written with a leading `\` (e.g. `"\my_esc"`). Compare
    // the unqualified name directly, stripping a single leading `\` from both
    // sides.
    if let Expression::Identifier(identifier) = function_call.function {
        let name = identifier.value();
        let name = name.strip_prefix(b"\\").unwrap_or(name);

        if !name.contains(&b'\\') {
            return is_custom_safe_function(name, cfg);
        }
    }

    false
}

/// Check if a function name matches one of the user-configured safe functions
/// (case-insensitive, ignoring a single leading `\` on either side).
fn is_custom_safe_function(name: &[u8], cfg: &NoUnescapedOutputConfig) -> bool {
    let name = name.strip_prefix(b"\\").unwrap_or(name);

    cfg.custom_escaping_functions.iter().chain(cfg.custom_auto_escaped_functions.iter()).any(|configured| {
        let configured = configured.as_bytes();
        let configured = configured.strip_prefix(b"\\").unwrap_or(configured);

        name.eq_ignore_ascii_case(configured)
    })
}

/// Check if a function name is a `WordPress` escaping function (fallback without context)
fn is_escaping_function(name: &[u8]) -> bool {
    matches!(
        name,
        b"esc_html"
            | b"esc_attr"
            | b"esc_url"
            | b"esc_js"
            | b"esc_textarea"
            | b"esc_xml"
            | b"sanitize_text_field"
            | b"sanitize_email"
            | b"sanitize_url"
            | b"wp_kses"
            | b"wp_kses_post"
    )
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::NoUnescapedOutputRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    test_lint_success! {
        name = escaped_output_is_safe,
        rule = NoUnescapedOutputRule,
        code = indoc! {r"
            <?php

            echo esc_html($user_comment);
        "}
    }

    test_lint_failure! {
        name = unescaped_echo_tag_is_flagged,
        rule = NoUnescapedOutputRule,
        code = indoc! {r"
            <p><?= $user_comment ?></p>
        "}
    }

    test_lint_success! {
        name = escaped_echo_tag_is_safe,
        rule = NoUnescapedOutputRule,
        code = indoc! {r"
            <p><?= esc_html($user_comment) ?></p>
        "}
    }

    test_lint_success! {
        name = config_with_leading_backslash_matches_unqualified_call,
        rule = NoUnescapedOutputRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.no_unescaped_output.config.custom_escaping_functions = vec!["\\my_esc_html".to_string()];
        },
        code = indoc! {r"
            <?php

            echo my_esc_html($user_comment);
        "}
    }

    test_lint_failure! {
        name = unescaped_variable_is_flagged,
        rule = NoUnescapedOutputRule,
        code = indoc! {r"
            <?php

            echo $user_comment;
        "}
    }

    test_lint_success! {
        name = custom_escaping_function_is_accepted,
        rule = NoUnescapedOutputRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.no_unescaped_output.config.custom_escaping_functions = vec!["my_esc_html".to_string()];
        },
        code = indoc! {r"
            <?php

            echo my_esc_html($user_comment);
        "}
    }

    test_lint_success! {
        name = custom_auto_escaped_function_is_accepted,
        rule = NoUnescapedOutputRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.no_unescaped_output.config.custom_auto_escaped_functions = vec!["get_safe_html".to_string()];
        },
        code = indoc! {r"
            <?php

            echo get_safe_html();
        "}
    }

    test_lint_success! {
        name = custom_escaping_function_is_case_insensitive,
        rule = NoUnescapedOutputRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.no_unescaped_output.config.custom_escaping_functions = vec!["my_esc_html".to_string()];
        },
        code = indoc! {r"
            <?php

            echo My_Esc_Html($user_comment);
        "}
    }

    test_lint_failure! {
        name = unlisted_custom_function_is_still_flagged,
        rule = NoUnescapedOutputRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.no_unescaped_output.config.custom_escaping_functions = vec!["my_esc_html".to_string()];
        },
        code = indoc! {r"
            <?php

            echo some_other_function($user_comment);
        "}
    }

    test_lint_success! {
        name = custom_escaping_function_with_leading_backslash,
        rule = NoUnescapedOutputRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.no_unescaped_output.config.custom_escaping_functions = vec!["my_esc_html".to_string()];
        },
        code = indoc! {r"
            <?php

            echo \my_esc_html($user_comment);
        "}
    }

    test_lint_success! {
        name = custom_auto_escaped_in_print,
        rule = NoUnescapedOutputRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.no_unescaped_output.config.custom_auto_escaped_functions = vec!["get_safe_html".to_string()];
        },
        code = indoc! {r"
            <?php

            print get_safe_html($post_id);
        "}
    }

    test_lint_failure! {
        name = custom_functions_do_not_affect_variables,
        rule = NoUnescapedOutputRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.no_unescaped_output.config.custom_escaping_functions = vec!["my_esc_html".to_string()];
            s.rules.no_unescaped_output.config.custom_auto_escaped_functions = vec!["get_safe_html".to_string()];
        },
        code = indoc! {r"
            <?php

            echo $user_comment;
        "}
    }
}
