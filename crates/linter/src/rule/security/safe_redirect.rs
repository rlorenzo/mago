use indoc::indoc;
use mago_allocator::Arena;
use schemars::JsonSchema;

use mago_reporting::Annotation;
use mago_reporting::Issue;
use mago_reporting::Level;
use mago_span::HasSpan;
use mago_syntax::cst::Expression;
use mago_syntax::cst::FunctionCall;
use mago_syntax::cst::Node;
use mago_syntax::cst::NodeKind;

use crate::category::Category;
use crate::context::LintContext;
use crate::integration::Integration;
use crate::requirements::RuleRequirements;
use crate::rule::Config;
use crate::rule::LintRule;
use crate::rule::utils::call::function_call_matches;
use crate::rule_meta::RuleMeta;
use crate::settings::RuleSettings;

#[derive(Debug, Clone)]
pub struct SafeRedirectRule {
    meta: &'static RuleMeta,
    cfg: SafeRedirectConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct SafeRedirectConfig {
    pub level: Level,
}

impl Default for SafeRedirectConfig {
    fn default() -> Self {
        Self { level: Level::Warning }
    }
}

impl Config for SafeRedirectConfig {
    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for SafeRedirectRule {
    type Config = SafeRedirectConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "Safe Redirect",
            code: "safe-redirect",
            description: indoc! {"
                This rule flags every call to `wp_redirect()`. Unlike `wp_safe_redirect()`,
                `wp_redirect()` does not validate the target host, so redirecting to a
                user-influenced URL can enable open-redirect vulnerabilities where visitors
                are silently forwarded to a malicious external site.
            "},
            good_example: indoc! {r"
                <?php

                // wp_safe_redirect() only allows local hosts (plus any hosts added
                // via the `allowed_redirect_hosts` filter).
                wp_safe_redirect(esc_url_raw($_GET['redirect_to'] ?? home_url()));
                exit;
            "},
            bad_example: indoc! {r"
                <?php

                // The target host is not validated; attacker-controlled input can
                // redirect visitors anywhere.
                wp_redirect($_GET['redirect_to']);
                exit;
            "},
            category: Category::Security,
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

        if !is_wp_redirect_call(ctx, function_call) {
            return;
        }

        let issue = Issue::new(self.cfg.level(), "Unsafe redirect using `wp_redirect()`")
            .with_code(self.meta.code)
            .with_annotation(
                Annotation::primary(function_call.span())
                    .with_message("`wp_redirect()` does not validate the target host"),
            )
            .with_note(
                "`wp_redirect()` does not validate the redirect target, which can enable open-redirect vulnerabilities when the URL is user-influenced.",
            )
            .with_help(
                "Use `wp_safe_redirect()` instead, and register additional hosts via the `allowed_redirect_hosts` filter if needed.",
            );

        ctx.collector.report(issue);
    }
}

/// Checks whether the call refers to `wp_redirect`, including fully qualified
/// `\wp_redirect()` calls.
fn is_wp_redirect_call<'arena, A>(ctx: &LintContext<'_, 'arena, A>, call: &FunctionCall<'arena>) -> bool
where
    A: Arena,
{
    if function_call_matches(ctx, call, "wp_redirect") {
        return true;
    }

    let Expression::Identifier(identifier) = call.function else {
        return false;
    };

    let value = identifier.value();
    let value = value.strip_prefix(b"\\").unwrap_or(value);

    value.eq_ignore_ascii_case(b"wp_redirect")
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::SafeRedirectRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    test_lint_failure! {
        name = wp_redirect_is_flagged,
        rule = SafeRedirectRule,
        code = indoc! {r"
            <?php

            wp_redirect('https://example.com');
            exit;
        "}
    }

    test_lint_failure! {
        name = wp_redirect_with_user_input_is_flagged,
        rule = SafeRedirectRule,
        code = indoc! {r"
            <?php

            wp_redirect($_GET['redirect_to'], 302);
        "}
    }

    test_lint_failure! {
        name = fully_qualified_wp_redirect_is_flagged,
        rule = SafeRedirectRule,
        code = indoc! {r"
            <?php

            \wp_redirect(home_url());
        "}
    }

    test_lint_failure! {
        name = uppercase_wp_redirect_is_flagged,
        rule = SafeRedirectRule,
        code = indoc! {r"
            <?php

            WP_Redirect(home_url());
        "}
    }

    test_lint_failure! {
        name = wp_redirect_in_namespace_is_flagged,
        rule = SafeRedirectRule,
        code = indoc! {r"
            <?php

            namespace My\Plugin;

            wp_redirect(home_url());
        "}
    }

    test_lint_success! {
        name = wp_safe_redirect_is_allowed,
        rule = SafeRedirectRule,
        code = indoc! {r"
            <?php

            wp_safe_redirect(home_url());
            exit;
        "}
    }

    test_lint_success! {
        name = fully_qualified_wp_safe_redirect_is_allowed,
        rule = SafeRedirectRule,
        code = indoc! {r"
            <?php

            \wp_safe_redirect($_GET['redirect_to'] ?? home_url());
        "}
    }

    test_lint_success! {
        name = method_named_wp_redirect_is_allowed,
        rule = SafeRedirectRule,
        code = indoc! {r"
            <?php

            $handler->wp_redirect('https://example.com');
        "}
    }

    test_lint_success! {
        name = unrelated_function_is_allowed,
        rule = SafeRedirectRule,
        code = indoc! {r"
            <?php

            my_custom_redirect('https://example.com');
        "}
    }
}
