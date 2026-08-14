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

/// Discouraged WordPress functions with the reason and the suggested alternative.
const DISCOURAGED_FUNCTIONS: &[(&str, &str, &str)] = &[
    (
        "query_posts",
        "`query_posts()` replaces and breaks the main query, causing pagination and conditional tag issues.",
        "Use a new `WP_Query` instance, or modify the main query via the `pre_get_posts` filter.",
    ),
    (
        "wp_reset_query",
        "`wp_reset_query()` is only needed after `query_posts()`, which should not be used.",
        "Use `wp_reset_postdata()` after custom `WP_Query` loops instead.",
    ),
    (
        "get_page_by_title",
        "`get_page_by_title()` is deprecated and discouraged.",
        "Use a `WP_Query` with the `title` argument instead.",
    ),
    (
        "url_to_postid",
        "`url_to_postid()` runs an expensive query on every call.",
        "Cache the result (e.g. with the object cache or a transient) instead of calling it repeatedly.",
    ),
    (
        "attachment_url_to_postid",
        "`attachment_url_to_postid()` runs an expensive query on every call.",
        "Cache the result (e.g. with the object cache or a transient) instead of calling it repeatedly.",
    ),
    (
        "wp_is_mobile",
        "`wp_is_mobile()` relies on unreliable user-agent sniffing and breaks with page caching.",
        "Use client-side detection (CSS media queries or JavaScript), or server checks that are safe with caching.",
    ),
];

#[derive(Debug, Clone)]
pub struct DiscouragedWpFunctionsRule {
    meta: &'static RuleMeta,
    cfg: DiscouragedWpFunctionsConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct DiscouragedWpFunctionsConfig {
    pub level: Level,
}

impl Default for DiscouragedWpFunctionsConfig {
    fn default() -> Self {
        Self { level: Level::Warning }
    }
}

impl Config for DiscouragedWpFunctionsConfig {
    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for DiscouragedWpFunctionsRule {
    type Config = DiscouragedWpFunctionsConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "Discouraged WordPress Functions",
            code: "discouraged-wp-functions",
            description: indoc! {"
                This rule flags calls to WordPress functions that are discouraged because they
                break the main query (`query_posts`, `wp_reset_query`), are deprecated
                (`get_page_by_title`), are expensive without caching (`url_to_postid`,
                `attachment_url_to_postid`), or rely on unreliable user-agent sniffing
                (`wp_is_mobile`). Each has a better-supported alternative.
            "},
            good_example: indoc! {r"
                <?php

                $query = new WP_Query(['post_type' => 'post', 'posts_per_page' => 10]);
                while ($query->have_posts()) {
                    $query->the_post();
                    the_title();
                }
                wp_reset_postdata();
            "},
            bad_example: indoc! {r"
                <?php

                query_posts(['post_type' => 'post', 'posts_per_page' => 10]);
                while (have_posts()) {
                    the_post();
                    the_title();
                }
                wp_reset_query();
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

        for (function_name, reason, alternative) in DISCOURAGED_FUNCTIONS {
            if !matches_function(ctx, function_call, function_name) {
                continue;
            }

            let issue = Issue::new(self.cfg.level(), format!("Discouraged WordPress function `{function_name}()`"))
                .with_code(self.meta.code)
                .with_annotation(
                    Annotation::primary(function_call.span())
                        .with_message(format!("`{function_name}()` is discouraged")),
                )
                .with_note(*reason)
                .with_help(*alternative);

            ctx.collector.report(issue);
            return;
        }
    }
}

/// Checks whether the call refers to the given function, including fully
/// qualified calls such as `\query_posts()`.
fn matches_function<'arena, A>(ctx: &LintContext<'_, 'arena, A>, call: &FunctionCall<'arena>, name: &str) -> bool
where
    A: Arena,
{
    if function_call_matches(ctx, call, name) {
        return true;
    }

    let Expression::Identifier(identifier) = call.function else {
        return false;
    };

    let value = identifier.value();
    let value = value.strip_prefix(b"\\").unwrap_or(value);

    value.eq_ignore_ascii_case(name.as_bytes())
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::DiscouragedWpFunctionsRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    test_lint_failure! {
        name = query_posts_is_flagged,
        rule = DiscouragedWpFunctionsRule,
        code = indoc! {r"
            <?php

            query_posts(['post_type' => 'post']);
        "}
    }

    test_lint_failure! {
        name = wp_reset_query_is_flagged,
        rule = DiscouragedWpFunctionsRule,
        code = indoc! {r"
            <?php

            wp_reset_query();
        "}
    }

    test_lint_failure! {
        name = get_page_by_title_is_flagged,
        rule = DiscouragedWpFunctionsRule,
        code = indoc! {r"
            <?php

            $page = get_page_by_title('About Us');
        "}
    }

    test_lint_failure! {
        name = url_to_postid_is_flagged,
        rule = DiscouragedWpFunctionsRule,
        code = indoc! {r"
            <?php

            $post_id = url_to_postid('https://example.com/about/');
        "}
    }

    test_lint_failure! {
        name = attachment_url_to_postid_is_flagged,
        rule = DiscouragedWpFunctionsRule,
        code = indoc! {r"
            <?php

            $attachment_id = attachment_url_to_postid($url);
        "}
    }

    test_lint_failure! {
        name = wp_is_mobile_is_flagged,
        rule = DiscouragedWpFunctionsRule,
        code = indoc! {r"
            <?php

            if (wp_is_mobile()) {
                echo 'mobile';
            }
        "}
    }

    test_lint_failure! {
        name = fully_qualified_call_is_flagged,
        rule = DiscouragedWpFunctionsRule,
        code = indoc! {r"
            <?php

            \query_posts(['post_type' => 'post']);
        "}
    }

    test_lint_failure! {
        name = uppercase_call_is_flagged,
        rule = DiscouragedWpFunctionsRule,
        code = indoc! {r"
            <?php

            WP_Reset_Query();
        "}
    }

    test_lint_success! {
        name = wp_query_is_allowed,
        rule = DiscouragedWpFunctionsRule,
        code = indoc! {r"
            <?php

            $query = new WP_Query(['post_type' => 'post']);
            wp_reset_postdata();
        "}
    }

    test_lint_success! {
        name = method_call_is_allowed,
        rule = DiscouragedWpFunctionsRule,
        code = indoc! {r"
            <?php

            $helper->query_posts(['post_type' => 'post']);
        "}
    }

    test_lint_success! {
        name = unrelated_function_is_allowed,
        rule = DiscouragedWpFunctionsRule,
        code = indoc! {r"
            <?php

            get_posts(['post_type' => 'post']);
        "}
    }
}
