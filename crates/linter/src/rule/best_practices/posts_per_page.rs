use indoc::indoc;
use mago_allocator::Arena;
use schemars::JsonSchema;

use mago_reporting::Annotation;
use mago_reporting::Issue;
use mago_reporting::Level;
use mago_span::HasSpan;
use mago_syntax::cst::ArrayElement;
use mago_syntax::cst::Expression;
use mago_syntax::cst::Literal;
use mago_syntax::cst::Node;
use mago_syntax::cst::NodeKind;
use mago_syntax::cst::UnaryPrefixOperator;

use crate::category::Category;
use crate::context::LintContext;
use crate::integration::Integration;
use crate::requirements::RuleRequirements;
use crate::rule::Config;
use crate::rule::LintRule;
use crate::rule_meta::RuleMeta;
use crate::settings::RuleSettings;

const DEFAULT_MAX_POSTS_PER_PAGE: i64 = 100;

#[derive(Debug, Clone)]
pub struct PostsPerPageRule {
    meta: &'static RuleMeta,
    cfg: PostsPerPageConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct PostsPerPageConfig {
    pub level: Level,
    /// The maximum allowed value for `posts_per_page` / `numberposts`.
    ///
    /// Negative values are invalid and are treated as the default (`100`).
    pub max_posts_per_page: i64,
}

impl Default for PostsPerPageConfig {
    fn default() -> Self {
        Self { level: Level::Warning, max_posts_per_page: DEFAULT_MAX_POSTS_PER_PAGE }
    }
}

impl Config for PostsPerPageConfig {
    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for PostsPerPageRule {
    type Config = PostsPerPageConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "Posts Per Page",
            code: "posts-per-page",
            description: indoc! {"
                This rule flags query arguments that request an unbounded or excessively large
                number of posts: `posts_per_page` or `numberposts` set to `-1` or to a value
                above the configured maximum, and `nopaging` set to `true`. Unbounded queries
                load every matching row into memory and can take a site down as content grows.

                The maximum allowed value can be configured with the `max-posts-per-page`
                option (default: `100`).
            "},
            good_example: indoc! {r"
                <?php

                $query = new WP_Query([
                    'post_type'      => 'post',
                    'posts_per_page' => 20,
                    'paged'          => get_query_var('paged', 1),
                ]);
            "},
            bad_example: indoc! {r"
                <?php

                // Loads every matching post into memory.
                $query = new WP_Query([
                    'post_type'      => 'post',
                    'posts_per_page' => -1,
                ]);
            "},
            category: Category::BestPractices,
            requirements: RuleRequirements::Integration(Integration::WordPress),
        };

        &META
    }

    fn targets() -> &'static [NodeKind] {
        const TARGETS: &[NodeKind] = &[NodeKind::Array, NodeKind::LegacyArray];

        TARGETS
    }

    fn build(settings: &RuleSettings<Self::Config>) -> Self {
        let mut cfg = settings.config;
        if cfg.max_posts_per_page < 0 {
            // A negative maximum is invalid; fall back to the default.
            cfg.max_posts_per_page = DEFAULT_MAX_POSTS_PER_PAGE;
        }

        Self { meta: Self::meta(), cfg }
    }

    fn check<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, node: Node<'_, 'arena>)
    where
        A: Arena,
    {
        let elements = match node {
            Node::Array(array) => &array.elements,
            Node::LegacyArray(array) => &array.elements,
            _ => return,
        };

        for element in elements.iter() {
            let ArrayElement::KeyValue(key_value) = element else {
                continue;
            };

            let Some(key) = get_string_literal_value(key_value.key) else {
                continue;
            };

            if key == b"posts_per_page" || key == b"numberposts" {
                let key_name = if key == b"posts_per_page" { "posts_per_page" } else { "numberposts" };

                match classify_limit_value(key_value.value, self.cfg.max_posts_per_page) {
                    Some(LimitProblem::Unbounded) => {
                        let issue = Issue::new(
                            self.cfg.level(),
                            format!("Unbounded query: `{key_name}` is set to `-1`"),
                        )
                        .with_code(self.meta.code)
                        .with_annotation(
                            Annotation::primary(key_value.span())
                                .with_message("This query fetches every matching post"),
                        )
                        .with_note(
                            "Unbounded queries load every matching row into memory and degrade badly as content grows.",
                        )
                        .with_help(
                            "Paginate the query with a reasonable page size instead of fetching everything at once.",
                        );

                        ctx.collector.report(issue);
                    }
                    Some(LimitProblem::TooLarge) => {
                        let issue = Issue::new(
                            self.cfg.level(),
                            format!(
                                "Excessively large query: `{key_name}` exceeds the maximum of {}",
                                self.cfg.max_posts_per_page
                            ),
                        )
                        .with_code(self.meta.code)
                        .with_annotation(
                            Annotation::primary(key_value.span()).with_message("This query fetches too many posts"),
                        )
                        .with_note(
                            "Huge result sets load every matching row into memory and degrade badly as content grows.",
                        )
                        .with_help(
                            "Paginate the query with a reasonable page size instead of fetching everything at once.",
                        );

                        ctx.collector.report(issue);
                    }
                    None => {}
                }
            } else if key == b"nopaging" && matches!(key_value.value, Expression::Literal(Literal::True(_))) {
                let issue = Issue::new(self.cfg.level(), "Unbounded query: `nopaging` is set to `true`")
                    .with_code(self.meta.code)
                    .with_annotation(
                        Annotation::primary(key_value.span()).with_message("This query fetches every matching post"),
                    )
                    .with_note("Disabling pagination loads every matching row into memory and degrades badly as content grows.")
                    .with_help("Paginate the query with a reasonable page size instead of fetching everything at once.");

                ctx.collector.report(issue);
            }
        }
    }
}

enum LimitProblem {
    /// The value is `-1`, requesting all posts.
    Unbounded,
    /// The value exceeds the configured maximum.
    TooLarge,
}

/// Classifies a `posts_per_page` / `numberposts` value expression.
///
/// Returns `Some(LimitProblem)` if the value is `-1` (integer or string) or a
/// numeric literal greater than `max`, and `None` otherwise.
///
/// `max` is guaranteed to be non-negative: `build()` replaces negative
/// configuration values with the default, so both the integer and the string
/// paths compare against the same limit.
fn classify_limit_value(expression: &Expression, max: i64) -> Option<LimitProblem> {
    debug_assert!(max >= 0, "`build()` must normalize `max_posts_per_page` to a non-negative value");

    match expression {
        Expression::Literal(Literal::Integer(integer)) => match integer.value {
            // An unparseable integer literal overflowed `u64`; it is definitely too large.
            None => Some(LimitProblem::TooLarge),
            Some(value) => {
                if value > max.unsigned_abs() {
                    Some(LimitProblem::TooLarge)
                } else {
                    None
                }
            }
        },
        Expression::UnaryPrefix(unary) if matches!(unary.operator, UnaryPrefixOperator::Negation(_)) => {
            match unary.operand {
                Expression::Literal(Literal::Integer(integer)) if integer.value == Some(1) => {
                    Some(LimitProblem::Unbounded)
                }
                _ => None,
            }
        }
        Expression::Literal(Literal::String(string_literal)) => {
            let value = string_literal.value?;
            let parsed: i64 = std::str::from_utf8(value).ok()?.trim().parse().ok()?;

            if parsed == -1 {
                Some(LimitProblem::Unbounded)
            } else if parsed > max {
                Some(LimitProblem::TooLarge)
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Returns the value of a string literal expression, if it is one.
fn get_string_literal_value<'arena>(expression: &Expression<'arena>) -> Option<&'arena [u8]> {
    match expression {
        Expression::Literal(Literal::String(string_literal)) => string_literal.value,
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::PostsPerPageRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    test_lint_failure! {
        name = posts_per_page_minus_one_is_flagged,
        rule = PostsPerPageRule,
        code = indoc! {r"
            <?php

            $query = new WP_Query(['posts_per_page' => -1]);
        "}
    }

    test_lint_failure! {
        name = posts_per_page_minus_one_string_is_flagged,
        rule = PostsPerPageRule,
        code = indoc! {r"
            <?php

            $query = new WP_Query(['posts_per_page' => '-1']);
        "}
    }

    test_lint_failure! {
        name = posts_per_page_over_limit_is_flagged,
        rule = PostsPerPageRule,
        code = indoc! {r"
            <?php

            $query = new WP_Query(['posts_per_page' => 500]);
        "}
    }

    test_lint_failure! {
        name = posts_per_page_over_limit_string_is_flagged,
        rule = PostsPerPageRule,
        code = indoc! {r"
            <?php

            $query = new WP_Query(['posts_per_page' => '500']);
        "}
    }

    test_lint_failure! {
        name = numberposts_minus_one_is_flagged,
        rule = PostsPerPageRule,
        code = indoc! {r"
            <?php

            $posts = get_posts(array('numberposts' => -1));
        "}
    }

    test_lint_failure! {
        name = nopaging_true_is_flagged,
        rule = PostsPerPageRule,
        code = indoc! {r"
            <?php

            $query = new WP_Query(['nopaging' => true]);
        "}
    }

    test_lint_failure! {
        name = custom_limit_is_respected,
        rule = PostsPerPageRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.posts_per_page.config.max_posts_per_page = 10;
        },
        code = indoc! {r"
            <?php

            $query = new WP_Query(['posts_per_page' => 25]);
        "}
    }

    test_lint_success! {
        name = reasonable_posts_per_page_is_allowed,
        rule = PostsPerPageRule,
        code = indoc! {r"
            <?php

            $query = new WP_Query(['posts_per_page' => 20, 'paged' => 2]);
        "}
    }

    test_lint_success! {
        name = limit_boundary_is_allowed,
        rule = PostsPerPageRule,
        code = indoc! {r"
            <?php

            $query = new WP_Query(['posts_per_page' => 100]);
        "}
    }

    test_lint_success! {
        name = nopaging_false_is_allowed,
        rule = PostsPerPageRule,
        code = indoc! {r"
            <?php

            $query = new WP_Query(['nopaging' => false]);
        "}
    }

    test_lint_success! {
        name = variable_value_is_allowed,
        rule = PostsPerPageRule,
        code = indoc! {r"
            <?php

            $query = new WP_Query(['posts_per_page' => $limit]);
        "}
    }

    test_lint_success! {
        name = negative_max_falls_back_to_default,
        rule = PostsPerPageRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.posts_per_page.config.max_posts_per_page = -5;
        },
        code = indoc! {r"
            <?php

            $query = new WP_Query(['posts_per_page' => 10, 'numberposts' => '10']);
        "}
    }

    test_lint_failure! {
        name = negative_max_still_flags_over_default,
        rule = PostsPerPageRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.posts_per_page.config.max_posts_per_page = -5;
        },
        code = indoc! {r"
            <?php

            $query = new WP_Query(['posts_per_page' => '500']);
        "}
    }

    test_lint_success! {
        name = raised_limit_is_respected,
        rule = PostsPerPageRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.posts_per_page.config.max_posts_per_page = 1000;
        },
        code = indoc! {r"
            <?php

            $query = new WP_Query(['posts_per_page' => 500]);
        "}
    }
}
