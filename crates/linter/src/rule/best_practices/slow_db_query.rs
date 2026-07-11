use indoc::indoc;
use mago_allocator::Arena;
use schemars::JsonSchema;

use mago_reporting::Annotation;
use mago_reporting::Issue;
use mago_reporting::Level;
use mago_span::HasSpan;
use mago_syntax::cst::Argument;
use mago_syntax::cst::ArrayElement;
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
use crate::rule_meta::RuleMeta;
use crate::settings::RuleSettings;

const SLOW_QUERY_KEYS: &[&str] = &["meta_query", "tax_query", "meta_key", "meta_value"];

#[derive(Debug, Clone)]
pub struct SlowDbQueryRule {
    meta: &'static RuleMeta,
    cfg: SlowDbQueryConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct SlowDbQueryConfig {
    pub level: Level,
}

impl Default for SlowDbQueryConfig {
    fn default() -> Self {
        Self { level: Level::Warning }
    }
}

impl Config for SlowDbQueryConfig {
    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for SlowDbQueryRule {
    type Config = SlowDbQueryConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "Slow DB Query",
            code: "slow-db-query",
            description: indoc! {"
                This rule flags query arguments that are known to produce slow database queries:
                `meta_query`, `tax_query`, `meta_key`, and `meta_value` used as array keys
                (or passed to `set_query_var()`). Meta and taxonomy queries run against
                unindexed columns in `wp_postmeta`, so they degrade badly as the site grows.
            "},
            good_example: indoc! {r"
                <?php

                // Query by an indexed, first-class dimension such as a registered taxonomy
                // term (resolved via a cached lookup) or post properties.
                $query = new WP_Query([
                    'post_type'      => 'product',
                    'category_name'  => 'featured',
                    'posts_per_page' => 20,
                ]);
            "},
            bad_example: indoc! {r"
                <?php

                // Meta queries are unindexed and slow at scale.
                $query = new WP_Query([
                    'post_type'  => 'product',
                    'meta_query' => [
                        ['key' => 'featured', 'value' => 'yes'],
                    ],
                ]);
            "},
            category: Category::BestPractices,
            requirements: RuleRequirements::Integration(Integration::WordPress),
        };

        &META
    }

    fn targets() -> &'static [NodeKind] {
        const TARGETS: &[NodeKind] = &[NodeKind::Array, NodeKind::LegacyArray, NodeKind::FunctionCall];

        TARGETS
    }

    fn build(settings: &RuleSettings<Self::Config>) -> Self {
        Self { meta: Self::meta(), cfg: settings.config }
    }

    fn check<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, node: Node<'_, 'arena>)
    where
        A: Arena,
    {
        match node {
            Node::Array(array) => {
                for element in array.elements.iter() {
                    self.check_element(ctx, element);
                }
            }
            Node::LegacyArray(array) => {
                for element in array.elements.iter() {
                    self.check_element(ctx, element);
                }
            }
            Node::FunctionCall(function_call) => {
                self.check_set_query_var(ctx, function_call);
            }
            _ => {}
        }
    }
}

impl SlowDbQueryRule {
    fn check_element<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, element: &ArrayElement<'arena>)
    where
        A: Arena,
    {
        let ArrayElement::KeyValue(key_value) = element else {
            return;
        };

        let Some(key) = get_slow_query_key(key_value.key) else {
            return;
        };

        self.report(ctx, key, key_value.key);
    }

    fn check_set_query_var<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, function_call: &FunctionCall<'arena>)
    where
        A: Arena,
    {
        if !is_set_query_var_call(ctx, function_call) {
            return;
        }

        let Some(Argument::Positional(first_argument)) = function_call.argument_list.arguments.first() else {
            return;
        };

        let Some(key) = get_slow_query_key(first_argument.value) else {
            return;
        };

        self.report(ctx, key, first_argument.value);
    }

    fn report<A>(&self, ctx: &mut LintContext<'_, '_, A>, key: &str, spanned: &impl HasSpan)
    where
        A: Arena,
    {
        let issue = Issue::new(self.cfg.level(), format!("Potentially slow database query using `{key}`"))
            .with_code(self.meta.code)
            .with_annotation(Annotation::primary(spanned.span()).with_message("This query argument is slow at scale"))
            .with_note("Meta and taxonomy queries run against unindexed columns, so they become very slow as the number of posts grows.")
            .with_help(
                "Prefer indexed alternatives: register a taxonomy for filterable values, use a dedicated table for complex lookups, or cache the query results.",
            );

        ctx.collector.report(issue);
    }
}

/// Checks whether the call refers to `set_query_var`, including fully
/// qualified `\set_query_var()` calls.
fn is_set_query_var_call<'arena, A>(ctx: &LintContext<'_, 'arena, A>, call: &FunctionCall<'arena>) -> bool
where
    A: Arena,
{
    if function_call_matches(ctx, call, "set_query_var") {
        return true;
    }

    let Expression::Identifier(identifier) = call.function else {
        return false;
    };

    let value = identifier.value();
    let value = value.strip_prefix(b"\\").unwrap_or(value);

    value.eq_ignore_ascii_case(b"set_query_var")
}

/// Returns the matched slow-query key if the expression is a string literal
/// with one of the flagged names.
fn get_slow_query_key(expression: &Expression) -> Option<&'static str> {
    let Expression::Literal(Literal::String(string_literal)) = expression else {
        return None;
    };

    let value = string_literal.value?;

    SLOW_QUERY_KEYS.iter().find(|key| value == key.as_bytes()).copied()
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::SlowDbQueryRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    test_lint_failure! {
        name = meta_query_key_is_flagged,
        rule = SlowDbQueryRule,
        code = indoc! {r"
            <?php

            $query = new WP_Query([
                'meta_query' => [
                    ['key' => 'featured', 'value' => 'yes'],
                ],
            ]);
        "}
    }

    test_lint_failure! {
        name = tax_query_key_is_flagged,
        rule = SlowDbQueryRule,
        code = indoc! {r"
            <?php

            $args = [
                'tax_query' => [
                    ['taxonomy' => 'genre', 'field' => 'slug', 'terms' => 'jazz'],
                ],
            ];
        "}
    }

    test_lint_failure! {
        name = meta_key_in_legacy_array_is_flagged,
        rule = SlowDbQueryRule,
        code = indoc! {r"
            <?php

            $args = array('meta_key' => 'color', 'post_type' => 'product');
        "}
    }

    test_lint_failure! {
        name = meta_value_key_is_flagged,
        rule = SlowDbQueryRule,
        code = indoc! {r"
            <?php

            $args = ['meta_value' => 'blue'];
        "}
    }

    test_lint_failure! {
        name = nested_meta_query_is_flagged,
        rule = SlowDbQueryRule,
        code = indoc! {r"
            <?php

            $args = ['post_type' => 'post', 'inner' => ['meta_query' => []]];
        "}
    }

    test_lint_failure! {
        name = set_query_var_with_meta_key_is_flagged,
        rule = SlowDbQueryRule,
        code = indoc! {r"
            <?php

            set_query_var('meta_key', 'color');
        "}
    }

    test_lint_failure! {
        name = fully_qualified_set_query_var_is_flagged,
        rule = SlowDbQueryRule,
        code = indoc! {r"
            <?php

            \set_query_var('meta_query', []);
        "}
    }

    test_lint_success! {
        name = regular_query_args_are_allowed,
        rule = SlowDbQueryRule,
        code = indoc! {r"
            <?php

            $query = new WP_Query([
                'post_type'      => 'product',
                'category_name'  => 'featured',
                'posts_per_page' => 20,
            ]);
        "}
    }

    test_lint_success! {
        name = meta_query_as_value_is_allowed,
        rule = SlowDbQueryRule,
        code = indoc! {r"
            <?php

            $keys = ['meta_query', 'tax_query'];
        "}
    }

    test_lint_success! {
        name = set_query_var_with_safe_key_is_allowed,
        rule = SlowDbQueryRule,
        code = indoc! {r"
            <?php

            set_query_var('paged', 2);
        "}
    }

    test_lint_success! {
        name = variable_key_is_allowed,
        rule = SlowDbQueryRule,
        code = indoc! {r"
            <?php

            $args = [$key => 'value'];
        "}
    }
}
