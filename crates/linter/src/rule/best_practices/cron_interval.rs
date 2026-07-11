use indoc::indoc;
use mago_allocator::Arena;
use schemars::JsonSchema;

use mago_reporting::Annotation;
use mago_reporting::Issue;
use mago_reporting::Level;
use mago_span::HasSpan;
use mago_syntax::cst::Argument;
use mago_syntax::cst::ArrayElement;
use mago_syntax::cst::BinaryOperator;
use mago_syntax::cst::Expression;
use mago_syntax::cst::KeyValueArrayElement;
use mago_syntax::cst::Literal;
use mago_syntax::cst::Node;
use mago_syntax::cst::NodeKind;
use mago_syntax::cst::TokenSeparatedSequence;

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
pub struct CronIntervalRule {
    meta: &'static RuleMeta,
    cfg: CronIntervalConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct CronIntervalConfig {
    pub level: Level,
    /// The minimum allowed cron interval, in seconds. Defaults to 900 (15 minutes).
    pub min_interval: i64,
}

impl Default for CronIntervalConfig {
    fn default() -> Self {
        Self { level: Level::Warning, min_interval: 900 }
    }
}

impl Config for CronIntervalConfig {
    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for CronIntervalRule {
    type Config = CronIntervalConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "Cron Interval",
            code: "cron-interval",
            description: indoc! {"
                Flags custom cron schedules registered via `add_filter('cron_schedules', ...)`
                whose `interval` is shorter than the configured minimum (`min-interval`,
                900 seconds / 15 minutes by default). Cron schedules that run too often
                can severely degrade site performance.

                Only inline callbacks (closures and arrow functions) are inspected, and
                only `interval` values that are simple constant integer expressions —
                integer literals, `*`/`+` arithmetic on them, and the WordPress time
                constants `MINUTE_IN_SECONDS`, `HOUR_IN_SECONDS`, and `DAY_IN_SECONDS`.
                Callbacks referenced by name and dynamic interval values are not resolved.
            "},
            good_example: indoc! {r#"
                <?php

                add_filter('cron_schedules', function (array $schedules): array {
                    $schedules['every_30_minutes'] = [
                        'interval' => 30 * MINUTE_IN_SECONDS,
                        'display'  => __('Every 30 minutes'),
                    ];

                    return $schedules;
                });
            "#},
            bad_example: indoc! {r#"
                <?php

                add_filter('cron_schedules', function (array $schedules): array {
                    $schedules['every_minute'] = [
                        'interval' => 60, // Runs far too often.
                        'display'  => __('Every minute'),
                    ];

                    return $schedules;
                });
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
        Self { meta: Self::meta(), cfg: settings.config }
    }

    fn check<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, node: Node<'_, 'arena>)
    where
        A: Arena,
    {
        let Node::FunctionCall(function_call) = node else {
            return;
        };

        if !function_call_matches(ctx, function_call, "add_filter") {
            return;
        }

        let mut positional_arguments =
            function_call.argument_list.arguments.iter().filter_map(|argument| match argument {
                Argument::Positional(positional) => Some(positional.value),
                Argument::Named(_) => None,
            });

        let Some(hook_argument) = positional_arguments.next() else {
            return;
        };

        let Expression::Literal(Literal::String(hook_name)) = hook_argument else {
            return;
        };

        if !matches!(hook_name.value, Some(value) if value == b"cron_schedules") {
            return;
        }

        let Some(callback_argument) = positional_arguments.next() else {
            return;
        };

        match unwrap_parenthesized(callback_argument) {
            Expression::Closure(closure) => {
                for statement in closure.body.statements.iter() {
                    self.scan_for_intervals(ctx, Node::Statement(statement));
                }
            }
            Expression::ArrowFunction(arrow_function) => {
                self.scan_for_intervals(ctx, Node::Expression(arrow_function.expression));
            }
            _ => {
                // Callbacks referenced by name (strings, first-class callables,
                // method references) are not resolved.
            }
        }
    }
}

impl CronIntervalRule {
    /// Recursively looks for array literals containing an `'interval' => ...`
    /// entry, without descending into nested function-like scopes.
    fn scan_for_intervals<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, node: Node<'_, 'arena>)
    where
        A: Arena,
    {
        match node.kind() {
            NodeKind::Function | NodeKind::Method | NodeKind::Closure | NodeKind::ArrowFunction => return,
            _ => {}
        }

        match node {
            Node::Array(array) => self.check_array_elements(ctx, &array.elements),
            Node::LegacyArray(array) => self.check_array_elements(ctx, &array.elements),
            _ => {}
        }

        for child in node.children() {
            self.scan_for_intervals(ctx, child);
        }
    }

    fn check_array_elements<'arena, A>(
        &self,
        ctx: &mut LintContext<'_, 'arena, A>,
        elements: &TokenSeparatedSequence<'arena, ArrayElement<'arena>>,
    ) where
        A: Arena,
    {
        for element in elements.iter() {
            let ArrayElement::KeyValue(KeyValueArrayElement { key, value, .. }) = element else {
                continue;
            };

            let Expression::Literal(Literal::String(key_literal)) = key else {
                continue;
            };

            if !matches!(key_literal.value, Some(value) if value == b"interval") {
                continue;
            }

            let Some(interval) = evaluate_constant_integer(value) else {
                continue;
            };

            if interval >= self.cfg.min_interval {
                continue;
            }

            ctx.collector.report(
                Issue::new(
                    self.cfg.level(),
                    format!(
                        "Cron schedule interval of {interval} seconds is below the minimum of {} seconds.",
                        self.cfg.min_interval
                    ),
                )
                .with_code(self.meta.code)
                .with_annotation(
                    Annotation::primary(value.span())
                        .with_message(format!("This interval evaluates to {interval} seconds")),
                )
                .with_note("Cron schedules that run too frequently can severely degrade site performance.")
                .with_help(
                    "Use a longer interval (15 minutes or more), or adjust the `min-interval` option if this frequency is intentional.",
                ),
            );
        }
    }
}

fn unwrap_parenthesized<'arena>(expression: &'arena Expression<'arena>) -> &'arena Expression<'arena> {
    match expression {
        Expression::Parenthesized(parenthesized) => unwrap_parenthesized(parenthesized.expression),
        _ => expression,
    }
}

/// Evaluates simple constant integer expressions: integer literals, `*`/`+`
/// arithmetic on them, and the WordPress time constants `MINUTE_IN_SECONDS`,
/// `HOUR_IN_SECONDS`, and `DAY_IN_SECONDS`. Anything else yields `None`.
fn evaluate_constant_integer(expression: &Expression<'_>) -> Option<i64> {
    match expression {
        Expression::Literal(Literal::Integer(integer)) => integer.value.and_then(|value| i64::try_from(value).ok()),
        Expression::Parenthesized(parenthesized) => evaluate_constant_integer(parenthesized.expression),
        Expression::ConstantAccess(constant_access) => {
            let name = constant_access.name.value();
            let name = name.strip_prefix(b"\\").unwrap_or(name);

            match name {
                b"MINUTE_IN_SECONDS" => Some(60),
                b"HOUR_IN_SECONDS" => Some(3600),
                b"DAY_IN_SECONDS" => Some(86400),
                _ => None,
            }
        }
        Expression::Binary(binary) => {
            let lhs = evaluate_constant_integer(binary.lhs)?;
            let rhs = evaluate_constant_integer(binary.rhs)?;

            match binary.operator {
                BinaryOperator::Multiplication(_) => lhs.checked_mul(rhs),
                BinaryOperator::Addition(_) => lhs.checked_add(rhs),
                _ => None,
            }
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::CronIntervalRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    test_lint_failure! {
        name = closure_with_low_interval_is_flagged,
        rule = CronIntervalRule,
        count = 1,
        code = indoc! {r"
            <?php

            add_filter('cron_schedules', function ($schedules) {
                $schedules['every_minute'] = [
                    'interval' => 60,
                    'display'  => 'Every Minute',
                ];

                return $schedules;
            });
        "}
    }

    test_lint_failure! {
        name = arrow_function_with_low_interval_is_flagged,
        rule = CronIntervalRule,
        count = 1,
        code = indoc! {r"
            <?php

            add_filter('cron_schedules', fn($schedules) => array_merge($schedules, [
                'every_five_minutes' => [
                    'interval' => 5 * 60,
                    'display'  => 'Every 5 Minutes',
                ],
            ]));
        "}
    }

    test_lint_failure! {
        name = minute_in_seconds_constant_is_recognized,
        rule = CronIntervalRule,
        count = 1,
        code = indoc! {r"
            <?php

            add_filter('cron_schedules', function ($schedules) {
                $schedules['every_minute'] = [
                    'interval' => MINUTE_IN_SECONDS,
                    'display'  => 'Every Minute',
                ];

                return $schedules;
            });
        "}
    }

    test_lint_failure! {
        name = arithmetic_with_constant_is_evaluated,
        rule = CronIntervalRule,
        count = 1,
        code = indoc! {r"
            <?php

            add_filter('cron_schedules', function ($schedules) {
                $schedules['every_two_minutes'] = [
                    'interval' => 2 * MINUTE_IN_SECONDS,
                    'display'  => 'Every 2 Minutes',
                ];

                return $schedules;
            });
        "}
    }

    test_lint_failure! {
        name = legacy_array_syntax_is_checked,
        rule = CronIntervalRule,
        count = 1,
        code = indoc! {r"
            <?php

            add_filter('cron_schedules', function ($schedules) {
                $schedules['every_30_seconds'] = array(
                    'interval' => 30,
                    'display'  => 'Every 30 Seconds',
                );

                return $schedules;
            });
        "}
    }

    test_lint_failure! {
        name = addition_expression_is_evaluated,
        rule = CronIntervalRule,
        count = 1,
        code = indoc! {r"
            <?php

            add_filter('cron_schedules', function ($schedules) {
                $schedules['odd_schedule'] = [
                    'interval' => 60 + 60,
                    'display'  => 'Every 2 Minutes',
                ];

                return $schedules;
            });
        "}
    }

    test_lint_success! {
        name = interval_at_minimum_is_allowed,
        rule = CronIntervalRule,
        code = indoc! {r"
            <?php

            add_filter('cron_schedules', function ($schedules) {
                $schedules['every_15_minutes'] = [
                    'interval' => 900,
                    'display'  => 'Every 15 Minutes',
                ];

                return $schedules;
            });
        "}
    }

    test_lint_success! {
        name = hour_in_seconds_constant_is_allowed,
        rule = CronIntervalRule,
        code = indoc! {r"
            <?php

            add_filter('cron_schedules', function ($schedules) {
                $schedules['hourly_custom'] = [
                    'interval' => HOUR_IN_SECONDS,
                    'display'  => 'Every Hour',
                ];

                return $schedules;
            });
        "}
    }

    test_lint_success! {
        name = constant_arithmetic_above_minimum_is_allowed,
        rule = CronIntervalRule,
        code = indoc! {r"
            <?php

            add_filter('cron_schedules', function ($schedules) {
                $schedules['every_30_minutes'] = [
                    'interval' => 30 * MINUTE_IN_SECONDS,
                    'display'  => 'Every 30 Minutes',
                ];

                return $schedules;
            });
        "}
    }

    test_lint_success! {
        name = variable_interval_is_skipped,
        rule = CronIntervalRule,
        code = indoc! {r"
            <?php

            add_filter('cron_schedules', function ($schedules) use ($interval) {
                $schedules['custom'] = [
                    'interval' => $interval,
                    'display'  => 'Custom',
                ];

                return $schedules;
            });
        "}
    }

    test_lint_success! {
        name = function_call_interval_is_skipped,
        rule = CronIntervalRule,
        code = indoc! {r"
            <?php

            add_filter('cron_schedules', function ($schedules) {
                $schedules['custom'] = [
                    'interval' => (int) get_option('my_plugin_interval'),
                    'display'  => 'Custom',
                ];

                return $schedules;
            });
        "}
    }

    test_lint_success! {
        name = unknown_constant_is_skipped,
        rule = CronIntervalRule,
        code = indoc! {r"
            <?php

            add_filter('cron_schedules', function ($schedules) {
                $schedules['custom'] = [
                    'interval' => MY_PLUGIN_CRON_INTERVAL,
                    'display'  => 'Custom',
                ];

                return $schedules;
            });
        "}
    }

    test_lint_success! {
        name = string_callback_is_not_resolved,
        rule = CronIntervalRule,
        code = indoc! {r"
            <?php

            add_filter('cron_schedules', 'my_plugin_cron_schedules');
        "}
    }

    test_lint_success! {
        name = other_filters_are_ignored,
        rule = CronIntervalRule,
        code = indoc! {r"
            <?php

            add_filter('the_content', function ($content) {
                return ['interval' => 1, 'content' => $content];
            });
        "}
    }

    test_lint_success! {
        name = non_literal_hook_name_is_skipped,
        rule = CronIntervalRule,
        code = indoc! {r"
            <?php

            add_filter($hook, function ($schedules) {
                $schedules['custom'] = ['interval' => 1];

                return $schedules;
            });
        "}
    }

    test_lint_success! {
        name = configured_minimum_is_respected,
        rule = CronIntervalRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.cron_interval.config.min_interval = 60;
        },
        code = indoc! {r"
            <?php

            add_filter('cron_schedules', function ($schedules) {
                $schedules['every_minute'] = [
                    'interval' => 60,
                    'display'  => 'Every Minute',
                ];

                return $schedules;
            });
        "}
    }
}
