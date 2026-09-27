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
use crate::rule::utils::call::function_call_matches;
use crate::rule_meta::RuleMeta;
use crate::settings::RuleSettings;

const DATE_FUNCTION: &str = "date";
const CURRENT_TIME_FUNCTION: &str = "current_time";

#[derive(Debug, Clone)]
pub struct WpDateTimeRule {
    meta: &'static RuleMeta,
    cfg: WpDateTimeConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct WpDateTimeConfig {
    pub level: Level,
}

impl Default for WpDateTimeConfig {
    fn default() -> Self {
        Self { level: Level::Warning }
    }
}

impl Config for WpDateTimeConfig {
    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for WpDateTimeRule {
    type Config = WpDateTimeConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "WordPress Date Time",
            code: "wp-date-time",
            description: indoc! {"
                Detects date/time handling that conflicts with how WordPress manages timezones.

                `date()` depends on the server's timezone configuration, while WordPress manages
                its own timezone setting. Use `gmdate()` for timezone-independent formatting, or
                `wp_date()` to format in the site's configured timezone.

                `current_time('timestamp')` (or `current_time('U')`) returns a \"local\"
                pseudo-timestamp: a Unix timestamp shifted by the site's UTC offset. Feeding it
                into date math or APIs that expect a true Unix timestamp corrupts the result.
                Use `time()` for a true Unix timestamp, or `current_datetime()` for a
                timezone-aware `DateTimeImmutable` object.
            "},
            good_example: indoc! {r"
                <?php

                $formatted = gmdate('Y-m-d H:i:s');
                $local = wp_date('Y-m-d H:i:s');

                $timestamp = time();
                $now = current_datetime();
                $mysql = current_time('mysql');
            "},
            bad_example: indoc! {r"
                <?php

                $formatted = date('Y-m-d H:i:s');

                $timestamp = current_time('timestamp');
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

        if function_call_matches(ctx, function_call, DATE_FUNCTION) {
            self.report_date(ctx, function_call);
        } else if function_call_matches(ctx, function_call, CURRENT_TIME_FUNCTION)
            && is_timestamp_retrieval(function_call)
        {
            self.report_current_time_timestamp(ctx, function_call);
        }
    }
}

impl WpDateTimeRule {
    fn report_date<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, function_call: &FunctionCall<'arena>)
    where
        A: Arena,
    {
        let issue = Issue::new(self.cfg.level(), "`date()` is affected by the server timezone configuration.")
            .with_code(self.meta.code)
            .with_annotation(
                Annotation::primary(function_call.span())
                    .with_message("`date()` uses the runtime timezone, not the WordPress site timezone"),
            )
            .with_note("WordPress manages its own timezone setting, which `date()` does not respect.")
            .with_help("Use `gmdate()` for timezone-independent output, or `wp_date()` for the site's timezone.");

        ctx.collector.report(issue);
    }

    fn report_current_time_timestamp<'arena, A>(
        &self,
        ctx: &mut LintContext<'_, 'arena, A>,
        function_call: &FunctionCall<'arena>,
    ) where
        A: Arena,
    {
        let issue = Issue::new(
            self.cfg.level(),
            "`current_time()` should not be used to retrieve a timestamp.",
        )
        .with_code(self.meta.code)
        .with_annotation(
            Annotation::primary(function_call.span())
                .with_message("This returns a \"local\" pseudo-timestamp offset from UTC"),
        )
        .with_note(
            "`current_time('timestamp')` returns a Unix timestamp shifted by the site's UTC offset, which corrupts date arithmetic.",
        )
        .with_help("Use `time()` for a true Unix timestamp, or `current_datetime()` for a timezone-aware object.");

        ctx.collector.report(issue);
    }
}

/// Checks whether a `current_time()` call retrieves a (pseudo-)timestamp:
/// the first argument is the literal `'timestamp'` or `'U'`, and the `$gmt`
/// argument is absent or a literal `false`/`0`.
fn is_timestamp_retrieval(function_call: &FunctionCall<'_>) -> bool {
    let arguments = &function_call.argument_list.arguments;

    // Only match a literal, positional first argument; dynamic formats are skipped.
    let Some(Argument::Positional(format_argument)) = arguments.first() else {
        return false;
    };

    let Expression::Literal(Literal::String(format_string)) = &format_argument.value else {
        return false;
    };

    let Some(format) = format_string.value else {
        return false;
    };

    if !format.eq_ignore_ascii_case(b"timestamp") && format != b"U" {
        return false;
    }

    match arguments.get(1) {
        // `$gmt` defaults to `false`, which yields the offset pseudo-timestamp.
        None => true,
        Some(argument) => match argument.value() {
            Expression::Literal(Literal::False(_)) => true,
            Expression::Literal(Literal::Integer(integer)) => integer.value == Some(0),
            _ => false,
        },
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::WpDateTimeRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    test_lint_failure! {
        name = date_call_is_flagged,
        rule = WpDateTimeRule,
        count = 1,
        code = indoc! {r"
            <?php

            $formatted = date('Y-m-d H:i:s');
        "}
    }

    test_lint_failure! {
        name = date_call_with_leading_backslash_is_flagged,
        rule = WpDateTimeRule,
        count = 1,
        code = indoc! {r"
            <?php

            $formatted = \DATE('Y-m-d');
        "}
    }

    test_lint_failure! {
        name = current_time_timestamp_is_flagged,
        rule = WpDateTimeRule,
        count = 1,
        code = indoc! {r"
            <?php

            $timestamp = current_time('timestamp');
        "}
    }

    test_lint_failure! {
        name = current_time_u_format_is_flagged,
        rule = WpDateTimeRule,
        count = 1,
        code = indoc! {r"
            <?php

            $timestamp = current_time('U');
        "}
    }

    test_lint_failure! {
        name = current_time_timestamp_uppercase_is_flagged,
        rule = WpDateTimeRule,
        count = 1,
        code = indoc! {r"
            <?php

            $timestamp = current_time('TIMESTAMP');
        "}
    }

    test_lint_failure! {
        name = current_time_timestamp_with_explicit_false_is_flagged,
        rule = WpDateTimeRule,
        count = 1,
        code = indoc! {r"
            <?php

            $timestamp = current_time('timestamp', false);
        "}
    }

    test_lint_failure! {
        name = current_time_timestamp_with_zero_is_flagged,
        rule = WpDateTimeRule,
        count = 1,
        code = indoc! {r"
            <?php

            $timestamp = current_time('timestamp', 0);
        "}
    }

    test_lint_success! {
        name = gmdate_and_wp_date_are_not_flagged,
        rule = WpDateTimeRule,
        code = indoc! {r"
            <?php

            $utc = gmdate('Y-m-d H:i:s');
            $local = wp_date('Y-m-d H:i:s');
            $i18n = date_i18n('Y-m-d');
        "}
    }

    test_lint_success! {
        name = date_method_calls_are_not_flagged,
        rule = WpDateTimeRule,
        code = indoc! {r"
            <?php

            $formatted = $datetime->date('Y-m-d');
            $other = Carbon::date('Y-m-d');
        "}
    }

    test_lint_success! {
        name = namespaced_date_function_is_not_flagged,
        rule = WpDateTimeRule,
        code = indoc! {r"
            <?php

            use function My\Plugin\date;

            $formatted = date('Y-m-d');
        "}
    }

    test_lint_success! {
        name = current_time_mysql_is_not_flagged,
        rule = WpDateTimeRule,
        code = indoc! {r"
            <?php

            $mysql = current_time('mysql');
            $lower_u = current_time('u');
        "}
    }

    test_lint_success! {
        name = current_time_with_dynamic_format_is_not_flagged,
        rule = WpDateTimeRule,
        code = indoc! {r"
            <?php

            $timestamp = current_time($format);
        "}
    }

    test_lint_success! {
        name = current_time_timestamp_with_gmt_true_is_not_flagged,
        rule = WpDateTimeRule,
        code = indoc! {r"
            <?php

            $timestamp = current_time('timestamp', true);
            $dynamic = current_time('timestamp', $gmt);
        "}
    }
}
