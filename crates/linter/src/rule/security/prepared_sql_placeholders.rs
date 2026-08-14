use indoc::indoc;
use mago_allocator::Arena;
use schemars::JsonSchema;

use mago_reporting::Annotation;
use mago_reporting::Issue;
use mago_reporting::Level;
use mago_span::HasSpan;
use mago_syntax::cst::Argument;
use mago_syntax::cst::BinaryOperator;
use mago_syntax::cst::Expression;
use mago_syntax::cst::Literal;
use mago_syntax::cst::Node;
use mago_syntax::cst::NodeKind;
use mago_syntax::cst::StringPart;
use mago_syntax::cst::Variable;

use crate::category::Category;
use crate::context::LintContext;
use crate::integration::Integration;
use crate::requirements::RuleRequirements;
use crate::rule::Config;
use crate::rule::LintRule;
use crate::rule::utils::call::method_name_matches_any;
use crate::rule_meta::RuleMeta;
use crate::settings::RuleSettings;

#[derive(Debug, Clone)]
pub struct PreparedSqlPlaceholdersRule {
    meta: &'static RuleMeta,
    cfg: PreparedSqlPlaceholdersConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct PreparedSqlPlaceholdersConfig {
    pub level: Level,
}

impl Default for PreparedSqlPlaceholdersConfig {
    fn default() -> Self {
        Self { level: Level::Error }
    }
}

impl Config for PreparedSqlPlaceholdersConfig {
    fn default_enabled() -> bool {
        false
    }

    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for PreparedSqlPlaceholdersRule {
    type Config = PreparedSqlPlaceholdersConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "Prepared SQL Placeholders",
            code: "prepared-sql-placeholders",
            description: indoc! {"
                Validates placeholder usage in `$wpdb->prepare()` calls.

                Detects quoted placeholders (e.g. `'%s'` — `prepare()` adds quoting itself),
                unsupported placeholders (only `%s`, `%d`, `%f`, and `%i` are supported),
                mismatches between the number of placeholders and the number of replacement
                arguments, and `prepare()` calls with no placeholders at all.
            "},
            good_example: indoc! {r#"
                <?php

                $wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE post_title = %s AND ID = %d", $title, $id);
            "#},
            bad_example: indoc! {r#"
                <?php

                $wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE post_title = '%s' AND ID = %d", $title);
            "#},
            category: Category::Security,
            requirements: RuleRequirements::Integration(Integration::WordPress),
        };

        &META
    }

    fn targets() -> &'static [NodeKind] {
        const TARGETS: &[NodeKind] = &[NodeKind::MethodCall];

        TARGETS
    }

    fn build(settings: &RuleSettings<Self::Config>) -> Self {
        Self { meta: Self::meta(), cfg: settings.config }
    }

    fn check<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, node: Node<'_, 'arena>)
    where
        A: Arena,
    {
        let Node::MethodCall(method_call) = node else {
            return;
        };

        if !is_wpdb_variable(method_call.object) {
            return;
        }

        if method_name_matches_any(method_call, &["prepare"]).is_none() {
            return;
        }

        let arguments = &method_call.argument_list.arguments;

        let Some((query_index, query_expr)) = arguments
            .iter()
            .enumerate()
            .find_map(|(index, arg)| match arg {
                Argument::Named(named) if named.name.value.eq_ignore_ascii_case(b"query") => Some((index, named.value)),
                _ => None,
            })
            .or_else(|| {
                arguments.first().and_then(|arg| match arg {
                    Argument::Positional(positional) => Some((0, positional.value)),
                    Argument::Named(_) => None,
                })
            })
        else {
            return;
        };

        let mut analysis = QueryAnalysis::new();
        analysis.analyze(query_expr);
        analysis.finish_chunk();

        if !analysis.saw_literal_text {
            // The query is entirely dynamic; the `prepared-sql` rule covers that case.
            return;
        }

        let scan = &analysis.scan;

        if scan.quoted_placeholder {
            let issue = Issue::new(self.cfg.level(), "Placeholder in `$wpdb->prepare()` query must not be quoted")
                .with_code(self.meta.code)
                .with_annotation(
                    Annotation::primary(query_expr.span()).with_message("Quoted placeholder found in this SQL query"),
                )
                .with_note("`$wpdb->prepare()` adds quoting to replaced values itself; quoting the placeholder breaks the escaping.")
                .with_help("Remove the quotes around the placeholder (e.g. use `WHERE name = %s` instead of `WHERE name = '%s'`).");

            ctx.collector.report(issue);
        }

        if scan.has_unsupported() {
            let specifiers = scan.format_unsupported();

            let issue = Issue::new(
                self.cfg.level(),
                format!("Unsupported placeholder in `$wpdb->prepare()` query: {specifiers}"),
            )
            .with_code(self.meta.code)
            .with_annotation(
                Annotation::primary(query_expr.span()).with_message("Unsupported placeholder found in this SQL query"),
            )
            .with_note("`$wpdb->prepare()` only supports the `%s`, `%d`, `%f`, and `%i` placeholders.")
            .with_help("Use `%s` for strings, `%d` for integers, `%f` for floats, or `%i` for identifiers (WP >= 6.2). Use `%%` for a literal percent sign.");

            ctx.collector.report(issue);
        }

        // The count checks are only reliable when the entire query is visible as literal
        // text, and when every placeholder is a supported one (unsupported placeholders
        // were probably intended as replacements, so the intended count is unknowable).
        if !analysis.fully_literal || scan.has_unsupported() {
            return;
        }

        let mut extra_count = 0usize;
        let mut has_spread = false;
        let mut single_extra_value: Option<&Expression<'arena>> = None;

        for (index, argument) in arguments.iter().enumerate() {
            if index == query_index {
                continue;
            }

            extra_count += 1;

            match argument {
                Argument::Positional(positional) => {
                    if positional.ellipsis.is_some() {
                        has_spread = true;
                    }

                    single_extra_value = Some(positional.value);
                }
                Argument::Named(named) => single_extra_value = Some(named.value),
            }
        }

        // Spread arguments make the actual replacement count unknowable.
        if has_spread {
            return;
        }

        let placeholder_count = scan.expected_arguments();

        if placeholder_count == 0 {
            if extra_count == 0 {
                let issue = Issue::new(self.cfg.level(), "`$wpdb->prepare()` called without any placeholders")
                    .with_code(self.meta.code)
                    .with_annotation(
                        Annotation::primary(method_call.span())
                            .with_message("This `prepare()` call has no placeholders to replace"),
                    )
                    .with_note("Calling `$wpdb->prepare()` on a fully-literal query with no placeholders is useless.")
                    .with_help("Pass the query directly to the query method (e.g. `$wpdb->query()`), or add placeholders for the dynamic values.");

                ctx.collector.report(issue);
            }

            return;
        }

        // A single array literal or plain variable may hold all replacement values.
        if extra_count == 1
            && matches!(
                single_extra_value,
                Some(Expression::Array(_) | Expression::LegacyArray(_) | Expression::Variable(_))
            )
        {
            return;
        }

        if extra_count != placeholder_count {
            let issue = Issue::new(
                self.cfg.level(),
                format!(
                    "`$wpdb->prepare()` placeholder count mismatch: {placeholder_count} placeholder(s) but {extra_count} replacement argument(s)",
                ),
            )
            .with_code(self.meta.code)
            .with_annotation(
                Annotation::primary(method_call.span())
                    .with_message(format!("Query expects {placeholder_count} replacement(s), {extra_count} provided")),
            )
            .with_note("Each placeholder in the query must correspond to exactly one replacement argument.")
            .with_help("Pass one replacement argument per placeholder (`%%` is a literal percent sign, not a placeholder).");

            ctx.collector.report(issue);
        }
    }
}

fn is_wpdb_variable(expr: &Expression) -> bool {
    matches!(expr, Expression::Variable(Variable::Direct(var)) if var.name == b"$wpdb")
}

/// Analyzes the literal text segments of a query expression.
///
/// Contiguous literal text (plain literals, adjacent concatenated literals, and the
/// literal parts of interpolated strings) is merged into a chunk which is scanned for
/// placeholders as soon as it ends; every dynamic part ends the current chunk so that
/// placeholder patterns are never matched across dynamic gaps.
struct QueryAnalysis {
    scan: PlaceholderScan,
    current: Vec<u8>,
    fully_literal: bool,
    saw_literal_text: bool,
}

impl QueryAnalysis {
    fn new() -> Self {
        Self { scan: PlaceholderScan::default(), current: Vec::new(), fully_literal: true, saw_literal_text: false }
    }

    fn analyze(&mut self, expr: &Expression) {
        match expr {
            Expression::Literal(Literal::String(string_literal)) => match string_literal.value {
                Some(value) => self.push_literal(value),
                None => self.mark_dynamic(),
            },
            Expression::CompositeString(composite_string) => {
                for part in composite_string.parts() {
                    match part {
                        StringPart::Literal(literal_part) => {
                            self.push_literal(literal_part.value.unwrap_or(literal_part.raw));
                        }
                        StringPart::Expression(_) | StringPart::BracedExpression(_) => {
                            self.mark_dynamic();
                        }
                    }
                }
            }
            Expression::Binary(binary) if matches!(binary.operator, BinaryOperator::StringConcat(_)) => {
                self.analyze(binary.lhs);
                self.analyze(binary.rhs);
            }
            Expression::Parenthesized(parenthesized) => {
                self.analyze(parenthesized.expression);
            }
            _ => self.mark_dynamic(),
        }
    }

    fn push_literal(&mut self, text: &[u8]) {
        // An empty literal (e.g. `prepare("")`) still counts as visible literal text.
        self.saw_literal_text = true;
        self.current.extend_from_slice(text);
    }

    fn mark_dynamic(&mut self) {
        self.fully_literal = false;
        self.finish_chunk();
    }

    fn finish_chunk(&mut self) {
        if !self.current.is_empty() {
            self.scan.scan(&self.current);
            self.current.clear();
        }
    }
}

/// Accumulated results of scanning literal SQL text for `wpdb::prepare()` placeholders.
#[derive(Default)]
struct PlaceholderScan {
    /// Number of un-numbered placeholders (`%s`, `%d`, ...).
    unnumbered: usize,
    /// Highest argnum seen among numbered placeholders (`%1$s`, `%2$d`, ...).
    max_argnum: usize,
    /// Whether any supported placeholder is wrapped in matching quotes.
    quoted_placeholder: bool,
    /// Bitmask of unsupported conversion letters found (`a`-`z` map to bits 0-25,
    /// `A`-`Z` to bits 26-51).
    unsupported_mask: u64,
}

impl PlaceholderScan {
    fn expected_arguments(&self) -> usize {
        self.unnumbered.max(self.max_argnum)
    }

    fn has_unsupported(&self) -> bool {
        self.unsupported_mask != 0
    }

    fn format_unsupported(&self) -> String {
        let mut specifiers = String::new();

        for bit in 0..52u32 {
            if self.unsupported_mask & (1 << bit) == 0 {
                continue;
            }

            let letter = if bit < 26 { b'a' + bit as u8 } else { b'A' + (bit - 26) as u8 };

            if !specifiers.is_empty() {
                specifiers.push_str(", ");
            }

            specifiers.push_str("`%");
            specifiers.push(letter as char);
            specifiers.push('`');
        }

        specifiers
    }

    fn record_unsupported(&mut self, letter: u8) {
        let bit = if letter.is_ascii_lowercase() { letter - b'a' } else { 26 + (letter - b'A') };
        self.unsupported_mask |= 1 << bit;
    }

    fn scan(&mut self, text: &[u8]) {
        let mut i = 0;

        while i < text.len() {
            if text[i] != b'%' {
                i += 1;
                continue;
            }

            // `%%` is a literal percent escape.
            if text.get(i + 1) == Some(&b'%') {
                i += 2;
                continue;
            }

            let mut j = i + 1;

            // Optional argnum prefix: digits followed by `$` (e.g. `%1$s`).
            let mut argnum: Option<usize> = None;
            let digits_start = j;
            while j < text.len() && text[j].is_ascii_digit() {
                j += 1;
            }

            if j > digits_start {
                if text.get(j) == Some(&b'$') {
                    let digits = std::str::from_utf8(&text[digits_start..j]).unwrap_or("0");
                    argnum = digits.parse::<usize>().ok();
                    j += 1;
                } else {
                    // `%` followed by digits without `$` is not a placeholder (e.g. `100%3`).
                    i += 1;
                    continue;
                }
            }

            let Some(&letter) = text.get(j).filter(|byte| byte.is_ascii_alphabetic()) else {
                // A lone `%` (e.g. a `LIKE 'foo%'` wildcard) is not a placeholder.
                i += 1;
                continue;
            };

            if matches!(letter, b's' | b'd' | b'f' | b'i') {
                match argnum {
                    Some(n) => self.max_argnum = self.max_argnum.max(n),
                    None => self.unnumbered += 1,
                }

                // Quoted placeholder: a quote directly before `%` and the same quote
                // directly after the conversion letter.
                if i > 0 && matches!(text[i - 1], b'\'' | b'"') && text.get(j + 1) == Some(&text[i - 1]) {
                    self.quoted_placeholder = true;
                }
            } else {
                self.record_unsupported(letter);
            }

            i = j + 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::PreparedSqlPlaceholdersRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    test_lint_success! {
        name = correct_placeholders_and_arguments,
        rule = PreparedSqlPlaceholdersRule,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE post_title = %s AND ID = %d", $title, $id);
        "#}
    }

    test_lint_success! {
        name = entirely_dynamic_query_is_ignored,
        rule = PreparedSqlPlaceholdersRule,
        code = indoc! {r#"
            <?php

            $wpdb->prepare($sql, $id);
        "#}
    }

    test_lint_success! {
        name = other_methods_are_ignored,
        rule = PreparedSqlPlaceholdersRule,
        code = indoc! {r#"
            <?php

            $wpdb->query("SELECT * FROM my_table WHERE name = '%s'");
            $db->prepare("SELECT * FROM my_table WHERE name = '%s'", $name);
        "#}
    }

    test_lint_failure! {
        name = single_quoted_placeholder,
        rule = PreparedSqlPlaceholdersRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM my_table WHERE name = '%s'", $name);
        "#}
    }

    test_lint_failure! {
        name = double_quoted_placeholder,
        rule = PreparedSqlPlaceholdersRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $wpdb->prepare('SELECT * FROM my_table WHERE ID = "%d"', $id);
        "#}
    }

    test_lint_failure! {
        name = quoted_numbered_placeholder,
        rule = PreparedSqlPlaceholdersRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $wpdb->prepare('SELECT * FROM my_table WHERE name = "%1$s"', $name);
        "#}
    }

    test_lint_failure! {
        name = quoted_placeholder_in_concatenated_literals,
        rule = PreparedSqlPlaceholdersRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM my_table WHERE name = '" . "%s'", $name);
        "#}
    }

    test_lint_failure! {
        name = unsupported_placeholder,
        rule = PreparedSqlPlaceholdersRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM my_table WHERE flags = %x AND name = %s", $flags, $name);
        "#}
    }

    test_lint_failure! {
        name = unsupported_placeholder_in_interpolated_string,
        rule = PreparedSqlPlaceholdersRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE flags = %c", $flags);
        "#}
    }

    test_lint_failure! {
        name = too_few_arguments,
        rule = PreparedSqlPlaceholdersRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM my_table WHERE a = %s AND b = %d AND c = %s", $a, $b);
        "#}
    }

    test_lint_failure! {
        name = too_many_arguments,
        rule = PreparedSqlPlaceholdersRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM my_table WHERE ID = %d", $id, $extra);
        "#}
    }

    test_lint_success! {
        name = numbered_placeholders_counted_by_highest_argnum,
        rule = PreparedSqlPlaceholdersRule,
        code = indoc! {r#"
            <?php

            $wpdb->prepare('SELECT * FROM my_table WHERE a = %1$s AND b = %2$d AND c = %1$s', $a, $b);
        "#}
    }

    test_lint_failure! {
        name = numbered_placeholders_with_too_few_arguments,
        rule = PreparedSqlPlaceholdersRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $wpdb->prepare('SELECT * FROM my_table WHERE a = %1$s AND b = %3$d', $a, $b);
        "#}
    }

    test_lint_success! {
        name = percent_escape_is_not_a_placeholder,
        rule = PreparedSqlPlaceholdersRule,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM my_table WHERE discount = '100%%' AND name = %s", $name);
        "#}
    }

    test_lint_success! {
        name = like_wildcard_is_not_a_placeholder,
        rule = PreparedSqlPlaceholdersRule,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM my_table WHERE name LIKE %s AND slug LIKE 'admin%' AND path LIKE '%'", $like);
        "#}
    }

    test_lint_success! {
        name = array_argument_skips_count_check,
        rule = PreparedSqlPlaceholdersRule,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM my_table WHERE a = %s AND b = %d AND c = %s", [$a, $b, $c]);
        "#}
    }

    test_lint_success! {
        name = single_variable_argument_skips_count_check,
        rule = PreparedSqlPlaceholdersRule,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM my_table WHERE a = %s AND b = %d", $values);
        "#}
    }

    test_lint_success! {
        name = spread_argument_skips_count_check,
        rule = PreparedSqlPlaceholdersRule,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM my_table WHERE a = %s AND b = %d AND c = %s", ...$args);
        "#}
    }

    test_lint_success! {
        name = dynamic_parts_skip_count_check,
        rule = PreparedSqlPlaceholdersRule,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM $table WHERE a = %s $extra_where", $a, $b);
        "#}
    }

    test_lint_failure! {
        name = prepare_without_placeholders,
        rule = PreparedSqlPlaceholdersRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM my_table WHERE status = 'publish'");
        "#}
    }

    test_lint_failure! {
        name = empty_double_quoted_query_is_useless_prepare,
        rule = PreparedSqlPlaceholdersRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("");
        "#}
    }

    test_lint_failure! {
        name = empty_single_quoted_query_is_useless_prepare,
        rule = PreparedSqlPlaceholdersRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $wpdb->prepare('');
        "#}
    }

    test_lint_success! {
        name = no_placeholders_with_interpolation_is_ignored,
        rule = PreparedSqlPlaceholdersRule,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM {$wpdb->posts} WHERE status = 'publish'");
        "#}
    }

    test_lint_failure! {
        name = quoted_and_mismatch_reported_together,
        rule = PreparedSqlPlaceholdersRule,
        count = 2,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM my_table WHERE name = '%s' AND ID = %d", $name, $id, $extra);
        "#}
    }

    test_lint_success! {
        name = identifier_placeholder_is_supported,
        rule = PreparedSqlPlaceholdersRule,
        code = indoc! {r#"
            <?php

            $wpdb->prepare("SELECT * FROM %i WHERE ID = %d", $table, $id);
        "#}
    }

    test_lint_failure! {
        name = named_query_argument_is_checked,
        rule = PreparedSqlPlaceholdersRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $wpdb->prepare(query: "SELECT * FROM my_table WHERE name = '%s'", args: $name);
        "#}
    }
}
