use indoc::indoc;
use mago_allocator::Arena;
use schemars::JsonSchema;

use mago_reporting::Annotation;
use mago_reporting::Issue;
use mago_reporting::Level;
use mago_span::HasSpan;
use mago_syntax::cst::Expression;
use mago_syntax::cst::FunctionCall;
use mago_syntax::cst::Identifier;
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
pub struct DontExtractRule {
    meta: &'static RuleMeta,
    cfg: DontExtractConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct DontExtractConfig {
    pub level: Level,
}

impl Default for DontExtractConfig {
    fn default() -> Self {
        Self { level: Level::Error }
    }
}

impl Config for DontExtractConfig {
    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for DontExtractRule {
    type Config = DontExtractConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "Don't Extract",
            code: "dont-extract",
            description: indoc! {"
                This rule flags every call to the `extract()` function. `extract()` creates variables
                from arbitrary array keys, which obscures where variables come from and enables
                variable clobbering when the array contains unexpected keys.
            "},
            good_example: indoc! {r"
                <?php

                $args = wp_parse_args($input, ['title' => '', 'count' => 10]);
                $title = $args['title'];
                $count = $args['count'];
            "},
            bad_example: indoc! {r"
                <?php

                // Which variables does this create? Nobody knows.
                extract($args);
            "},
            category: Category::Safety,
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

        if !is_extract_call(ctx, function_call) {
            return;
        }

        let issue = Issue::new(self.cfg.level(), "Do not use `extract()`")
            .with_code(self.meta.code)
            .with_annotation(Annotation::primary(function_call.span()).with_message("`extract()` call detected"))
            .with_note(
                "`extract()` creates variables from arbitrary array keys, obscuring where variables come from and enabling variable clobbering.",
            )
            .with_help("Access array elements explicitly, or use `wp_parse_args()` for defaults merging.");

        ctx.collector.report(issue);
    }
}

/// Checks whether a function call refers to the global `extract()` function.
///
/// PHP function names are case-insensitive, and a leading `\` (fully-qualified
/// reference to the global function) must also match. Qualified calls such as
/// `Util\extract()` refer to a namespaced function and are never matched.
fn is_extract_call<'arena, A>(ctx: &LintContext<'_, 'arena, A>, function_call: &FunctionCall<'arena>) -> bool
where
    A: Arena,
{
    if function_call_matches(ctx, function_call, "extract") {
        return true;
    }

    // `function_call_matches` does not resolve fully-qualified references to
    // global functions (e.g. `\extract()`), so handle them explicitly.
    if let Expression::Identifier(Identifier::FullyQualified(fully_qualified)) = function_call.function
        && let Some(unqualified) = fully_qualified.value.strip_prefix(b"\\")
    {
        return unqualified.eq_ignore_ascii_case(b"extract");
    }

    false
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::DontExtractRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    test_lint_failure! {
        name = extract_call_is_flagged,
        rule = DontExtractRule,
        code = indoc! {r"
            <?php

            extract($args);
        "}
    }

    test_lint_failure! {
        name = fully_qualified_extract_is_flagged,
        rule = DontExtractRule,
        code = indoc! {r"
            <?php

            \extract($args);
        "}
    }

    test_lint_failure! {
        name = extract_is_case_insensitive,
        rule = DontExtractRule,
        code = indoc! {r"
            <?php

            EXTRACT($args);
        "}
    }

    test_lint_failure! {
        name = extract_inside_function_is_flagged,
        rule = DontExtractRule,
        code = indoc! {r"
            <?php

            function render($args) {
                extract($args, EXTR_SKIP);
            }
        "}
    }

    test_lint_failure! {
        name = extract_inside_namespace_is_flagged,
        rule = DontExtractRule,
        code = indoc! {r"
            <?php

            namespace App;

            extract($args);
        "}
    }

    test_lint_success! {
        name = method_call_named_extract_is_not_flagged,
        rule = DontExtractRule,
        code = indoc! {r"
            <?php

            $parser->extract($data);
        "}
    }

    test_lint_success! {
        name = static_call_named_extract_is_not_flagged,
        rule = DontExtractRule,
        code = indoc! {r"
            <?php

            Parser::extract($data);
        "}
    }

    test_lint_success! {
        name = similarly_named_function_is_not_flagged,
        rule = DontExtractRule,
        code = indoc! {r"
            <?php

            extract_data($args);
            my_extract($args);
        "}
    }

    test_lint_success! {
        name = qualified_namespaced_extract_is_not_flagged,
        rule = DontExtractRule,
        code = indoc! {r"
            <?php

            Util\extract($args);
        "}
    }

    test_lint_success! {
        name = imported_namespaced_extract_is_not_flagged,
        rule = DontExtractRule,
        code = indoc! {r"
            <?php

            use function Util\extract;

            extract($args);
        "}
    }
}
