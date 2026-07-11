use indoc::indoc;
use mago_allocator::Arena;
use schemars::JsonSchema;

use mago_reporting::Annotation;
use mago_reporting::Issue;
use mago_reporting::Level;
use mago_span::Span;
use mago_syntax::cst::Node;
use mago_syntax::cst::NodeKind;

use crate::category::Category;
use crate::context::LintContext;
use crate::integration::Integration;
use crate::requirements::RuleRequirements;
use crate::rule::Config;
use crate::rule::LintRule;
use crate::rule_meta::RuleMeta;
use crate::settings::RuleSettings;

const CORRECT_SPELLING: &[u8] = b"WordPress";
const LOWERCASE_SPELLING: &[u8] = b"wordpress";
const SPACED_SPELLING: &[u8] = b"word press";

#[derive(Debug, Clone)]
pub struct CapitalPDangitRule {
    meta: &'static RuleMeta,
    cfg: CapitalPDangitConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct CapitalPDangitConfig {
    pub level: Level,
}

impl Default for CapitalPDangitConfig {
    fn default() -> Self {
        Self { level: Level::Note }
    }
}

impl Config for CapitalPDangitConfig {
    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for CapitalPDangitRule {
    type Config = CapitalPDangitConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "Capital P Dangit",
            code: "capital-p-dangit",
            description: indoc! {"
                Detects the misspelling of `WordPress` (such as `Wordpress`, `wordPress`, or
                `Word Press`) in string literals and comments. The correct spelling uses a
                capital `W` and a capital `P`.

                All-lowercase `wordpress` is never flagged, since it is legitimate in slugs,
                URLs, and identifiers. Occurrences inside URLs or class-like tokens
                (e.g. `Wordpress_Plugin`) are also ignored.
            "},
            good_example: indoc! {r"
                <?php

                // WordPress is spelled correctly here.
                $message = 'Welcome to WordPress!';
                $slug = 'my-wordpress-plugin';
            "},
            bad_example: indoc! {r"
                <?php

                // Wordpress is misspelled here.
                $message = 'Welcome to Wordpress!';
            "},
            category: Category::Consistency,
            requirements: RuleRequirements::Integration(Integration::WordPress),
        };

        &META
    }

    fn targets() -> &'static [NodeKind] {
        const TARGETS: &[NodeKind] = &[NodeKind::Program, NodeKind::LiteralString, NodeKind::LiteralStringPart];

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
            Node::Program(program) => {
                for trivia in &program.trivia {
                    if !trivia.kind.is_comment() {
                        continue;
                    }

                    self.scan_text(ctx, trivia.value, trivia.span);
                }
            }
            Node::LiteralString(literal_string) => {
                self.scan_text(ctx, literal_string.value.unwrap_or(literal_string.raw), literal_string.span);
            }
            Node::LiteralStringPart(literal_string_part) => {
                self.scan_text(
                    ctx,
                    literal_string_part.value.unwrap_or(literal_string_part.raw),
                    literal_string_part.span,
                );
            }
            _ => {}
        }
    }
}

impl CapitalPDangitRule {
    fn scan_text<A>(&self, ctx: &mut LintContext<'_, '_, A>, text: &[u8], span: Span)
    where
        A: Arena,
    {
        let lower = text.to_ascii_lowercase();

        for start in memchr::memmem::find_iter(&lower, LOWERCASE_SPELLING) {
            let end = start + LOWERCASE_SPELLING.len();
            let word = &text[start..end];

            // The correct spelling and all-lowercase `wordpress` (legitimate in
            // slugs, URLs, and identifiers) are never flagged.
            if word == CORRECT_SPELLING || word == LOWERCASE_SPELLING {
                continue;
            }

            if !is_standalone_word(text, start, end) || is_inside_url(&lower, start) {
                continue;
            }

            self.report_misspelling(ctx, word, span);
        }

        for start in memchr::memmem::find_iter(&lower, SPACED_SPELLING) {
            let end = start + SPACED_SPELLING.len();

            if !is_standalone_word(text, start, end) || is_inside_url(&lower, start) {
                continue;
            }

            self.report_misspelling(ctx, &text[start..end], span);
        }
    }

    fn report_misspelling<A>(&self, ctx: &mut LintContext<'_, '_, A>, word: &[u8], span: Span)
    where
        A: Arena,
    {
        let word = String::from_utf8_lossy(word);
        let issue = Issue::new(self.cfg.level(), "Misspelled `WordPress`")
            .with_code(self.meta.code)
            .with_annotation(Annotation::primary(span).with_message(format!("`{word}` should be `WordPress`")))
            .with_note("The correct spelling of `WordPress` uses a capital `W` and a capital `P`.")
            .with_help("Replace the misspelling with `WordPress`.");

        ctx.collector.report(issue);
    }
}

/// Returns `true` if the byte is considered part of a word for boundary checks.
///
/// Besides alphanumeric characters, `_`, `-`, `.`, `/`, and `=` are treated as
/// word characters so that slugs, URLs, file paths, query strings, and
/// class-like tokens (e.g. `Wordpress_Plugin`) are never flagged.
fn is_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'/' | b'=')
}

/// Checks that the match at `start..end` is a standalone word: the characters
/// directly before and after must be non-word bytes or the edge of the text.
fn is_standalone_word(text: &[u8], start: usize, end: usize) -> bool {
    let before_ok = start == 0 || !is_word_byte(text[start - 1]);
    let after_ok = end == text.len() || !is_word_byte(text[end]);

    before_ok && after_ok
}

/// Checks whether a URL scheme separator (`://`) appears before the match in
/// the same text, which indicates the match is part of a URL.
fn is_inside_url(lower_text: &[u8], start: usize) -> bool {
    memchr::memmem::find(&lower_text[..start], b"://").is_some()
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::CapitalPDangitRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    test_lint_failure! {
        name = misspelling_in_single_quoted_string,
        rule = CapitalPDangitRule,
        code = indoc! {r"
            <?php

            $message = 'Welcome to Wordpress!';
        "}
    }

    test_lint_failure! {
        name = misspelling_in_double_quoted_string,
        rule = CapitalPDangitRule,
        code = indoc! {r#"
            <?php

            $message = "I love wordPress";
        "#}
    }

    test_lint_failure! {
        name = spaced_misspelling_is_flagged,
        rule = CapitalPDangitRule,
        code = indoc! {r"
            <?php

            $message = 'Powered by Word Press';
        "}
    }

    test_lint_failure! {
        name = lowercase_spaced_misspelling_is_flagged,
        rule = CapitalPDangitRule,
        code = indoc! {r"
            <?php

            $message = 'Powered by word press';
        "}
    }

    test_lint_failure! {
        name = misspelling_in_comment,
        rule = CapitalPDangitRule,
        code = indoc! {r"
            <?php

            // This plugin integrates with Wordpress core.
            $x = 1;
        "}
    }

    test_lint_failure! {
        name = misspelling_in_interpolated_string_part,
        rule = CapitalPDangitRule,
        code = indoc! {r#"
            <?php

            $message = "Hello $name, welcome to Wordpress";
        "#}
    }

    test_lint_failure! {
        name = misspelling_at_string_edges,
        rule = CapitalPDangitRule,
        code = indoc! {r"
            <?php

            $message = 'Wordpress';
        "}
    }

    test_lint_success! {
        name = correct_spelling_is_not_flagged,
        rule = CapitalPDangitRule,
        code = indoc! {r"
            <?php

            // WordPress is spelled correctly.
            $message = 'Welcome to WordPress!';
        "}
    }

    test_lint_success! {
        name = all_lowercase_is_not_flagged,
        rule = CapitalPDangitRule,
        code = indoc! {r"
            <?php

            $slug = 'my-wordpress-site';
            $note = 'installing wordpress here';
        "}
    }

    test_lint_success! {
        name = url_with_scheme_is_not_flagged,
        rule = CapitalPDangitRule,
        code = indoc! {r"
            <?php

            $url = 'See https://Wordpress.org for details';
        "}
    }

    test_lint_success! {
        name = path_adjacent_occurrence_is_not_flagged,
        rule = CapitalPDangitRule,
        code = indoc! {r"
            <?php

            $path = 'visit /Wordpress/ now';
            $query = 'platform=Wordpress';
        "}
    }

    test_lint_success! {
        name = class_like_token_is_not_flagged,
        rule = CapitalPDangitRule,
        code = indoc! {r"
            <?php

            $class = 'Wordpress_Plugin';
        "}
    }

    test_lint_success! {
        name = embedded_in_identifier_is_not_flagged,
        rule = CapitalPDangitRule,
        code = indoc! {r"
            <?php

            $name = 'MyWordpressClass';
            $other = 'WordPressy things';
        "}
    }

    test_lint_success! {
        name = unrelated_text_is_not_flagged,
        rule = CapitalPDangitRule,
        code = indoc! {r"
            <?php

            // A perfectly normal comment about presses.
            $message = 'the printing press changed the world';
        "}
    }
}
