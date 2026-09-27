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

#[derive(Debug, Clone)]
pub struct EnqueuedResourcesRule {
    meta: &'static RuleMeta,
    cfg: EnqueuedResourcesConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct EnqueuedResourcesConfig {
    pub level: Level,
}

impl Default for EnqueuedResourcesConfig {
    fn default() -> Self {
        Self { level: Level::Warning }
    }
}

impl Config for EnqueuedResourcesConfig {
    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for EnqueuedResourcesRule {
    type Config = EnqueuedResourcesConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "Enqueued Resources",
            code: "enqueued-resources",
            description: indoc! {"
                Detects hardcoded `<script src=\"...\">` and `<link rel=\"stylesheet\">` tags in
                string literals and inline HTML. Scripts and stylesheets must be registered through
                the WordPress dependency API (`wp_enqueue_script()` / `wp_enqueue_style()`) so that
                dependencies, versioning, concatenation, and deduplication work correctly.
            "},
            good_example: indoc! {r"
                <?php

                function my_theme_assets() {
                    wp_enqueue_script('my-script', get_template_directory_uri() . '/js/app.js', [], '1.0.0', true);
                    wp_enqueue_style('my-style', get_template_directory_uri() . '/css/app.css', [], '1.0.0');
                }

                add_action('wp_enqueue_scripts', 'my_theme_assets');
            "},
            bad_example: indoc! {r#"
                <?php

                function my_theme_assets() {
                    echo '<script src="https://example.com/js/app.js"></script>';
                    echo '<link rel="stylesheet" href="https://example.com/css/app.css" />';
                }
            "#},
            category: Category::BestPractices,
            requirements: RuleRequirements::Integration(Integration::WordPress),
        };

        &META
    }

    fn targets() -> &'static [NodeKind] {
        const TARGETS: &[NodeKind] = &[NodeKind::LiteralString, NodeKind::LiteralStringPart, NodeKind::Inline];

        TARGETS
    }

    fn build(settings: &RuleSettings<Self::Config>) -> Self {
        Self { meta: Self::meta(), cfg: settings.config }
    }

    fn check<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, node: Node<'_, 'arena>)
    where
        A: Arena,
    {
        // The raw text of each of these nodes maps one-to-one onto its span, so byte
        // offsets into the text can be turned into precise sub-spans for reporting.
        let (text, span) = match node {
            Node::LiteralString(literal) => (literal.raw, literal.span),
            Node::LiteralStringPart(part) => (part.raw, part.span),
            Node::Inline(inline) if inline.kind.is_text() => (inline.value, inline.span),
            _ => return,
        };

        self.scan_text(ctx, text, span);
    }
}

impl EnqueuedResourcesRule {
    fn scan_text<A>(&self, ctx: &mut LintContext<'_, '_, A>, text: &[u8], span: Span)
    where
        A: Arena,
    {
        let lower = text.to_ascii_lowercase();

        for (start, end, tag) in html_tag_occurrences(&lower, b"<script") {
            // Only flag external scripts (`src=`); inline `<script>` blocks are a different concern.
            if !tag_has_attribute(tag, b"src") {
                continue;
            }

            let issue = Issue::new(self.cfg.level(), "Hardcoded `<script>` tag with a `src` attribute")
                .with_code(self.meta.code)
                .with_annotation(
                    Annotation::primary(span.subspan(start as u32, end as u32))
                        .with_message("Script loaded outside the WordPress dependency API"),
                )
                .with_note(
                    "Hardcoded script tags bypass dependency resolution, versioning, and deduplication provided by WordPress.",
                )
                .with_help("Register the script with `wp_enqueue_script()` instead.");

            ctx.collector.report(issue);
        }

        for (start, end, tag) in html_tag_occurrences(&lower, b"<link") {
            // Only flag stylesheet links; e.g. `rel="canonical"` links are fine.
            if !tag_has_stylesheet_rel(tag) {
                continue;
            }

            let issue = Issue::new(self.cfg.level(), "Hardcoded stylesheet `<link>` tag")
                .with_code(self.meta.code)
                .with_annotation(
                    Annotation::primary(span.subspan(start as u32, end as u32))
                        .with_message("Stylesheet loaded outside the WordPress dependency API"),
                )
                .with_note(
                    "Hardcoded stylesheet tags bypass dependency resolution, versioning, and deduplication provided by WordPress.",
                )
                .with_help("Register the stylesheet with `wp_enqueue_style()` instead.");

            ctx.collector.report(issue);
        }
    }
}

/// Yields `(start, end, tag_text)` for each occurrence of an HTML opening tag (e.g. `<script`)
/// in `text`, where `tag_text` runs from the `<` up to (excluding) the next `>` or the end of
/// the text. Occurrences where the tag name continues (e.g. `<scripting`) are skipped.
fn html_tag_occurrences<'text>(
    text: &'text [u8],
    open: &'static [u8],
) -> impl Iterator<Item = (usize, usize, &'text [u8])> {
    memchr::memmem::find_iter(text, open).filter_map(move |start| {
        let name_end = start + open.len();

        // Guard against longer tag names, e.g. `<links>` when searching for `<link`.
        if text.get(name_end).is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'-') {
            return None;
        }

        let end = memchr::memchr(b'>', &text[name_end..]).map_or(text.len(), |offset| name_end + offset);

        Some((start, end, &text[start..end]))
    })
}

/// Checks whether an (already lowercased) tag text contains the attribute `name=`, ignoring
/// whitespace around `=` and requiring an attribute-name boundary before it (so `data-src=`
/// does not count as `src=`).
fn tag_has_attribute(tag: &[u8], name: &[u8]) -> bool {
    attribute_value_offset(tag, name).is_some()
}

/// Finds `name=` as an HTML attribute in the (already lowercased) tag text and returns the
/// offset of the first byte of its value (past `=` and any whitespace around it).
///
/// Quote state is tracked while scanning so text inside a quoted attribute value (e.g.
/// `data-config="src=foo.js"`) is never mistaken for an attribute.
fn attribute_value_offset(tag: &[u8], name: &[u8]) -> Option<usize> {
    let mut index = 0;
    let mut quote: Option<u8> = None;

    while index < tag.len() {
        let byte = tag[index];

        if let Some(open_quote) = quote {
            if byte == open_quote {
                quote = None;
            }

            index += 1;
            continue;
        }

        if byte == b'\'' || byte == b'"' {
            quote = Some(byte);
            index += 1;
            continue;
        }

        if tag[index..].starts_with(name) {
            // An attribute name must be preceded by whitespace (or a quote closing the
            // previous value); this rejects e.g. `data-src` when searching for `src`, as
            // well as the tag name itself.
            let boundary_before = index > 0 && {
                let before = tag[index - 1];
                before.is_ascii_whitespace() || before == b'\'' || before == b'"'
            };

            if boundary_before {
                let mut cursor = index + name.len();
                while tag.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                    cursor += 1;
                }

                if tag.get(cursor) == Some(&b'=') {
                    cursor += 1;
                    while tag.get(cursor).is_some_and(u8::is_ascii_whitespace) {
                        cursor += 1;
                    }

                    return Some(cursor);
                }
            }
        }

        index += 1;
    }

    None
}

/// Checks whether an (already lowercased) `<link ...` tag text declares `rel="stylesheet"`,
/// accepting single quotes, double quotes, no quotes, and whitespace around `=`.
fn tag_has_stylesheet_rel(tag: &[u8]) -> bool {
    let Some(value_offset) = attribute_value_offset(tag, b"rel") else {
        return false;
    };

    let value = &tag[value_offset..];

    if let Some(rest) = value.strip_prefix(b"'") {
        rest.strip_prefix(b"stylesheet").is_some_and(|after| after.starts_with(b"'"))
    } else if let Some(rest) = value.strip_prefix(b"\"") {
        rest.strip_prefix(b"stylesheet").is_some_and(|after| after.starts_with(b"\""))
    } else {
        value
            .strip_prefix(b"stylesheet")
            .is_some_and(|after| !after.first().is_some_and(|byte| byte.is_ascii_alphanumeric() || *byte == b'-'))
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::EnqueuedResourcesRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    test_lint_success! {
        name = wp_enqueue_functions_are_fine,
        rule = EnqueuedResourcesRule,
        code = indoc! {r"
            <?php

            wp_enqueue_script('my-script', 'https://example.com/js/app.js', [], '1.0.0', true);
            wp_enqueue_style('my-style', 'https://example.com/css/app.css', [], '1.0.0');
        "}
    }

    test_lint_success! {
        name = inline_script_without_src_is_fine,
        rule = EnqueuedResourcesRule,
        code = indoc! {r#"
            <?php

            echo '<script>console.log("hello");</script>';
            echo '<script type="text/template">{{ name }}</script>';
        "#}
    }

    test_lint_success! {
        name = non_stylesheet_link_is_fine,
        rule = EnqueuedResourcesRule,
        code = indoc! {r#"
            <?php

            echo '<link rel="canonical" href="https://example.com/page/" />';
            echo '<link rel="preconnect" href="https://fonts.example.com" />';
        "#}
    }

    test_lint_success! {
        name = data_src_attribute_is_fine,
        rule = EnqueuedResourcesRule,
        code = indoc! {r#"
            <?php

            echo '<script data-src="lazy.js"></script>';
        "#}
    }

    test_lint_success! {
        name = attribute_lookalike_inside_quoted_value_is_fine,
        rule = EnqueuedResourcesRule,
        code = indoc! {r#"
            <?php

            echo '<script data-config="src=foo.js"></script>';
            echo '<link href="app.css" data-meta="rel=stylesheet">';
        "#}
    }

    test_lint_success! {
        name = longer_tag_names_are_fine,
        rule = EnqueuedResourcesRule,
        code = indoc! {r#"
            <?php

            echo '<scripting src="not-html.js">';
            echo '<linkage rel="stylesheet">';
        "#}
    }

    test_lint_success! {
        name = plain_text_mentioning_src_is_fine,
        rule = EnqueuedResourcesRule,
        code = indoc! {r#"
            <?php

            $doc = 'Set the src= attribute on your script tag, or use rel="stylesheet".';
        "#}
    }

    test_lint_failure! {
        name = script_tag_with_src,
        rule = EnqueuedResourcesRule,
        count = 1,
        code = indoc! {r#"
            <?php

            echo '<script src="https://example.com/js/app.js"></script>';
        "#}
    }

    test_lint_failure! {
        name = script_tag_with_attributes_before_src,
        rule = EnqueuedResourcesRule,
        count = 1,
        code = indoc! {r#"
            <?php

            echo '<script type="module" src="https://example.com/js/app.mjs"></script>';
        "#}
    }

    test_lint_failure! {
        name = stylesheet_link_tag,
        rule = EnqueuedResourcesRule,
        count = 1,
        code = indoc! {r#"
            <?php

            echo '<link rel="stylesheet" href="https://example.com/css/app.css" />';
        "#}
    }

    test_lint_failure! {
        name = single_quoted_rel_and_uppercase,
        rule = EnqueuedResourcesRule,
        count = 2,
        code = indoc! {r#"
            <?php

            echo "<LINK REL='STYLESHEET' HREF='style.css'>";
            echo "<SCRIPT SRC='app.js'></SCRIPT>";
        "#}
    }

    test_lint_failure! {
        name = interpolated_string_with_script_src,
        rule = EnqueuedResourcesRule,
        count = 1,
        code = indoc! {r#"
            <?php

            echo "<script src='{$url}'></script>";
        "#}
    }

    test_lint_failure! {
        name = heredoc_with_stylesheet_link,
        rule = EnqueuedResourcesRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $html = <<<HTML
            <link rel="stylesheet" href="{$url}" />
            HTML;
        "#}
    }

    test_lint_failure! {
        name = returned_string_with_script_src,
        rule = EnqueuedResourcesRule,
        count = 1,
        code = indoc! {r#"
            <?php

            function footer_scripts() {
                return '<script src="/js/footer.js"></script>';
            }
        "#}
    }

    test_lint_failure! {
        name = inline_html_with_script_src,
        rule = EnqueuedResourcesRule,
        count = 1,
        code = indoc! {r#"
            <?php $title = 'x'; ?>
            <script src="/js/app.js"></script>
        "#}
    }

    test_lint_failure! {
        name = inline_html_with_stylesheet_link,
        rule = EnqueuedResourcesRule,
        count = 1,
        code = indoc! {r#"
            <?php $title = 'x'; ?>
            <link rel=stylesheet href="/css/app.css">
        "#}
    }
}
