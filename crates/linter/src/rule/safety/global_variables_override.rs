use indoc::indoc;
use mago_allocator::Arena;
use schemars::JsonSchema;

use mago_reporting::Annotation;
use mago_reporting::Issue;
use mago_reporting::Level;
use mago_span::HasSpan;
use mago_syntax::cst::Assignment;
use mago_syntax::cst::Expression;
use mago_syntax::cst::Literal;
use mago_syntax::cst::MethodBody;
use mago_syntax::cst::Node;
use mago_syntax::cst::NodeKind;
use mago_syntax::cst::Variable;

use crate::category::Category;
use crate::context::LintContext;
use crate::integration::Integration;
use crate::requirements::RuleRequirements;
use crate::rule::Config;
use crate::rule::LintRule;
use crate::rule_meta::RuleMeta;
use crate::settings::RuleSettings;

/// WordPress global variables that must not be overwritten (names without the
/// leading `$`).
const PROTECTED_GLOBALS: &[&str] = &[
    "wpdb",
    "wp_query",
    "wp",
    "post",
    "posts",
    "query_string",
    "wp_rewrite",
    "wp_version",
    "wp_the_query",
    "pagenow",
    "page",
    "paged",
    "authordata",
    "comment",
    "comments",
    "currentday",
    "currentmonth",
    "current_user",
    "current_screen",
    "error",
    "id",
    "locale",
    "more",
    "multipage",
    "numpages",
    "wp_roles",
    "wp_scripts",
    "wp_styles",
    "wp_filter",
    "wp_actions",
    "wp_taxonomies",
    "wp_post_types",
    "wp_widget_factory",
    "allowedtags",
    "allowedposttags",
    "concatenate_scripts",
];

#[derive(Debug, Clone)]
pub struct GlobalVariablesOverrideRule {
    meta: &'static RuleMeta,
    cfg: GlobalVariablesOverrideConfig,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Hash, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct GlobalVariablesOverrideConfig {
    pub level: Level,
}

impl Default for GlobalVariablesOverrideConfig {
    fn default() -> Self {
        Self { level: Level::Error }
    }
}

impl Config for GlobalVariablesOverrideConfig {
    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for GlobalVariablesOverrideRule {
    type Config = GlobalVariablesOverrideConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "Global Variables Override",
            code: "global-variables-override",
            description: indoc! {"
                Flags assignments that overwrite WordPress-protected global variables
                such as `$post`, `$wp_query`, or `$wpdb`. Overwriting these globals
                breaks WordPress core and other plugins in hard-to-debug ways.

                An assignment is flagged when it happens in the top-level (global)
                scope, or inside a function-like scope where the variable was imported
                with a `global` statement. Writes to `$GLOBALS['...']` with a
                protected key are flagged anywhere. Globals in namespaced files are
                still flagged, since PHP globals are process-wide.

                Out of scope (not flagged): writes to array elements or properties of
                a protected global (e.g. `$post->ID = 5`, `$GLOBALS['post']['x'] = 1`),
                and `list()`-destructuring assignments.
            "},
            good_example: indoc! {r#"
                <?php

                function my_plugin_render() {
                    $my_post = get_post(123);
                    echo esc_html($my_post->post_title);
                }
            "#},
            bad_example: indoc! {r#"
                <?php

                function my_plugin_render() {
                    global $post;
                    $post = get_post(123); // Overwrites the WordPress global.
                }
            "#},
            category: Category::Safety,
            requirements: RuleRequirements::Integration(Integration::WordPress),
        };

        &META
    }

    fn targets() -> &'static [NodeKind] {
        const TARGETS: &[NodeKind] =
            &[NodeKind::Program, NodeKind::Function, NodeKind::Method, NodeKind::Closure, NodeKind::ArrowFunction];

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
            Node::Program(_) => {
                // The top-level (global) scope: every assignment to a protected
                // global is flagged. Nested function-like and class-like scopes
                // are skipped here; they receive their own `check` invocation.
                self.scan(ctx, node, None);
            }
            Node::Function(function) => {
                self.check_function_like_body(ctx, function.body.statements.as_slice());
            }
            Node::Method(method) => {
                if let MethodBody::Concrete(block) = &method.body {
                    self.check_function_like_body(ctx, block.statements.as_slice());
                }
            }
            Node::Closure(closure) => {
                self.check_function_like_body(ctx, closure.body.statements.as_slice());
            }
            Node::ArrowFunction(arrow_function) => {
                // `global` statements cannot appear in an arrow function, so only
                // `$GLOBALS['...']` writes are relevant here.
                self.scan(ctx, Node::Expression(arrow_function.expression), Some(&[]));
            }
            _ => {}
        }
    }
}

impl GlobalVariablesOverrideRule {
    fn check_function_like_body<'arena, A>(
        &self,
        ctx: &mut LintContext<'_, 'arena, A>,
        statements: &[mago_syntax::cst::Statement<'arena>],
    ) where
        A: Arena,
    {
        let mut imports: Vec<(&'arena [u8], u32)> = Vec::new();
        for statement in statements {
            collect_global_imports(Node::Statement(statement), &mut imports);
        }

        for statement in statements {
            self.scan(ctx, Node::Statement(statement), Some(imports.as_slice()));
        }
    }

    /// Recursively scans for offending assignments, stopping at nested scope
    /// boundaries (they receive their own `check` invocation).
    fn scan<'arena, A>(
        &self,
        ctx: &mut LintContext<'_, 'arena, A>,
        node: Node<'_, 'arena>,
        imports: Option<&[(&'arena [u8], u32)]>,
    ) where
        A: Arena,
    {
        if is_scope_boundary(node.kind()) {
            return;
        }

        if let Node::Assignment(assignment) = node {
            self.check_assignment(ctx, assignment, imports);
        }

        for child in node.children() {
            self.scan(ctx, child, imports);
        }
    }

    fn check_assignment<'arena, A>(
        &self,
        ctx: &mut LintContext<'_, 'arena, A>,
        assignment: &Assignment<'arena>,
        imports: Option<&[(&'arena [u8], u32)]>,
    ) where
        A: Arena,
    {
        match assignment.lhs {
            Expression::Variable(Variable::Direct(variable)) => {
                let Some(name) = protected_global_from_variable(variable.name) else {
                    return;
                };

                let overrides_global = match imports {
                    // In the global scope, the variable *is* the WordPress global.
                    None => true,
                    // Inside a function-like scope, only if it was imported with
                    // a `global` statement earlier in the same scope.
                    Some(imports) => imports
                        .iter()
                        .any(|(imported, offset)| *imported == variable.name && variable.span.start.offset >= *offset),
                };

                if overrides_global {
                    self.report(ctx, assignment, name);
                }
            }
            Expression::ArrayAccess(array_access) => {
                // `$GLOBALS['post'] = ...` is an override of the global anywhere.
                let Expression::Variable(Variable::Direct(array_variable)) = array_access.array else {
                    return;
                };

                if array_variable.name != b"$GLOBALS" {
                    return;
                }

                let Expression::Literal(Literal::String(key)) = array_access.index else {
                    return;
                };

                if let Some(name) = key.value.and_then(protected_global_from_key) {
                    self.report(ctx, assignment, name);
                }
            }
            _ => {
                // `list()`-destructuring, property writes (`$post->ID = 5`) and
                // array-element writes are conservatively not flagged.
            }
        }
    }

    fn report<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, assignment: &Assignment<'arena>, name: &str)
    where
        A: Arena,
    {
        ctx.collector.report(
            Issue::new(self.cfg.level(), format!("Assignment overwrites the WordPress global variable `${name}`."))
                .with_code(self.meta.code)
                .with_annotation(
                    Annotation::primary(assignment.lhs.span())
                        .with_message(format!("`${name}` is a WordPress global and must not be overwritten")),
                )
                .with_note("WordPress core and other plugins rely on this global; overwriting it can break them in unpredictable ways.")
                .with_help("Use a differently named local variable, or the appropriate WordPress API instead."),
        );
    }
}

const fn is_scope_boundary(kind: NodeKind) -> bool {
    matches!(
        kind,
        NodeKind::Function
            | NodeKind::Method
            | NodeKind::Closure
            | NodeKind::ArrowFunction
            | NodeKind::Class
            | NodeKind::Interface
            | NodeKind::Trait
            | NodeKind::Enum
            | NodeKind::AnonymousClass
    )
}

/// Collects `global $var;` imports within a function-like body, without
/// descending into nested scopes. Records the end offset of each `global`
/// statement so only assignments *after* the import are flagged.
fn collect_global_imports<'arena>(node: Node<'_, 'arena>, imports: &mut Vec<(&'arena [u8], u32)>) {
    if is_scope_boundary(node.kind()) {
        return;
    }

    if let Node::Global(global) = node {
        let end_offset = global.span().end.offset;
        for variable in global.variables.iter() {
            if let Variable::Direct(direct) = variable {
                imports.push((direct.name, end_offset));
            }
        }
    }

    for child in node.children() {
        collect_global_imports(child, imports);
    }
}

fn protected_global_from_variable(name: &[u8]) -> Option<&'static str> {
    let bare = name.strip_prefix(b"$")?;

    PROTECTED_GLOBALS.iter().find(|protected| protected.as_bytes() == bare).copied()
}

fn protected_global_from_key(key: &[u8]) -> Option<&'static str> {
    // The `$GLOBALS` key may be written with or without the `$` prefix.
    let bare = key.strip_prefix(b"$").unwrap_or(key);

    PROTECTED_GLOBALS.iter().find(|protected| protected.as_bytes() == bare).copied()
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::GlobalVariablesOverrideRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    test_lint_failure! {
        name = top_level_override_is_flagged,
        rule = GlobalVariablesOverrideRule,
        count = 1,
        code = indoc! {r"
            <?php

            $post = get_post(123);
        "}
    }

    test_lint_failure! {
        name = top_level_compound_assignment_is_flagged,
        rule = GlobalVariablesOverrideRule,
        count = 1,
        code = indoc! {r"
            <?php

            $wp_version .= '-modified';
        "}
    }

    test_lint_failure! {
        name = override_after_global_import_is_flagged,
        rule = GlobalVariablesOverrideRule,
        count = 1,
        code = indoc! {r"
            <?php

            function my_plugin_setup() {
                global $post;
                $post = get_post(123);
            }
        "}
    }

    test_lint_failure! {
        name = globals_array_write_is_flagged,
        rule = GlobalVariablesOverrideRule,
        count = 1,
        code = indoc! {r"
            <?php

            function my_plugin_setup() {
                $GLOBALS['post'] = get_post(123);
            }
        "}
    }

    test_lint_failure! {
        name = globals_array_write_with_dollar_key_is_flagged,
        rule = GlobalVariablesOverrideRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $GLOBALS['$wp_query'] = new WP_Query();
        "#}
    }

    test_lint_failure! {
        name = namespaced_top_level_is_still_flagged,
        rule = GlobalVariablesOverrideRule,
        count = 1,
        code = indoc! {r"
            <?php

            namespace MyPlugin;

            $wp_query = new \WP_Query();
        "}
    }

    test_lint_failure! {
        name = override_in_method_with_global_import_is_flagged,
        rule = GlobalVariablesOverrideRule,
        count = 1,
        code = indoc! {r"
            <?php

            class MyPlugin {
                public function setup() {
                    global $current_user;
                    $current_user = wp_get_current_user();
                }
            }
        "}
    }

    test_lint_failure! {
        name = nested_top_level_assignment_is_flagged,
        rule = GlobalVariablesOverrideRule,
        count = 1,
        code = indoc! {r"
            <?php

            if (is_admin()) {
                $pagenow = 'index.php';
            }
        "}
    }

    test_lint_failure! {
        name = globals_write_in_arrow_function_is_flagged,
        rule = GlobalVariablesOverrideRule,
        count = 1,
        code = indoc! {r"
            <?php

            $callback = fn() => $GLOBALS['post'] = get_post(123);
        "}
    }

    test_lint_success! {
        name = local_variable_in_function_is_not_flagged,
        rule = GlobalVariablesOverrideRule,
        code = indoc! {r"
            <?php

            function my_plugin_render() {
                $post = get_post(123); // Local variable, not the global.
            }
        "}
    }

    test_lint_success! {
        name = other_variable_names_are_not_flagged,
        rule = GlobalVariablesOverrideRule,
        code = indoc! {r"
            <?php

            $my_post = get_post(123);
        "}
    }

    test_lint_success! {
        name = reading_a_global_is_not_flagged,
        rule = GlobalVariablesOverrideRule,
        code = indoc! {r"
            <?php

            function my_plugin_title() {
                global $post;
                return $post->post_title;
            }
        "}
    }

    test_lint_success! {
        name = property_write_is_not_flagged,
        rule = GlobalVariablesOverrideRule,
        code = indoc! {r"
            <?php

            global $post;
            $post->ID = 5;
        "}
    }

    test_lint_success! {
        name = array_element_write_is_not_flagged,
        rule = GlobalVariablesOverrideRule,
        code = indoc! {r"
            <?php

            function my_plugin_setup() {
                global $wp_filter;
                $wp_filter['init'] = 'something';
            }
        "}
    }

    test_lint_success! {
        name = globals_write_with_other_key_is_not_flagged,
        rule = GlobalVariablesOverrideRule,
        code = indoc! {r"
            <?php

            $GLOBALS['my_plugin_state'] = [];
        "}
    }

    test_lint_success! {
        name = globals_write_with_dynamic_key_is_not_flagged,
        rule = GlobalVariablesOverrideRule,
        code = indoc! {r"
            <?php

            $GLOBALS[$key] = 'value';
        "}
    }

    test_lint_success! {
        name = list_destructuring_is_not_flagged,
        rule = GlobalVariablesOverrideRule,
        code = indoc! {r"
            <?php

            [$post, $page] = my_plugin_get_pair();
        "}
    }

    test_lint_success! {
        name = closure_without_global_import_is_not_flagged,
        rule = GlobalVariablesOverrideRule,
        code = indoc! {r"
            <?php

            $callback = function () {
                $post = get_post(123);
            };
        "}
    }

    test_lint_success! {
        name = arrow_function_variable_assignment_is_not_flagged,
        rule = GlobalVariablesOverrideRule,
        code = indoc! {r"
            <?php

            $callback = fn() => $post = get_post(123);
        "}
    }

    test_lint_success! {
        name = assignment_before_global_import_is_not_flagged,
        rule = GlobalVariablesOverrideRule,
        code = indoc! {r"
            <?php

            function my_plugin_setup() {
                $post = get_post(123); // Still local at this point.
                global $post;
                return $post;
            }
        "}
    }
}
