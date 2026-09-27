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
use mago_syntax::cst::Node;
use mago_syntax::cst::NodeKind;
use mago_syntax::cst::Variable;

use crate::category::Category;
use crate::context::LintContext;
use crate::integration::Integration;
use crate::requirements::RuleRequirements;
use crate::rule::Config;
use crate::rule::LintRule;
use crate::rule::utils::variable_usage::function_like_parts;
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
    fn default_enabled() -> bool {
        false
    }

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
                `list()`-destructuring assignments, and `foreach` loop variable
                bindings (e.g. `foreach ($posts as $post)`).
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
        const TARGETS: &[NodeKind] = &[
            NodeKind::Program,
            NodeKind::Function,
            NodeKind::Method,
            NodeKind::Closure,
            NodeKind::ArrowFunction,
            NodeKind::PropertyHook,
        ];

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
                self.scan(ctx, node, &mut None);
            }
            Node::ArrowFunction(arrow_function) => {
                // `global` statements cannot appear in an arrow function, so only
                // `$GLOBALS['...']` writes are relevant here.
                self.scan(ctx, Node::Expression(arrow_function.expression), &mut Some(Vec::new()));
            }
            Node::PropertyHook(_) => {
                // A property hook body is its own function-like scope, reachable
                // only through the class (a scope boundary for the other scans).
                self.scan(ctx, node, &mut Some(Vec::new()));
            }
            _ => {
                let Some(parts) = function_like_parts(node) else {
                    return;
                };

                let mut imports = Some(Vec::new());
                for statement in parts.body.statements.iter() {
                    self.scan(ctx, Node::Statement(statement), &mut imports);
                }
            }
        }
    }
}

impl GlobalVariablesOverrideRule {
    /// Recursively scans for offending assignments, stopping at nested scope
    /// boundaries (they receive their own `check` invocation).
    ///
    /// `imports` is `None` in the global scope; inside a function-like scope it
    /// holds the variables imported by `global` statements seen so far. The
    /// traversal is in source order, so an assignment only sees the imports
    /// that precede it.
    fn scan<'arena, A>(
        &self,
        ctx: &mut LintContext<'_, 'arena, A>,
        node: Node<'_, 'arena>,
        imports: &mut Option<Vec<&'arena [u8]>>,
    ) where
        A: Arena,
    {
        if is_scope_boundary(node.kind()) {
            return;
        }

        match node {
            Node::Global(global) => {
                if let Some(imports) = imports {
                    imports.extend(global.variables.iter().filter_map(|variable| match variable {
                        Variable::Direct(direct) => Some(direct.name),
                        _ => None,
                    }));
                }
            }
            Node::Assignment(assignment) => self.check_assignment(ctx, assignment, imports.as_deref()),
            _ => {}
        }

        node.visit_children(|child| self.scan(ctx, child, imports));
    }

    fn check_assignment<'arena, A>(
        &self,
        ctx: &mut LintContext<'_, 'arena, A>,
        assignment: &Assignment<'arena>,
        imports: Option<&[&'arena [u8]]>,
    ) where
        A: Arena,
    {
        match assignment.lhs {
            Expression::Variable(Variable::Direct(variable)) => {
                let Some(name) = protected_global(variable.name) else {
                    return;
                };

                let overrides_global = match imports {
                    // In the global scope, the variable *is* the WordPress global.
                    None => true,
                    // Inside a function-like scope, only if it was imported with
                    // a `global` statement earlier in the same scope.
                    Some(imports) => imports.contains(&variable.name),
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

                if let Some(name) = key.value.and_then(protected_global) {
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

/// Accepts a variable name (`$post`) or a `$GLOBALS` key, which may be written
/// with or without the `$` prefix.
fn protected_global(name: &[u8]) -> Option<&'static str> {
    let bare = name.strip_prefix(b"$").unwrap_or(name);

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

    test_lint_failure! {
        name = global_import_in_nested_block_is_flagged,
        rule = GlobalVariablesOverrideRule,
        count = 1,
        code = indoc! {r"
            <?php

            function my_plugin_setup() {
                if (is_admin()) {
                    global $wp_query;
                }
                $wp_query = new WP_Query();
            }
        "}
    }

    test_lint_failure! {
        name = override_in_property_hook_is_flagged,
        rule = GlobalVariablesOverrideRule,
        count = 2,
        code = indoc! {r"
            <?php

            class MyPlugin {
                public string $title {
                    set {
                        global $post;
                        $post = get_post(123);
                    }
                    get => $GLOBALS['post'] = get_post(456);
                }
            }
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

    test_lint_success! {
        name = outer_global_import_does_not_leak_into_closure,
        rule = GlobalVariablesOverrideRule,
        code = indoc! {r"
            <?php

            function my_plugin_setup() {
                global $post;
                $callback = function () {
                    $post = get_post(123);
                };
            }
        "}
    }
}
