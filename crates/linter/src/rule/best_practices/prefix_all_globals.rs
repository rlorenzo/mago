use indoc::indoc;
use mago_allocator::Arena;
use schemars::JsonSchema;

use mago_reporting::Annotation;
use mago_reporting::Issue;
use mago_reporting::Level;
use mago_span::Span;
use mago_syntax::cst::Argument;
use mago_syntax::cst::ArgumentList;
use mago_syntax::cst::Expression;
use mago_syntax::cst::Literal;
use mago_syntax::cst::LiteralString;
use mago_syntax::cst::Node;
use mago_syntax::cst::NodeKind;

use crate::category::Category;
use crate::context::LintContext;
use crate::integration::Integration;
use crate::requirements::RuleRequirements;
use crate::rule::Config;
use crate::rule::LintRule;
use crate::rule::utils::call::function_call_matches_any;
use crate::rule_meta::RuleMeta;
use crate::settings::RuleSettings;

const DEFINE_FUNCTIONS: &[&str] = &["define"];

const HOOK_FUNCTIONS: &[&str] = &["do_action", "apply_filters"];

#[derive(Debug, Clone)]
pub struct PrefixAllGlobalsRule {
    meta: &'static RuleMeta,
    cfg: PrefixAllGlobalsConfig,
}

#[derive(Debug, Clone, Eq, PartialEq, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct PrefixAllGlobalsConfig {
    pub level: Level,
    pub prefixes: Vec<String>,
}

impl Default for PrefixAllGlobalsConfig {
    fn default() -> Self {
        Self { level: Level::Warning, prefixes: Vec::new() }
    }
}

impl Config for PrefixAllGlobalsConfig {
    fn default_enabled() -> bool {
        false
    }

    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for PrefixAllGlobalsRule {
    type Config = PrefixAllGlobalsConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "Prefix All Globals",
            code: "prefix-all-globals",
            description: indoc! {"
                Detects global-namespace symbols that do not start with one of the configured
                plugin/theme prefixes. In WordPress, all plugins and themes share a single global
                namespace, so unprefixed functions, classes, interfaces, traits, enums, constants
                (both `const` and `define()`), and hook names (`do_action()` / `apply_filters()`)
                risk colliding with WordPress core or other plugins.

                This rule is inert until you configure your plugin/theme prefix(es) via the
                `prefixes` option — configure your prefix(es) to activate this rule. Code declared
                inside a namespace is not checked, since namespaces already provide isolation.
            "},
            good_example: indoc! {r#"
                <?php

                // With `prefixes = ["myplugin"]` configured:

                const MYPLUGIN_VERSION = '1.0.0';
                define('MYPLUGIN_DIR', __DIR__);

                function myplugin_init() {}

                class MyPlugin_Admin {}

                do_action('myplugin_loaded');
            "#},
            bad_example: indoc! {r#"
                <?php

                // With `prefixes = ["myplugin"]` configured:

                const VERSION = '1.0.0';
                define('PLUGIN_DIR', __DIR__);

                function init() {}

                class Admin {}

                do_action('loaded');
            "#},
            category: Category::BestPractices,
            requirements: RuleRequirements::Integration(Integration::WordPress),
        };

        &META
    }

    fn targets() -> &'static [NodeKind] {
        const TARGETS: &[NodeKind] = &[
            NodeKind::Function,
            NodeKind::Class,
            NodeKind::Interface,
            NodeKind::Trait,
            NodeKind::Enum,
            NodeKind::Constant,
            NodeKind::FunctionCall,
        ];

        TARGETS
    }

    fn build(settings: &RuleSettings<Self::Config>) -> Self {
        let mut cfg = settings.config.clone();

        // Normalize the configured prefixes once: trim surrounding whitespace and drop
        // empty entries, so an effectively empty configuration leaves the rule inert.
        cfg.prefixes =
            cfg.prefixes.iter().map(|prefix| prefix.trim().to_string()).filter(|prefix| !prefix.is_empty()).collect();

        Self { meta: Self::meta(), cfg }
    }

    fn check<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, node: Node<'_, 'arena>)
    where
        A: Arena,
    {
        // The rule does nothing until at least one non-empty prefix is configured
        // (the prefixes are normalized in `build()`).
        if self.cfg.prefixes.is_empty() {
            return;
        }

        // Namespaced code is already isolated from the global namespace.
        if !ctx.scope.get_namespace().is_empty() {
            return;
        }

        match node {
            Node::Function(function) => {
                self.check_symbol(ctx, "function", function.name.value, function.name.span);
            }
            Node::Class(class) => {
                self.check_symbol(ctx, "class", class.name.value, class.name.span);
            }
            Node::Interface(interface) => {
                self.check_symbol(ctx, "interface", interface.name.value, interface.name.span);
            }
            Node::Trait(r#trait) => {
                self.check_symbol(ctx, "trait", r#trait.name.value, r#trait.name.span);
            }
            Node::Enum(r#enum) => {
                self.check_symbol(ctx, "enum", r#enum.name.value, r#enum.name.span);
            }
            Node::Constant(constant) => {
                for item in &constant.items {
                    self.check_symbol(ctx, "constant", item.name.value, item.name.span);
                }
            }
            Node::FunctionCall(function_call) => {
                if function_call_matches_any(ctx, function_call, DEFINE_FUNCTIONS).is_some() {
                    if let Some(string) = first_argument_string(&function_call.argument_list) {
                        let Some(name) = string.value else {
                            return;
                        };

                        // A backslash means the constant is explicitly namespaced.
                        if name.contains(&b'\\') {
                            return;
                        }

                        self.check_symbol(ctx, "constant", name, string.span);
                    }
                } else if function_call_matches_any(ctx, function_call, HOOK_FUNCTIONS).is_some()
                    && let Some(string) = first_argument_string(&function_call.argument_list)
                {
                    let Some(name) = string.value else {
                        return;
                    };

                    self.check_symbol(ctx, "hook", name, string.span);
                }
            }
            _ => {}
        }
    }
}

impl PrefixAllGlobalsRule {
    fn check_symbol<A>(&self, ctx: &mut LintContext<'_, '_, A>, kind: &str, name: &[u8], span: Span)
    where
        A: Arena,
    {
        if name.is_empty() {
            return;
        }

        // Never flag PHP magic names (`__construct`, `__DIR__`, etc.).
        if name.starts_with(b"__") {
            return;
        }

        if is_prefixed(name, &self.cfg.prefixes) {
            return;
        }

        let name_str = String::from_utf8_lossy(name);
        // The prefixes are normalized in `build()`, so the first entry is always
        // non-empty and trimmed.
        let prefix = self.cfg.prefixes.first().map_or("", String::as_str);

        let issue = Issue::new(self.cfg.level(), format!("Global {kind} `{name_str}` is not prefixed"))
            .with_code(self.meta.code)
            .with_annotation(
                Annotation::primary(span).with_message(format!("This {kind} name lacks a plugin/theme prefix")),
            )
            .with_note(
                "WordPress plugins and themes share a single global namespace; unprefixed global symbols can collide with WordPress core or other plugins.",
            )
            .with_help(format!("Rename it to start with your prefix, e.g. `{prefix}_{name_str}`."));

        ctx.collector.report(issue);
    }
}

/// Checks whether a symbol name starts with one of the configured prefixes.
///
/// Expects the prefixes to already be normalized (trimmed, non-empty), as done
/// in `build()`. The comparison is case-insensitive, and a single leading
/// underscore on the symbol name is ignored (e.g. prefix `myplugin` accepts
/// `_myplugin_internal`).
fn is_prefixed(name: &[u8], prefixes: &[String]) -> bool {
    let name = name.strip_prefix(b"_").unwrap_or(name);

    prefixes.iter().any(|prefix| {
        let prefix = prefix.as_bytes();

        !prefix.is_empty() && name.len() >= prefix.len() && name[..prefix.len()].eq_ignore_ascii_case(prefix)
    })
}

/// Extracts the first argument of a call if it is a positional string literal.
fn first_argument_string<'ast, 'arena>(
    argument_list: &'ast ArgumentList<'arena>,
) -> Option<&'ast LiteralString<'arena>> {
    let Some(Argument::Positional(first_argument)) = argument_list.arguments.first() else {
        return None;
    };

    match first_argument.value {
        Expression::Literal(Literal::String(string)) => Some(string),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::PrefixAllGlobalsRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    fn with_prefix(s: &mut crate::settings::Settings) {
        s.rules.prefix_all_globals.config.prefixes = vec!["myplugin".to_string()];
    }

    test_lint_success! {
        name = empty_config_is_silent,
        rule = PrefixAllGlobalsRule,
        code = indoc! {r"
            <?php

            function init() {}

            class Admin {}

            const VERSION = '1.0.0';
            define('PLUGIN_DIR', '/tmp');
            do_action('loaded');
        "}
    }

    test_lint_success! {
        name = whitespace_only_prefixes_are_inert,
        rule = PrefixAllGlobalsRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.prefix_all_globals.config.prefixes = vec!["   ".to_string(), String::new()];
        },
        code = indoc! {r"
            <?php

            function init() {}

            class Admin {}

            const VERSION = '1.0.0';
            define('PLUGIN_DIR', '/tmp');
            do_action('loaded');
        "}
    }

    test_lint_success! {
        name = padded_prefix_is_trimmed_before_matching,
        rule = PrefixAllGlobalsRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.prefix_all_globals.config.prefixes = vec![" myplugin ".to_string()];
        },
        code = indoc! {r"
            <?php

            function myplugin_init() {}
        "}
    }

    test_lint_failure! {
        name = padded_prefix_still_flags_unprefixed,
        rule = PrefixAllGlobalsRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.prefix_all_globals.config.prefixes = vec![" myplugin ".to_string()];
        },
        code = indoc! {r"
            <?php

            function init_plugin() {}
        "}
    }

    test_lint_failure! {
        name = unprefixed_function,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            function init_plugin() {}
        "}
    }

    test_lint_success! {
        name = prefixed_function,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            function myplugin_init() {}
        "}
    }

    test_lint_failure! {
        name = unprefixed_class,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            class Admin {}
        "}
    }

    test_lint_success! {
        name = prefixed_class_case_insensitive,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            class MyPlugin_Admin {}
        "}
    }

    test_lint_failure! {
        name = unprefixed_interface_trait_enum,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            interface Renderer {}
            trait Loggable {}
            enum Status {}
        "}
    }

    test_lint_success! {
        name = prefixed_interface_trait_enum,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            interface MyPlugin_Renderer {}
            trait MyPlugin_Loggable {}
            enum MyPlugin_Status {}
        "}
    }

    test_lint_failure! {
        name = unprefixed_const_statement,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            const VERSION = '1.0.0';
        "}
    }

    test_lint_success! {
        name = prefixed_const_statement,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            const MYPLUGIN_VERSION = '1.0.0';
        "}
    }

    test_lint_failure! {
        name = unprefixed_define,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            define('PLUGIN_DIR', '/tmp');
        "}
    }

    test_lint_success! {
        name = prefixed_define,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            define('MYPLUGIN_DIR', '/tmp');
        "}
    }

    test_lint_failure! {
        name = unprefixed_hooks,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            do_action('loaded');
            apply_filters('content', $content);
        "}
    }

    test_lint_success! {
        name = prefixed_hooks_with_separators,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            do_action('myplugin_loaded');
            apply_filters('myplugin/content', $content);
            do_action('myplugin-init');
        "}
    }

    test_lint_success! {
        name = namespaced_code_is_ignored,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            namespace App;

            function init() {}

            class Admin {}

            const VERSION = '1.0.0';
        "}
    }

    test_lint_success! {
        name = leading_underscore_is_ignored,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            function _myplugin_internal() {}
        "}
    }

    test_lint_success! {
        name = methods_and_closures_are_not_flagged,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            class MyPlugin_Admin {
                public function render() {}
                public function __construct() {}
            }

            $callback = function () {};
            $mapper = fn ($x) => $x;
        "}
    }

    test_lint_success! {
        name = dynamic_names_are_ignored,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            define($name, '/tmp');
            do_action($hook);
            apply_filters('myplugin_' . $key, $value);
        "}
    }

    test_lint_success! {
        name = subscribing_to_existing_hooks_is_ok,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            add_action('init', 'myplugin_init');
            add_filter('the_content', 'myplugin_filter_content');
            remove_action('wp_head', 'wp_generator');
            remove_filter('the_content', 'wpautop');
        "}
    }

    test_lint_success! {
        name = symbol_equal_to_prefix_is_ok,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            function myplugin() {}

            class MyPlugin {}
        "}
    }

    test_lint_failure! {
        name = prefix_in_middle_is_flagged,
        rule = PrefixAllGlobalsRule,
        settings = with_prefix,
        code = indoc! {r"
            <?php

            function init_myplugin() {}
        "}
    }
}
