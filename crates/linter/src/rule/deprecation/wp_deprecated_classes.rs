use std::cmp::Ordering;

use indoc::indoc;
use mago_allocator::Arena;
use schemars::JsonSchema;

use mago_reporting::Annotation;
use mago_reporting::Issue;
use mago_reporting::Level;
use mago_span::HasSpan;
use mago_syntax::cst::BinaryOperator;
use mago_syntax::cst::Expression;
use mago_syntax::cst::Identifier;
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

/// A WordPress core class that has been deprecated.
struct DeprecatedClass {
    /// Lowercase class name, used as the binary-search key.
    key: &'static [u8],
    /// Canonical class name, used for display.
    name: &'static str,
    /// The WordPress version in which the class was deprecated.
    since: &'static str,
    /// The recommended replacement, if any.
    replacement: Option<&'static str>,
}

/// Deprecated WordPress core classes, sorted by `key` for binary search.
const DEPRECATED_CLASSES: &[DeprecatedClass] = &[
    DeprecatedClass {
        key: b"phpmailer",
        name: "PHPMailer",
        since: "5.5",
        replacement: Some("PHPMailer\\PHPMailer\\PHPMailer"),
    },
    DeprecatedClass {
        key: b"phpmailerexception",
        name: "phpmailerException",
        since: "5.5",
        replacement: Some("PHPMailer\\PHPMailer\\Exception"),
    },
    DeprecatedClass {
        key: b"requests",
        name: "Requests",
        since: "6.2",
        replacement: Some("WpOrg\\Requests\\Requests"),
    },
    DeprecatedClass {
        key: b"services_json",
        name: "Services_JSON",
        since: "5.3",
        replacement: Some("json_encode()/json_decode()"),
    },
    DeprecatedClass {
        key: b"services_json_error",
        name: "Services_JSON_Error",
        since: "5.3",
        replacement: Some("json_encode()/json_decode()"),
    },
    DeprecatedClass { key: b"smtp", name: "SMTP", since: "5.5", replacement: Some("PHPMailer\\PHPMailer\\SMTP") },
    DeprecatedClass { key: b"wp_atom_server", name: "wp_atom_server", since: "3.0", replacement: None },
    DeprecatedClass {
        key: b"wp_customize_new_menu_control",
        name: "WP_Customize_New_Menu_Control",
        since: "4.9",
        replacement: None,
    },
    DeprecatedClass {
        key: b"wp_customize_new_menu_section",
        name: "WP_Customize_New_Menu_Section",
        since: "4.9",
        replacement: None,
    },
    DeprecatedClass { key: b"wp_http_curl", name: "WP_Http_Curl", since: "6.4", replacement: Some("WP_Http") },
    DeprecatedClass {
        key: b"wp_http_fsockopen",
        name: "WP_HTTP_Fsockopen",
        since: "4.4",
        replacement: Some("WP_HTTP_Streams"),
    },
    DeprecatedClass { key: b"wp_http_streams", name: "WP_Http_Streams", since: "6.4", replacement: Some("WP_Http") },
    DeprecatedClass {
        key: b"wp_user_search",
        name: "WP_User_Search",
        since: "3.1",
        replacement: Some("WP_User_Query"),
    },
];

#[derive(Debug, Clone)]
pub struct WpDeprecatedClassesRule {
    meta: &'static RuleMeta,
    cfg: WpDeprecatedClassesConfig,
    /// Parsed `minimum-wp-version`, or `None` when unset or unparsable (flag everything).
    minimum_wp_version: Option<[u32; 3]>,
}

#[derive(Debug, Clone, Eq, PartialEq, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct WpDeprecatedClassesConfig {
    pub level: Level,
    /// The minimum WordPress version supported by the project (e.g. `"6.0"`).
    ///
    /// When set, only classes deprecated at or before this version are flagged.
    /// When empty or unparsable, all deprecated classes are flagged.
    pub minimum_wp_version: String,
}

impl Default for WpDeprecatedClassesConfig {
    fn default() -> Self {
        Self { level: Level::Warning, minimum_wp_version: String::new() }
    }
}

impl Config for WpDeprecatedClassesConfig {
    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for WpDeprecatedClassesRule {
    type Config = WpDeprecatedClassesConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "WordPress Deprecated Classes",
            code: "wp-deprecated-classes",
            description: indoc! {"
                Detects usage of WordPress core classes that have been deprecated. Deprecated classes
                may be removed in future WordPress releases, emit deprecation notices, and no longer
                receive bug or security fixes.

                This rule flags instantiations, static method calls, class constant accesses,
                `extends` clauses, and `instanceof` checks that reference a deprecated class.

                The `minimum-wp-version` option can be set to only report classes that are already
                deprecated in the oldest WordPress version the project supports.
            "},
            good_example: indoc! {r"
                <?php

                $user_query = new WP_User_Query(['role' => 'editor']);
            "},
            bad_example: indoc! {r"
                <?php

                // WP_User_Search was deprecated in WordPress 3.1.
                $user_search = new WP_User_Search($_GET['usersearch']);
            "},
            category: Category::Deprecation,
            requirements: RuleRequirements::Integration(Integration::WordPress),
        };

        &META
    }

    fn targets() -> &'static [NodeKind] {
        const TARGETS: &[NodeKind] = &[
            NodeKind::Instantiation,
            NodeKind::StaticMethodCall,
            NodeKind::ClassConstantAccess,
            NodeKind::Extends,
            NodeKind::Binary,
        ];

        TARGETS
    }

    fn build(settings: &RuleSettings<Self::Config>) -> Self {
        let minimum_wp_version = parse_wp_version(&settings.config.minimum_wp_version);

        Self { meta: Self::meta(), cfg: settings.config.clone(), minimum_wp_version }
    }

    fn check<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, node: Node<'_, 'arena>)
    where
        A: Arena,
    {
        let identifier = match node {
            Node::Instantiation(instantiation) => {
                let Expression::Identifier(identifier) = instantiation.class else {
                    return;
                };

                identifier
            }
            Node::StaticMethodCall(static_method_call) => {
                let Expression::Identifier(identifier) = static_method_call.class else {
                    return;
                };

                identifier
            }
            Node::ClassConstantAccess(class_constant_access) => {
                let Expression::Identifier(identifier) = class_constant_access.class else {
                    return;
                };

                identifier
            }
            Node::Binary(binary) => {
                if !matches!(binary.operator, BinaryOperator::Instanceof(_)) {
                    return;
                }

                let Expression::Identifier(identifier) = binary.rhs else {
                    return;
                };

                identifier
            }
            Node::Extends(extends) => {
                for identifier in extends.types.iter() {
                    self.check_class_reference(ctx, identifier);
                }

                return;
            }
            _ => return,
        };

        self.check_class_reference(ctx, identifier);
    }
}

impl WpDeprecatedClassesRule {
    fn check_class_reference<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, identifier: &Identifier<'arena>)
    where
        A: Arena,
    {
        // The resolved name is fully qualified: user classes inside a namespace resolve to
        // `Some\Namespace\ClassName`, which never matches the global WordPress class names
        // in the lookup table. Only global (or `\`-prefixed / `use`-imported global) names match.
        let class_name = ctx.lookup_name(identifier);

        let Some(entry) = lookup_deprecated_class(class_name) else {
            return;
        };

        if let Some(minimum) = self.minimum_wp_version
            && let Some(since) = parse_wp_version(entry.since)
            && since > minimum
        {
            // The class is not yet deprecated in the oldest supported WordPress version.
            return;
        }

        let mut issue = Issue::new(
            self.cfg.level(),
            format!("Class `{}` has been deprecated since WordPress {}.", entry.name, entry.since),
        )
        .with_code(self.meta.code)
        .with_annotation(
            Annotation::primary(identifier.span())
                .with_message(format!("`{}` is a deprecated WordPress class", entry.name)),
        )
        .with_note("Deprecated classes may be removed in a future WordPress release.");

        issue = match entry.replacement {
            Some(replacement) => issue.with_help(format!("Use `{replacement}` instead.")),
            None => issue.with_help("There is no direct replacement; remove the usage."),
        };

        ctx.collector.report(issue);
    }
}

/// Looks up a resolved class name in the deprecated-classes table, case-insensitively.
fn lookup_deprecated_class(class_name: &[u8]) -> Option<&'static DeprecatedClass> {
    DEPRECATED_CLASSES
        .binary_search_by(|entry| compare_with_lowercase(entry.key, class_name))
        .ok()
        .map(|index| &DEPRECATED_CLASSES[index])
}

/// Compares a lowercase key against a candidate name lowered on the fly,
/// avoiding any per-call allocation.
fn compare_with_lowercase(key: &[u8], candidate: &[u8]) -> Ordering {
    let mut key_bytes = key.iter().copied();
    let mut candidate_bytes = candidate.iter().map(u8::to_ascii_lowercase);

    loop {
        match (key_bytes.next(), candidate_bytes.next()) {
            (Some(a), Some(b)) => match a.cmp(&b) {
                Ordering::Equal => {}
                ordering => return ordering,
            },
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
        }
    }
}

/// Parses a dotted WordPress version string (e.g. `"6.4"`) into comparable components.
///
/// Returns `None` for empty or unparsable strings.
fn parse_wp_version(version: &str) -> Option<[u32; 3]> {
    let mut components = [0u32; 3];
    let mut count = 0;

    for segment in version.split('.') {
        if count >= components.len() {
            break;
        }

        components[count] = segment.parse().ok()?;
        count += 1;
    }

    if count == 0 { None } else { Some(components) }
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::DEPRECATED_CLASSES;
    use super::WpDeprecatedClassesRule;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    #[test]
    fn deprecated_classes_table_is_sorted_and_lowercase() {
        for (previous, current) in DEPRECATED_CLASSES.iter().zip(DEPRECATED_CLASSES.iter().skip(1)) {
            assert!(
                previous.key < current.key,
                "DEPRECATED_CLASSES must be sorted by key: `{}` >= `{}`",
                String::from_utf8_lossy(previous.key),
                String::from_utf8_lossy(current.key),
            );
        }

        for entry in DEPRECATED_CLASSES {
            assert!(
                entry.key.iter().all(|byte| !byte.is_ascii_uppercase()),
                "DEPRECATED_CLASSES keys must be lowercase: `{}`",
                String::from_utf8_lossy(entry.key),
            );
            assert!(entry.name.as_bytes().eq_ignore_ascii_case(entry.key), "key must match name: `{}`", entry.name);
            assert!(super::parse_wp_version(entry.since).is_some(), "invalid version: `{}`", entry.since);
        }
    }

    test_lint_failure! {
        name = instantiation_of_deprecated_class,
        rule = WpDeprecatedClassesRule,
        count = 1,
        code = indoc! {r"
            <?php

            $search = new WP_User_Search($_GET['usersearch']);
        "}
    }

    test_lint_failure! {
        name = case_insensitive_class_name,
        rule = WpDeprecatedClassesRule,
        count = 1,
        code = indoc! {r"
            <?php

            $search = new wp_user_search();
        "}
    }

    test_lint_failure! {
        name = leading_backslash_class_name,
        rule = WpDeprecatedClassesRule,
        count = 1,
        code = indoc! {r"
            <?php

            $json = new \Services_JSON();
        "}
    }

    test_lint_failure! {
        name = static_method_call_on_deprecated_class,
        rule = WpDeprecatedClassesRule,
        count = 1,
        code = indoc! {r"
            <?php

            WP_HTTP_Fsockopen::test();
        "}
    }

    test_lint_failure! {
        name = class_constant_access_on_deprecated_class,
        rule = WpDeprecatedClassesRule,
        count = 1,
        code = indoc! {r"
            <?php

            $version = SMTP::VERSION;
        "}
    }

    test_lint_failure! {
        name = extends_deprecated_class,
        rule = WpDeprecatedClassesRule,
        count = 1,
        code = indoc! {r"
            <?php

            class My_Transport extends WP_Http_Curl {}
        "}
    }

    test_lint_failure! {
        name = instanceof_deprecated_class,
        rule = WpDeprecatedClassesRule,
        count = 1,
        code = indoc! {r"
            <?php

            if ($transport instanceof WP_Http_Streams) {
                return true;
            }
        "}
    }

    test_lint_failure! {
        name = deprecated_before_minimum_wp_version_is_flagged,
        rule = WpDeprecatedClassesRule,
        count = 1,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.wp_deprecated_classes.config.minimum_wp_version = "4.4".to_string();
        },
        code = indoc! {r"
            <?php

            $search = new WP_User_Search();
        "}
    }

    test_lint_success! {
        name = deprecated_after_minimum_wp_version_is_not_flagged,
        rule = WpDeprecatedClassesRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.wp_deprecated_classes.config.minimum_wp_version = "4.4".to_string();
        },
        code = indoc! {r"
            <?php

            $requests = new Requests();
        "}
    }

    test_lint_failure! {
        name = unparsable_minimum_wp_version_flags_everything,
        rule = WpDeprecatedClassesRule,
        count = 1,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.wp_deprecated_classes.config.minimum_wp_version = "latest".to_string();
        },
        code = indoc! {r"
            <?php

            $requests = new Requests();
        "}
    }

    test_lint_success! {
        name = non_deprecated_class_is_not_flagged,
        rule = WpDeprecatedClassesRule,
        code = indoc! {r"
            <?php

            $query = new WP_User_Query(['role' => 'editor']);
        "}
    }

    test_lint_success! {
        name = same_named_class_in_namespace_is_not_flagged,
        rule = WpDeprecatedClassesRule,
        code = indoc! {r"
            <?php

            namespace My\Plugin;

            $search = new WP_User_Search();
            WP_User_Search::run();
            $version = WP_User_Search::VERSION;

            if ($search instanceof WP_User_Search) {
                return;
            }
        "}
    }

    test_lint_success! {
        name = imported_namespaced_class_is_not_flagged,
        rule = WpDeprecatedClassesRule,
        code = indoc! {r"
            <?php

            use PHPMailer\PHPMailer\PHPMailer;

            $mailer = new PHPMailer(true);
        "}
    }

    test_lint_success! {
        name = qualified_class_name_is_not_flagged,
        rule = WpDeprecatedClassesRule,
        code = indoc! {r"
            <?php

            $requests = new WpOrg\Requests\Requests();
        "}
    }

    test_lint_success! {
        name = method_and_property_usage_is_not_flagged,
        rule = WpDeprecatedClassesRule,
        code = indoc! {r"
            <?php

            $object->WP_User_Search();
            $object->WP_User_Search;
        "}
    }
}
