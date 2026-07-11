use std::cmp::Ordering;

use indoc::indoc;
use mago_allocator::Arena;
use schemars::JsonSchema;

use mago_reporting::Annotation;
use mago_reporting::Issue;
use mago_reporting::Level;
use mago_span::HasSpan;
use mago_syntax::cst::Expression;
use mago_syntax::cst::FunctionCall;
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

/// A WordPress version, parsed as dotted integers (e.g. `4.10` > `4.9`).
type WpVersion = (u32, u32, u32);

/// Well-known deprecated WordPress core functions.
///
/// Each entry is `(function name, version deprecated, replacement)`. The function
/// names are lowercase and the table is sorted by name so it can be binary-searched.
/// Sourced from WordPress core's `deprecated.php` files (including the admin,
/// multisite, and pluggable variants).
const DEPRECATED_FUNCTIONS: &[(&str, &str, Option<&str>)] = &[
    ("add_custom_background", "3.4", Some("add_theme_support('custom-background')")),
    ("add_custom_image_header", "3.4", Some("add_theme_support('custom-header')")),
    ("add_object_page", "4.5", Some("add_menu_page()")),
    ("add_option_update_handler", "3.0", Some("register_setting()")),
    ("add_option_whitelist", "5.5", Some("add_allowed_options()")),
    ("add_utility_page", "4.5", Some("add_menu_page()")),
    ("attribute_escape", "2.8", Some("esc_attr()")),
    ("automatic_feed_links", "3.0", Some("add_theme_support('automatic-feed-links')")),
    ("bool_from_yn", "1.0", None),
    ("clean_pre", "3.4", None),
    ("clean_url", "3.0", Some("esc_url()")),
    ("comments_popup_script", "4.5", None),
    ("comments_rss", "2.2", Some("get_post_comments_feed_link()")),
    ("comments_rss_link", "2.5", Some("post_comments_feed_link()")),
    ("create_empty_blog", "4.4", None),
    ("create_user", "2.0", Some("wp_create_user()")),
    ("debug_fclose", "3.4", Some("error_log()")),
    ("debug_fopen", "3.4", Some("error_log()")),
    ("debug_fwrite", "3.4", Some("error_log()")),
    ("delete_usermeta", "3.0", Some("delete_user_meta()")),
    ("documentation_link", "2.5", None),
    ("dropdown_categories", "2.5", Some("wp_category_checklist()")),
    ("dropdown_cats", "2.1", Some("wp_dropdown_categories()")),
    ("dropdown_link_categories", "2.5", Some("wp_link_category_checklist()")),
    ("favorite_actions", "3.2", None),
    ("fetch_rss", "2.9", Some("fetch_feed()")),
    ("force_ssl_login", "4.4", Some("force_ssl_admin()")),
    ("funky_javascript_fix", "3.0", None),
    ("gd_edit_image_support", "3.5", Some("wp_image_editor_supports()")),
    ("get_admin_users_for_domain", "4.4", None),
    ("get_all_category_ids", "4.0", Some("get_terms()")),
    ("get_alloptions", "3.0", Some("wp_load_alloptions()")),
    ("get_allowed_themes", "3.4", Some("wp_get_themes()")),
    ("get_archives", "2.1", Some("wp_get_archives()")),
    ("get_attachment_icon", "2.5", Some("wp_get_attachment_image()")),
    ("get_attachment_icon_src", "2.5", Some("wp_get_attachment_image_src()")),
    ("get_attachment_innerhtml", "2.5", Some("wp_get_attachment_image()")),
    ("get_author_name", "2.8", Some("get_the_author_meta('display_name')")),
    ("get_author_user_ids", "3.1", Some("get_users()")),
    ("get_autotoggle", "2.1", None),
    ("get_blog_list", "3.0", Some("get_sites()")),
    ("get_blogaddress_by_domain", "3.7", None),
    ("get_boundary_post_rel_link", "3.3", None),
    ("get_broken_themes", "3.4", Some("wp_get_themes()")),
    ("get_catname", "2.1", Some("get_cat_name()")),
    ("get_comments_popup_template", "4.5", None),
    ("get_current_theme", "3.4", Some("wp_get_theme()")),
    ("get_currentuserinfo", "4.5", Some("wp_get_current_user()")),
    ("get_dashboard_blog", "3.1", Some("get_site()")),
    ("get_editable_authors", "3.1", Some("get_users()")),
    ("get_editable_user_ids", "3.1", Some("get_users()")),
    ("get_index_rel_link", "3.3", None),
    ("get_link", "2.1", Some("get_bookmark()")),
    ("get_linkcatname", "2.1", Some("get_category()")),
    ("get_linkrating", "2.1", Some("sanitize_bookmark_field()")),
    ("get_links_list", "2.1", Some("wp_list_bookmarks()")),
    ("get_linksbyname", "2.1", Some("get_bookmarks()")),
    ("get_nonauthor_user_ids", "3.1", Some("get_users()")),
    ("get_others_drafts", "3.1", None),
    ("get_others_pending", "3.1", None),
    ("get_others_unpublished_posts", "3.1", None),
    ("get_page", "3.5", Some("get_post()")),
    ("get_page_by_title", "6.2", Some("WP_Query")),
    ("get_paged_template", "4.7", None),
    ("get_parent_post_rel_link", "3.3", None),
    ("get_postdata", "1.5.1", Some("get_post()")),
    ("get_profile", "3.0", Some("get_the_author_meta()")),
    ("get_rss", "2.9", Some("fetch_feed()")),
    ("get_screen_icon", "3.8", None),
    ("get_settings", "2.1", Some("get_option()")),
    ("get_shortcut_link", "3.9", None),
    ("get_the_attachment_link", "2.5", Some("wp_get_attachment_link()")),
    ("get_the_author_aim", "2.8", Some("get_the_author_meta('aim')")),
    ("get_the_author_description", "2.8", Some("get_the_author_meta('description')")),
    ("get_the_author_email", "2.8", Some("get_the_author_meta('email')")),
    ("get_the_author_firstname", "2.8", Some("get_the_author_meta('first_name')")),
    ("get_the_author_icq", "2.8", Some("get_the_author_meta('icq')")),
    ("get_the_author_id", "2.8", Some("get_the_author_meta('ID')")),
    ("get_the_author_lastname", "2.8", Some("get_the_author_meta('last_name')")),
    ("get_the_author_login", "2.8", Some("get_the_author_meta('login')")),
    ("get_the_author_msn", "2.8", Some("get_the_author_meta('msn')")),
    ("get_the_author_nickname", "2.8", Some("get_the_author_meta('nickname')")),
    ("get_the_author_url", "2.8", Some("get_the_author_meta('url')")),
    ("get_the_author_yim", "2.8", Some("get_the_author_meta('yim')")),
    ("get_theme", "3.4", Some("wp_get_theme()")),
    ("get_theme_data", "3.4", Some("wp_get_theme()")),
    ("get_themes", "3.4", Some("wp_get_themes()")),
    ("get_user_by_email", "3.3", Some("get_user_by('email')")),
    ("get_user_id_from_string", "3.6", Some("get_user_by()")),
    ("get_user_metavalues", "3.3", None),
    ("get_userdatabylogin", "3.3", Some("get_user_by('login')")),
    ("get_usermeta", "3.0", Some("get_user_meta()")),
    ("get_usernumposts", "3.0", Some("count_user_posts()")),
    ("get_users_of_blog", "3.1", Some("get_users()")),
    ("global_terms_enabled", "6.1", None),
    ("graceful_fail", "3.0", Some("wp_die()")),
    ("gzip_compression", "2.5", None),
    ("image_resize", "3.5", Some("wp_get_image_editor()")),
    ("insert_blog", "5.1", Some("wp_insert_site()")),
    ("install_blog", "5.1", None),
    ("install_blog_defaults", "5.1", None),
    ("is_blog_user", "3.3", Some("is_user_member_of_blog()")),
    ("is_comments_popup", "4.5", None),
    ("is_main_blog", "3.0", Some("is_main_site()")),
    ("is_plugin_page", "3.1", None),
    ("is_taxonomy", "3.0", Some("taxonomy_exists()")),
    ("is_term", "3.0", Some("term_exists()")),
    ("js_escape", "2.8", Some("esc_js()")),
    ("like_escape", "4.0", Some("$wpdb->esc_like()")),
    ("link_pages", "2.1", Some("wp_link_pages()")),
    ("links_popup_script", "2.1", None),
    ("list_authors", "2.1", Some("wp_list_authors()")),
    ("list_cats", "2.1", Some("wp_list_categories()")),
    ("make_url_footnote", "2.9", None),
    ("next_post", "2.0", Some("next_post_link()")),
    ("noindex", "5.7", Some("wp_robots_no_robots()")),
    ("permalink_link", "1.2", Some("the_permalink()")),
    ("permalink_single_rss", "2.3", Some("the_permalink_rss()")),
    ("popuplinks", "4.5", None),
    ("post_permalink", "4.4", Some("get_permalink()")),
    ("preview_theme", "4.3", None),
    ("previous_post", "2.0", Some("previous_post_link()")),
    ("print_emoji_styles", "6.4", None),
    ("readonly", "5.9", Some("wp_readonly()")),
    ("register_sidebar_widget", "2.8", Some("wp_register_sidebar_widget()")),
    ("register_widget_control", "2.8", Some("wp_register_widget_control()")),
    ("remove_custom_background", "3.4", Some("remove_theme_support('custom-background')")),
    ("remove_custom_image_header", "3.4", Some("remove_theme_support('custom-header')")),
    ("remove_option_update_handler", "3.0", Some("unregister_setting()")),
    ("remove_option_whitelist", "5.5", Some("remove_allowed_options()")),
    ("rich_edit_exists", "3.9", None),
    ("sanitize_user_object", "3.3", None),
    ("screen_icon", "3.8", None),
    ("set_current_user", "3.0", Some("wp_set_current_user()")),
    ("start_wp", "1.5", None),
    ("sticky_class", "3.5", Some("post_class()")),
    ("the_author_aim", "2.8", Some("the_author_meta('aim')")),
    ("the_author_description", "2.8", Some("the_author_meta('description')")),
    ("the_author_email", "2.8", Some("the_author_meta('email')")),
    ("the_author_firstname", "2.8", Some("the_author_meta('first_name')")),
    ("the_author_icq", "2.8", Some("the_author_meta('icq')")),
    ("the_author_id", "2.8", Some("the_author_meta('ID')")),
    ("the_author_lastname", "2.8", Some("the_author_meta('last_name')")),
    ("the_author_login", "2.8", Some("the_author_meta('login')")),
    ("the_author_msn", "2.8", Some("the_author_meta('msn')")),
    ("the_author_nickname", "2.8", Some("the_author_meta('nickname')")),
    ("the_author_url", "2.8", Some("the_author_meta('url')")),
    ("the_author_yim", "2.8", Some("the_author_meta('yim')")),
    ("the_content_rss", "2.9", Some("the_content_feed()")),
    ("the_editor", "3.3", Some("wp_editor()")),
    ("tinymce_include", "2.1", Some("wp_editor()")),
    ("translate_with_context", "2.9", Some("_x()")),
    ("unregister_sidebar_widget", "2.8", Some("wp_unregister_sidebar_widget()")),
    ("unregister_widget_control", "2.8", Some("wp_unregister_widget_control()")),
    ("update_user_status", "5.3", Some("wp_update_user()")),
    ("update_usermeta", "3.0", Some("update_user_meta()")),
    ("url_is_accessable_via_ssl", "4.0", None),
    ("user_can_create_draft", "2.0", Some("current_user_can()")),
    ("user_can_create_post", "2.0", Some("current_user_can()")),
    ("user_can_delete_post", "2.0", Some("current_user_can()")),
    ("user_can_delete_post_comments", "2.0", Some("current_user_can()")),
    ("user_can_edit_post", "2.0", Some("current_user_can()")),
    ("user_can_edit_post_comments", "2.0", Some("current_user_can()")),
    ("user_can_edit_user", "2.0", Some("current_user_can()")),
    ("user_can_set_post_date", "2.0", Some("current_user_can()")),
    ("user_pass_ok", "3.5", Some("wp_authenticate()")),
    ("validate_email", "3.0", Some("is_email()")),
    ("wlwmanifest_link", "6.3", None),
    ("wp_ajax_press_this_add_category", "4.9", None),
    ("wp_ajax_press_this_save_post", "4.9", None),
    ("wp_blacklist_check", "5.5", Some("wp_check_comment_disallowed_list()")),
    ("wp_cache_reset", "3.5", None),
    ("wp_clearcookie", "2.5", Some("wp_clear_auth_cookie()")),
    ("wp_convert_bytes_to_hr", "3.6", Some("size_format()")),
    ("wp_dropdown_cats", "3.0", Some("wp_dropdown_categories()")),
    ("wp_get_cookie_login", "2.5", None),
    ("wp_get_http", "4.4", Some("WP_Http")),
    ("wp_get_links", "2.1", Some("wp_list_bookmarks()")),
    ("wp_get_linksbyname", "2.1", Some("wp_list_bookmarks()")),
    ("wp_get_loading_attr_default", "6.3", Some("wp_get_loading_optimization_attributes()")),
    ("wp_get_single_post", "3.5", Some("get_post()")),
    ("wp_get_sites", "4.6", Some("get_sites()")),
    ("wp_get_user_request_data", "5.4", Some("wp_get_user_request()")),
    ("wp_htmledit_pre", "4.3", Some("format_for_editor()")),
    ("wp_img_tag_add_decoding_attr", "6.3", Some("wp_img_tag_add_loading_optimization_attrs()")),
    ("wp_kses_js_entities", "4.7", None),
    ("wp_list_cats", "2.1", Some("wp_list_categories()")),
    ("wp_load_image", "3.5", Some("wp_get_image_editor()")),
    ("wp_login", "2.5", Some("wp_signon()")),
    ("wp_make_content_images_responsive", "5.5", Some("wp_filter_content_tags()")),
    ("wp_no_robots", "5.7", Some("wp_robots_no_robots()")),
    ("wp_richedit_pre", "4.3", Some("format_for_editor()")),
    ("wp_rss", "2.9", Some("fetch_feed()")),
    ("wp_sensitive_page_meta", "5.7", Some("wp_robots_sensitive_page()")),
    ("wp_setcookie", "2.5", Some("wp_set_auth_cookie()")),
    ("wp_shrink_dimensions", "3.0", Some("wp_constrain_dimensions()")),
    ("wp_specialchars", "2.8", Some("esc_html()")),
    ("wp_timezone_supported", "3.2", None),
    ("wp_tiny_mce", "3.2", Some("wp_editor()")),
    ("wpmu_delete_blog", "5.1", Some("wp_delete_site()")),
];

#[derive(Debug, Clone)]
pub struct WpDeprecatedFunctionsRule {
    meta: &'static RuleMeta,
    cfg: WpDeprecatedFunctionsConfig,
    /// Whether each entry of `DEPRECATED_FUNCTIONS` should be reported, precomputed
    /// at build time from the configured `minimum-wp-version` so that no version
    /// parsing or comparison happens per matched call. `None` means the option is
    /// unset (or unparsable) and every entry is reported.
    reportable: Option<Vec<bool>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, JsonSchema)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(default, rename_all = "kebab-case", deny_unknown_fields))]
pub struct WpDeprecatedFunctionsConfig {
    pub level: Level,
    /// The minimum WordPress version supported by the project (e.g. `"4.5"`).
    ///
    /// When set, only functions that were already deprecated in that version (or
    /// earlier) are reported. When empty or unparsable, every deprecated function
    /// in the table is reported.
    pub minimum_wp_version: String,
}

impl Default for WpDeprecatedFunctionsConfig {
    fn default() -> Self {
        Self { level: Level::Warning, minimum_wp_version: String::new() }
    }
}

impl Config for WpDeprecatedFunctionsConfig {
    fn level(&self) -> Level {
        self.level
    }
}

impl LintRule for WpDeprecatedFunctionsRule {
    type Config = WpDeprecatedFunctionsConfig;

    fn meta() -> &'static RuleMeta {
        const META: RuleMeta = RuleMeta {
            name: "WordPress Deprecated Functions",
            code: "wp-deprecated-functions",
            description: indoc! {"
                This rule flags calls to WordPress core functions that have been deprecated.
                Deprecated functions may be removed in future WordPress releases and often have
                modern replacements that are more secure and reliable.

                The `minimum-wp-version` option restricts reporting to functions that were already
                deprecated in the site's minimum supported WordPress version.
            "},
            good_example: indoc! {r"
                <?php

                $value = get_option('my_setting');
                $user = wp_get_current_user();
                echo esc_html($text);
            "},
            bad_example: indoc! {r"
                <?php

                $value = get_settings('my_setting');
                $user = get_currentuserinfo();
                echo wp_specialchars($text);
            "},
            category: Category::Deprecation,
            requirements: RuleRequirements::Integration(Integration::WordPress),
        };

        &META
    }

    fn targets() -> &'static [NodeKind] {
        const TARGETS: &[NodeKind] = &[NodeKind::FunctionCall];

        TARGETS
    }

    fn build(settings: &RuleSettings<Self::Config>) -> Self {
        // Parse the configured minimum version once, and precompute which table
        // entries were already deprecated in that version.
        let reportable = parse_wp_version(&settings.config.minimum_wp_version).map(|minimum_version| {
            DEPRECATED_FUNCTIONS
                .iter()
                .map(|(_, version, _)| {
                    parse_wp_version(version).is_none_or(|deprecated_in| deprecated_in <= minimum_version)
                })
                .collect()
        });

        Self { meta: Self::meta(), reportable, cfg: settings.config.clone() }
    }

    fn check<'arena, A>(&self, ctx: &mut LintContext<'_, 'arena, A>, node: Node<'_, 'arena>)
    where
        A: Arena,
    {
        let Node::FunctionCall(function_call) = node else {
            return;
        };

        let Some(called_name) = resolve_global_function_name(ctx, function_call) else {
            return;
        };

        let Ok(index) =
            DEPRECATED_FUNCTIONS.binary_search_by(|(name, _, _)| compare_lowercase(name.as_bytes(), called_name))
        else {
            return;
        };

        let (function_name, version, replacement) = DEPRECATED_FUNCTIONS[index];

        // When a minimum WordPress version is configured, only report functions that
        // were already deprecated in that version (precomputed at build time).
        if let Some(reportable) = &self.reportable
            && !reportable[index]
        {
            return;
        }

        let issue =
            Issue::new(self.cfg.level(), format!("`{function_name}` has been deprecated since WordPress {version}"))
                .with_code(self.meta.code)
                .with_annotation(
                    Annotation::primary(function_call.span())
                        .with_message(format!("This function was deprecated in WordPress {version}")),
                )
                .with_note("Deprecated WordPress functions may be removed in a future release.")
                .with_help(match replacement {
                    Some(replacement) => format!("Use `{replacement}` instead."),
                    None => "There is no direct replacement; remove the call or implement the behavior manually."
                        .to_string(),
                });

        ctx.collector.report(issue);
    }
}

/// Resolves the name of a plain (global) function call.
///
/// Returns `Some(name)` for unqualified calls (`get_settings()`) and fully qualified
/// global calls (`\get_settings()`), mirroring how `utils/call.rs` resolves names:
/// imported names are checked against their fully qualified resolution, and calls
/// that resolve to a namespaced function are skipped. Method calls and static
/// method calls are different node kinds and never reach this rule.
fn resolve_global_function_name<'arena, A>(
    ctx: &LintContext<'_, 'arena, A>,
    call: &FunctionCall<'arena>,
) -> Option<&'arena [u8]>
where
    A: Arena,
{
    let Expression::Identifier(identifier) = call.function else {
        return None;
    };

    // Names imported via `use function Foo\bar;` resolve to a namespaced function,
    // which cannot be a WordPress core function.
    if ctx.is_name_imported(identifier) {
        let fully_qualified = ctx.lookup_name(identifier);

        return if fully_qualified.contains(&b'\\') { None } else { Some(fully_qualified) };
    }

    let value = identifier.value();
    let name = value.strip_prefix(b"\\").unwrap_or(value);

    // Qualified calls such as `Foo\get_settings()` target a namespaced function.
    if name.contains(&b'\\') { None } else { Some(name) }
}

/// Compares a lowercase table entry against a candidate name, lowercasing the
/// candidate byte-by-byte, so the lookup is both case-insensitive and free of
/// per-call allocations.
fn compare_lowercase(entry: &[u8], candidate: &[u8]) -> Ordering {
    let common_length = entry.len().min(candidate.len());
    for i in 0..common_length {
        match entry[i].cmp(&candidate[i].to_ascii_lowercase()) {
            Ordering::Equal => {}
            ordering => return ordering,
        }
    }

    entry.len().cmp(&candidate.len())
}

/// Parses a WordPress version string as up to three dotted integers.
///
/// Returns `None` for empty or unparsable values.
fn parse_wp_version(value: &str) -> Option<WpVersion> {
    let mut parts = value.trim().split('.');

    let major = parts.next()?.parse().ok()?;
    let minor = match parts.next() {
        Some(part) => part.parse().ok()?,
        None => 0,
    };
    let patch = match parts.next() {
        Some(part) => part.parse().ok()?,
        None => 0,
    };

    if parts.next().is_some() {
        return None;
    }

    Some((major, minor, patch))
}

#[cfg(test)]
mod tests {
    use indoc::indoc;

    use super::*;
    use crate::test_lint_failure;
    use crate::test_lint_success;

    #[test]
    fn deprecated_functions_table_is_sorted_and_unique() {
        for (previous, current) in DEPRECATED_FUNCTIONS.iter().zip(DEPRECATED_FUNCTIONS.iter().skip(1)) {
            assert!(
                previous.0 < current.0,
                "DEPRECATED_FUNCTIONS must be sorted and unique: `{}` >= `{}`",
                previous.0,
                current.0
            );
        }
    }

    #[test]
    fn deprecated_functions_table_is_lowercase_with_valid_versions() {
        for (name, version, _) in DEPRECATED_FUNCTIONS {
            assert!(name.bytes().all(|byte| !byte.is_ascii_uppercase()), "table entry `{name}` must be lowercase");
            assert!(parse_wp_version(version).is_some(), "table entry `{name}` has unparsable version `{version}`");
        }
    }

    #[test]
    fn parse_wp_version_handles_edge_cases() {
        assert_eq!(parse_wp_version("4.5"), Some((4, 5, 0)));
        assert_eq!(parse_wp_version("1.5.1"), Some((1, 5, 1)));
        assert_eq!(parse_wp_version("6"), Some((6, 0, 0)));
        assert!(parse_wp_version("4.10") > parse_wp_version("4.9"));
        assert_eq!(parse_wp_version(""), None);
        assert_eq!(parse_wp_version("banana"), None);
        assert_eq!(parse_wp_version("4.5.1.2"), None);
    }

    test_lint_failure! {
        name = deprecated_function_with_replacement,
        rule = WpDeprecatedFunctionsRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $value = get_settings('siteurl');
        "#}
    }

    test_lint_failure! {
        name = deprecated_function_without_replacement,
        rule = WpDeprecatedFunctionsRule,
        count = 1,
        code = indoc! {r#"
            <?php

            screen_icon();
        "#}
    }

    test_lint_failure! {
        name = multiple_deprecated_functions,
        rule = WpDeprecatedFunctionsRule,
        count = 2,
        code = indoc! {r#"
            <?php

            $page = get_page(42);
            $url = clean_url('https://example.com');
        "#}
    }

    test_lint_failure! {
        name = case_insensitive_match,
        rule = WpDeprecatedFunctionsRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $user = Get_CurrentUserInfo();
        "#}
    }

    test_lint_failure! {
        name = fully_qualified_call_is_flagged,
        rule = WpDeprecatedFunctionsRule,
        count = 1,
        code = indoc! {r#"
            <?php

            $value = \get_settings('siteurl');
        "#}
    }

    test_lint_success! {
        name = non_deprecated_functions_pass,
        rule = WpDeprecatedFunctionsRule,
        code = indoc! {r#"
            <?php

            $value = get_option('siteurl');
            $user = wp_get_current_user();
            echo esc_html($value);
        "#}
    }

    test_lint_success! {
        name = method_call_with_same_name_is_not_flagged,
        rule = WpDeprecatedFunctionsRule,
        code = indoc! {r#"
            <?php

            $legacy->get_settings('siteurl');
            Legacy::get_settings('siteurl');
        "#}
    }

    test_lint_success! {
        name = namespaced_function_call_is_not_flagged,
        rule = WpDeprecatedFunctionsRule,
        code = indoc! {r#"
            <?php

            \MyPlugin\Compat\get_settings('siteurl');
        "#}
    }

    test_lint_success! {
        name = imported_namespaced_function_is_not_flagged,
        rule = WpDeprecatedFunctionsRule,
        code = indoc! {r#"
            <?php

            use function MyPlugin\Compat\get_settings;

            get_settings('siteurl');
        "#}
    }

    test_lint_failure! {
        name = minimum_wp_version_flags_older_deprecations,
        rule = WpDeprecatedFunctionsRule,
        count = 1,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.wp_deprecated_functions.config.minimum_wp_version = "4.5".to_string();
        },
        code = indoc! {r#"
            <?php

            $user = get_currentuserinfo();
        "#}
    }

    test_lint_success! {
        name = minimum_wp_version_skips_newer_deprecations,
        rule = WpDeprecatedFunctionsRule,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.wp_deprecated_functions.config.minimum_wp_version = "4.4".to_string();
        },
        code = indoc! {r#"
            <?php

            $user = get_currentuserinfo();
            $sites = wp_get_sites();
            $page = get_page_by_title('About');
        "#}
    }

    test_lint_failure! {
        name = minimum_wp_version_compares_numerically,
        rule = WpDeprecatedFunctionsRule,
        count = 1,
        settings = |s: &mut crate::settings::Settings| {
            // "4.10" must be treated as greater than "4.9", not compared as strings.
            s.rules.wp_deprecated_functions.config.minimum_wp_version = "4.10".to_string();
        },
        code = indoc! {r#"
            <?php

            $sites = wp_get_sites();
            $page = get_page_by_title('About');
        "#}
    }

    test_lint_failure! {
        name = unparsable_minimum_wp_version_flags_everything,
        rule = WpDeprecatedFunctionsRule,
        count = 1,
        settings = |s: &mut crate::settings::Settings| {
            s.rules.wp_deprecated_functions.config.minimum_wp_version = "banana".to_string();
        },
        code = indoc! {r#"
            <?php

            $page = get_page_by_title('About');
        "#}
    }
}
