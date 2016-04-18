<?php

/**
 * Plugin Name: Another WordPress Classifieds Plugin (AWPCP)
 * Plugin URI: http://www.awpcp.com
 * Description: AWPCP - A plugin that provides the ability to run a free or paid classified ads service on your WP site. <strong>!!!IMPORTANT!!!</strong> It's always a good idea to do a BACKUP before you upgrade AWPCP!
 * Version: 3.6.4.1
 * Author: D. Rodenbaugh
 * License: GPLv2 or any later version
 * Author URI: http://www.skylineconsult.com
 * Text Domain: another-wordpress-classifieds-plugin
 * Domain Path: /languages
 */

/**
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * dcfunctions.php and filop.class.php used with permission of Dan Caragea, http://datemill.com
 * AWPCP Classifieds icon set courtesy of http://www.famfamfam.com/lab/icons/silk/
 */

if (preg_match('#' . basename(__FILE__) . '#', $_SERVER['PHP_SELF'])) {
    die('You are not allowed to call this page directly.');
}

define( 'AWPCP_BASENAME', basename( dirname( __FILE__ ) ) );
define( 'AWPCP_DIR', rtrim( plugin_dir_path( __FILE__ ), '/' ) );
define( 'AWPCP_URL', rtrim( plugin_dir_url( __FILE__ ), '/' ) );

define( 'AWPCP_LOWEST_FILTER_PRIORITY', 1000000 );

global $awpcp;

global $awpcp_plugin_data;
global $awpcp_db_version;

global $wpcontenturl;
global $wpcontentdir;
global $awpcp_plugin_path;
global $awpcp_plugin_url;
global $imagespath;
global $awpcp_imagesurl;

global $nameofsite;


// get_plugin_data accounts for about 2% of the cost of
// each request, defining the version manually is a less
// expensive way --wvega
require_once( ABSPATH . 'wp-admin/includes/plugin.php' );
$awpcp_plugin_data = get_plugin_data(__FILE__);
$awpcp_db_version = $awpcp_plugin_data['Version'];

$wpcontenturl = WP_CONTENT_URL;
$wpcontentdir = WP_CONTENT_DIR;
$awpcp_plugin_path = AWPCP_DIR;
$awpcp_plugin_url = AWPCP_URL;
$imagespath = $awpcp_plugin_path . '/resources/images';
$awpcp_imagesurl = $awpcp_plugin_url .'/resources/images';


// common
require_once(AWPCP_DIR . "/debug.php");
require_once(AWPCP_DIR . "/functions.php");
require_once( AWPCP_DIR . "/includes/functions/categories.php" );
require_once( AWPCP_DIR . "/includes/functions/deprecated.php" );
require( AWPCP_DIR . '/includes/functions/file-upload.php' );
require_once( AWPCP_DIR . "/includes/functions/format.php" );
require_once( AWPCP_DIR . "/includes/functions/hooks.php" );
require_once( AWPCP_DIR . "/includes/functions/listings.php" );
require_once( AWPCP_DIR . "/includes/functions/notifications.php" );
require_once( AWPCP_DIR . "/includes/functions/payments.php" );
require_once( AWPCP_DIR . "/includes/functions/routes.php" );
require( AWPCP_DIR . "/includes/functions/legacy.php" );

$nameofsite = awpcp_get_blog_name();

// cron
require_once(AWPCP_DIR . "/cron.php");

// API & Classes
require_once(AWPCP_DIR . "/includes/exceptions.php");

require_once(AWPCP_DIR . "/includes/compatibility/compatibility.php");
require_once( AWPCP_DIR . "/includes/compatibility/class-add-meta-tags-plugin-integration.php" );
require_once(AWPCP_DIR . "/includes/compatibility/class-all-in-one-seo-pack-plugin-integration.php");
require( AWPCP_DIR . "/includes/compatibility/class-facebook-button-plugin-integration.php");
require_once(AWPCP_DIR . "/includes/compatibility/class-facebook-plugin-integration.php");
require_once( AWPCP_DIR . '/includes/compatibility/class-facebook-all-plugin-integration.php' );
require( AWPCP_DIR . "/includes/compatibility/class-profile-builder-plugin-integration.php");
require( AWPCP_DIR . "/includes/compatibility/class-profile-builder-login-form-implementation.php");
require_once( AWPCP_DIR . "/includes/compatibility/class-yoast-wordpress-seo-plugin-integration.php" );
require_once( AWPCP_DIR . "/includes/compatibility/class-woocommerce-plugin-integration.php" );
require( AWPCP_DIR . "/includes/compatibility/class-wp-members-login-form-implementation.php");
require( AWPCP_DIR . "/includes/compatibility/class-wp-members-plugin-integration.php");

require_once( AWPCP_DIR . "/includes/functions/settings.php" );

require_once( AWPCP_DIR . "/includes/form-fields/class-form-field.php" );
require_once( AWPCP_DIR . "/includes/form-fields/class-form-fields.php" );
require_once( AWPCP_DIR . "/includes/form-fields/class-listing-form-fields.php" );
require_once( AWPCP_DIR . "/includes/form-fields/class-listing-contact-name-form-field.php" );
require_once( AWPCP_DIR . "/includes/form-fields/class-listing-contact-email-form-field.php" );
require_once( AWPCP_DIR . "/includes/form-fields/class-listing-contact-phone-form-field.php" );
require_once( AWPCP_DIR . "/includes/form-fields/class-listing-details-form-field.php" );
require_once( AWPCP_DIR . "/includes/form-fields/class-listing-price-form-field.php" );
require_once( AWPCP_DIR . "/includes/form-fields/class-listing-regions-form-field.php" );
require_once( AWPCP_DIR . "/includes/form-fields/class-listing-title-form-field.php" );
require_once( AWPCP_DIR . "/includes/form-fields/class-listing-website-form-field.php" );

require_once( AWPCP_DIR . "/includes/helpers/class-easy-digital-downloads.php" );
require_once( AWPCP_DIR . "/includes/helpers/class-licenses-manager.php" );
require_once( AWPCP_DIR . '/includes/helpers/class-module.php' );
require_once( AWPCP_DIR . "/includes/helpers/class-modules-manager.php" );
require_once( AWPCP_DIR . "/includes/helpers/class-modules-updater.php" );

require_once( AWPCP_DIR . '/includes/helpers/class-admin-page-links-builder.php' );
require_once(AWPCP_DIR . "/includes/helpers/class-akismet-wrapper-base.php");
require_once(AWPCP_DIR . "/includes/helpers/class-akismet-wrapper.php");
require_once(AWPCP_DIR . "/includes/helpers/class-akismet-wrapper-factory.php");
require_once(AWPCP_DIR . "/includes/helpers/class-awpcp-request.php");
require_once( AWPCP_DIR . '/includes/helpers/class-facebook-cache-helper.php' );
require_once(AWPCP_DIR . "/includes/helpers/class-file-cache.php");
require_once( AWPCP_DIR . "/includes/helpers/class-http.php" );
require_once( AWPCP_DIR . "/includes/helpers/class-listing-akismet-data-source.php" );
require_once( AWPCP_DIR . "/includes/helpers/class-listing-renderer.php" );
require_once( AWPCP_DIR . "/includes/helpers/class-listing-reply-akismet-data-source.php" );
require_once( AWPCP_DIR . "/includes/helpers/class-page-title-builder.php" );
require_once( AWPCP_DIR . "/includes/helpers/class-payment-transaction-helper.php" );
require_once( AWPCP_DIR . "/includes/helpers/class-send-listing-to-facebook-helper.php" );
require_once( AWPCP_DIR . "/includes/helpers/class-send-to-facebook-helper.php" );
require_once( AWPCP_DIR . "/includes/helpers/class-spam-filter.php" );
require_once( AWPCP_DIR . "/includes/helpers/class-spam-submitter.php" );
require_once( AWPCP_DIR . '/includes/helpers/facebook.php' );
require_once(AWPCP_DIR . "/includes/helpers/list-table.php");
require_once(AWPCP_DIR . "/includes/helpers/email.php");
require_once(AWPCP_DIR . "/includes/helpers/javascript.php");
require_once(AWPCP_DIR . "/includes/helpers/captcha.php");
require_once(AWPCP_DIR . "/includes/helpers/widgets/categories-dropdown.php");
require_once(AWPCP_DIR . "/includes/helpers/widgets/multiple-region-selector.php");
require_once(AWPCP_DIR . "/includes/helpers/widgets/class-asynchronous-tasks-component.php");
require_once(AWPCP_DIR . "/includes/helpers/widgets/class-listing-actions-component.php");
require_once( AWPCP_DIR . "/includes/helpers/widgets/class-listing-form-steps-component.php" );
require_once(AWPCP_DIR . "/includes/helpers/widgets/class-user-field.php");
require_once(AWPCP_DIR . "/includes/helpers/widgets/class-users-dropdown.php");
require_once(AWPCP_DIR . "/includes/helpers/widgets/class-users-autocomplete.php");

require_once( AWPCP_DIR . "/includes/listings/class-listings-finder.php" );
require_once( AWPCP_DIR . "/includes/listings/class-listing-action.php" );
require_once( AWPCP_DIR . "/includes/listings/class-listing-action-with-confirmation.php" );
require_once( AWPCP_DIR . "/includes/listings/class-delete-listing-action.php" );

require_once( AWPCP_DIR . "/includes/meta/class-meta-tags-generator.php" );
require_once( AWPCP_DIR . "/includes/meta/class-tag-renderer.php" );

require_once(AWPCP_DIR . "/includes/models/class-media.php");
require_once(AWPCP_DIR . "/includes/models/ad.php");
require_once(AWPCP_DIR . "/includes/models/category.php");
require_once(AWPCP_DIR . "/includes/models/image.php");
require_once(AWPCP_DIR . "/includes/models/payment-transaction.php");

require_once( AWPCP_DIR . "/includes/db/class-database-column-creator.php" );
require( AWPCP_DIR . "/includes/db/class-database-helper.php" );

require_once( AWPCP_DIR . "/includes/views/class-ajax-handler.php" );
require_once( AWPCP_DIR . "/includes/views/class-base-page.php" );
require_once( AWPCP_DIR . "/includes/views/class-file-action-ajax-handler.php" );
require_once( AWPCP_DIR . "/includes/views/class-step-decorator.php" );
require_once( AWPCP_DIR . "/includes/views/class-payment-step-decorator.php" );
require_once( AWPCP_DIR . "/includes/views/class-prepare-transaction-for-payment-step-decorator.php" );
require_once( AWPCP_DIR . "/includes/views/class-set-credit-plan-step-decorator.php" );
require_once( AWPCP_DIR . "/includes/views/class-set-payment-method-step-decorator.php" );
require_once( AWPCP_DIR . "/includes/views/class-set-transaction-status-to-open-step-decorator.php" );
require_once( AWPCP_DIR . "/includes/views/class-set-transaction-status-to-checkout-step-decorator.php" );
require_once( AWPCP_DIR . "/includes/views/class-set-transaction-status-to-completed-step-decorator.php" );
require_once( AWPCP_DIR . "/includes/views/class-skip-payment-step-if-payment-is-not-required.php" );
require_once( AWPCP_DIR . "/includes/views/class-users-autocomplete-ajax-handler.php" );
require_once( AWPCP_DIR . "/includes/views/class-verify-credit-plan-was-set-step-decorator.php" );
require_once( AWPCP_DIR . "/includes/views/class-verify-payment-can-be-processed-step-decorator.php" );
require_once( AWPCP_DIR . "/includes/views/class-verify-transaction-exists-step-decorator.php" );
// load frontend views first, some frontend pages are required in admin pages
require_once( AWPCP_DIR . '/includes/views/frontend/buy-credits/class-buy-credits-page.php');
require_once( AWPCP_DIR . "/includes/views/frontend/buy-credits/class-buy-credits-page-select-credit-plan-step.php" );
require_once( AWPCP_DIR . "/includes/views/frontend/buy-credits/class-buy-credits-page-checkout-step.php" );
require_once( AWPCP_DIR . "/includes/views/frontend/buy-credits/class-buy-credits-page-payment-completed-step.php" );
require_once( AWPCP_DIR . "/includes/views/frontend/buy-credits/class-buy-credits-page-final-step.php" );
require_once( AWPCP_DIR . "/includes/views/frontend/class-categories-list-walker.php" );
require_once( AWPCP_DIR . "/includes/views/frontend/class-categories-renderer.php" );
require_once( AWPCP_DIR . "/includes/views/frontend/class-category-shortcode.php" );
require_once( AWPCP_DIR . "/includes/views/admin/class-fee-payment-terms-notices.php" );
require_once( AWPCP_DIR . "/includes/views/admin/class-credit-plans-notices.php" );
require_once( AWPCP_DIR . "/includes/views/admin/class-categories-checkbox-list-walker.php" );
require_once( AWPCP_DIR . "/includes/views/admin/listings/class-listing-action-admin-page.php" );
require_once( AWPCP_DIR . "/includes/views/admin/listings/class-renew-listings-admin-page.php" );
require_once( AWPCP_DIR . "/includes/views/admin/listings/class-send-listing-to-facebook-admin-page.php" );
require_once( AWPCP_DIR . "/includes/views/admin/listings/class-listings-table-search-by-id-condition.php" );
require_once( AWPCP_DIR . "/includes/views/admin/listings/class-listings-table-search-by-keyword-condition.php" );
require_once( AWPCP_DIR . "/includes/views/admin/listings/class-listings-table-search-by-location-condition.php" );
require_once( AWPCP_DIR . "/includes/views/admin/listings/class-listings-table-search-by-payer-email-condition.php" );
require_once( AWPCP_DIR . "/includes/views/admin/listings/class-listings-table-search-by-title-condition.php" );
require_once( AWPCP_DIR . "/includes/views/admin/listings/class-listings-table-search-by-user-condition.php" );
require_once( AWPCP_DIR . "/includes/views/admin/listings/class-listings-table-search-conditions-parser.php" );
require_once( AWPCP_DIR . "/includes/views/admin/account-balance/class-account-balance-page.php" );
require_once( AWPCP_DIR . "/includes/views/admin/account-balance/class-account-balance-page-summary-step.php" );

require_once( AWPCP_DIR . '/includes/cron/class-task-queue.php' );
require_once( AWPCP_DIR . '/includes/cron/class-task-logic-factory.php' );
require_once( AWPCP_DIR . '/includes/cron/class-task-logic.php' );
require_once( AWPCP_DIR . '/includes/cron/class-tasks-collection.php' );
require_once( AWPCP_DIR . '/includes/cron/class-background-process.php' );

require_once( AWPCP_DIR . '/includes/media/class-listing-file-validator.php' );

require( AWPCP_DIR . '/includes/media/class-file-handlers-manager.php' );
require_once( AWPCP_DIR . '/includes/media/class-file-types.php' );
require_once( AWPCP_DIR . '/includes/media/class-file-uploader.php' );
require_once( AWPCP_DIR . '/includes/media/class-file-validation-errors.php' );
require_once( AWPCP_DIR . '/includes/media/class-filesystem.php' );
require( AWPCP_DIR . '/includes/media/class-image-dimensions-generator.php' );
require_once( AWPCP_DIR . '/includes/media/class-image-file-handler.php' );
require( AWPCP_DIR . '/includes/media/class-image-file-mover.php' );
require_once( AWPCP_DIR . '/includes/media/class-image-file-processor.php' );
require_once( AWPCP_DIR . '/includes/media/class-image-file-validator.php' );
require( AWPCP_DIR . '/includes/media/class-image-media-creator.php' );
require_once( AWPCP_DIR . '/includes/media/class-image-resizer.php' );
require( AWPCP_DIR . '/includes/media/class-listings-media-uploader-component.php' );
require_once( AWPCP_DIR . '/includes/media/class-listing-upload-limits.php' );
require( AWPCP_DIR . '/includes/media/class-listing-media-creator.php' );
require_once( AWPCP_DIR . "/includes/media/class-media-manager-component.php" );
require_once( AWPCP_DIR . "/includes/media/class-media-manager.php" );
require_once( AWPCP_DIR . '/includes/media/class-media-uploader-component.php' );
require_once( AWPCP_DIR . "/includes/media/class-messages-component.php" );
require_once( AWPCP_DIR . '/includes/media/class-mime-types.php' );
require_once( AWPCP_DIR . '/includes/media/class-uploaded-file-logic-factory.php' );
require_once( AWPCP_DIR . '/includes/media/class-uploaded-file-logic.php' );
require_once( AWPCP_DIR . '/includes/media/class-uploads-manager.php' );
require_once( AWPCP_DIR . '/includes/media/class-upload-listing-media-ajax-handler.php' );
require_once( AWPCP_DIR . '/includes/media/class-upload-generated-thumbnail-ajax-handler.php' );

require( AWPCP_DIR . "/includes/modules/class-license-settings-update-handler.php" );
require( AWPCP_DIR . "/includes/modules/class-license-settings-actions-request-handler.php" );

require_once( AWPCP_DIR . '/includes/placeholders/class-placeholders-installation-verifier.php' );

require_once( AWPCP_DIR . "/includes/settings/class-credit-system-settings.php" );
require_once( AWPCP_DIR . "/includes/settings/class-files-settings.php" );
require_once( AWPCP_DIR . "/includes/settings/class-form-fields-settings.php" );
require_once( AWPCP_DIR . "/includes/settings/class-general-settings.php" );
require_once( AWPCP_DIR . "/includes/settings/class-listings-moderation-settings.php" );
require_once( AWPCP_DIR . '/includes/settings/class-listing-url-settings.php' );
require_once( AWPCP_DIR . "/includes/settings/class-payment-general-settings.php" );
require_once( AWPCP_DIR . "/includes/settings/class-registration-settings.php" );
require_once( AWPCP_DIR . "/includes/settings/class-user-notifications-settings.php" );
require_once( AWPCP_DIR . "/includes/settings/class-window-title-settings.php" );

require( AWPCP_DIR . "/includes/upgrade/class-calculate-image-dimensions-upgrade-task-handler.php" );
require( AWPCP_DIR . "/includes/upgrade/class-database-tables.php" );
require_once( AWPCP_DIR . "/includes/upgrade/class-fix-empty-media-mime-type-upgrade-routine.php" );
require_once( AWPCP_DIR . "/includes/upgrade/class-manual-upgrade-tasks-manager.php" );
require_once( AWPCP_DIR . "/includes/upgrade/class-manual-upgrade-tasks.php" );
require_once( AWPCP_DIR . "/includes/upgrade/class-sanitize-media-filenames-upgrade-task-handler.php" );
require_once( AWPCP_DIR . "/includes/upgrade/class-upgrade-task-ajax-handler-factory.php" );
require_once( AWPCP_DIR . "/includes/upgrade/class-upgrade-task-ajax-handler.php" );

require_once( AWPCP_DIR . "/includes/upgrade/class-import-payment-transactions-task-handler.php" );
require_once( AWPCP_DIR . "/includes/upgrade/class-migrate-media-information-task-handler.php" );
require_once( AWPCP_DIR . "/includes/upgrade/class-migrate-regions-information-task-handler.php" );
require_once( AWPCP_DIR . "/includes/upgrade/class-update-media-status-task-handler.php" );

require_once( AWPCP_DIR . "/includes/wordpress/class-wordpress-scripts.php" );

require( AWPCP_DIR . '/includes/class-csv-importer.php' );

require_once( AWPCP_DIR . '/includes/class-edit-listing-url-placeholder.php' );
require_once( AWPCP_DIR . '/includes/class-edit-listing-link-placeholder.php' );

require_once( AWPCP_DIR . "/includes/class-listings-api.php" );
require_once( AWPCP_DIR . "/includes/class-cookie-manager.php" );
require( AWPCP_DIR . '/includes/class-default-login-form-implementation.php' );
require_once( AWPCP_DIR . "/includes/class-exceptions.php" );
require_once( AWPCP_DIR . "/includes/class-fees-collection.php" );
require_once( AWPCP_DIR . "/includes/class-listing-authorization.php" );
require_once( AWPCP_DIR . "/includes/class-listing-payment-transaction-handler.php" );
require_once( AWPCP_DIR . "/includes/class-listing-is-about-to-expire-notification.php" );
require_once( AWPCP_DIR . "/includes/class-listings-collection.php" );
require_once( AWPCP_DIR . "/includes/class-listings-metadata.php" );
require_once( AWPCP_DIR . "/includes/class-media-api.php" );
require_once( AWPCP_DIR . "/includes/class-missing-pages-finder.php" );
require_once( AWPCP_DIR . "/includes/class-pages-creator.php" );
require( AWPCP_DIR . '/includes/class-plugin-rewrite-rules.php' );
require( AWPCP_DIR . '/includes/class-rewrite-rules-helper.php' );
require_once( AWPCP_DIR . "/includes/class-roles-and-capabilities.php" );
require_once( AWPCP_DIR . "/includes/class-secure-url-redirection-handler.php" );
require_once( AWPCP_DIR . "/includes/class-users-collection.php" );
require_once(AWPCP_DIR . "/includes/payments-api.php");
require_once(AWPCP_DIR . "/includes/regions-api.php");
require_once(AWPCP_DIR . "/includes/settings-api.php");

require_once(AWPCP_DIR . "/includes/credit-plan.php");

require_once(AWPCP_DIR . "/includes/payment-term-type.php");
require_once(AWPCP_DIR . "/includes/payment-term.php");
require_once(AWPCP_DIR . "/includes/payment-term-fee-type.php");
require_once(AWPCP_DIR . "/includes/payment-term-fee.php");

require_once(AWPCP_DIR . "/includes/payment-gateway.php");
require_once(AWPCP_DIR . "/includes/payment-gateway-paypal-standard.php");
require_once(AWPCP_DIR . "/includes/payment-gateway-2checkout.php");

require_once(AWPCP_DIR . "/includes/payment-terms-table.php");

// installation functions
require( AWPCP_DIR . "/installer.php" );

// admin functions
require_once(AWPCP_DIR . "/admin/admin-panel.php");
require_once(AWPCP_DIR . "/admin/user-panel.php");
require_once( AWPCP_DIR . '/admin/pointers/class-drip-autoresponder-ajax-handler.php' );
require_once( AWPCP_DIR . '/admin/pointers/class-drip-autoresponder.php' );
require_once( AWPCP_DIR . '/admin/pointers/class-pointers-manager.php' );
require_once( AWPCP_DIR . '/admin/profile/class-user-profile-contact-information-controller.php' );
require_once( AWPCP_DIR . '/admin/class-page-name-monitor.php' );
require_once( AWPCP_DIR . '/admin/form-fields/class-form-fields-admin-page.php' );
require_once( AWPCP_DIR . '/admin/form-fields/class-form-fields-table-factory.php' );
require_once( AWPCP_DIR . '/admin/form-fields/class-form-fields-table.php' );
require_once( AWPCP_DIR . '/admin/form-fields/class-update-form-fields-order-ajax-handler.php' );

// frontend functions
require_once(AWPCP_DIR . "/frontend/placeholders.php");
require_once(AWPCP_DIR . "/frontend/ad-functions.php");
require_once(AWPCP_DIR . "/frontend/shortcode.php");

require( AWPCP_DIR . '/frontend/class-categories-selector-component.php' );
require( AWPCP_DIR . '/frontend/class-categories-renderer-factory.php' );
require( AWPCP_DIR . '/frontend/class-image-placeholders.php' );
require( AWPCP_DIR . '/frontend/class-query.php' );
require_once(AWPCP_DIR . "/frontend/widget-search.php");
require_once(AWPCP_DIR . "/frontend/widget-latest-ads.php");
require_once(AWPCP_DIR . "/frontend/widget-random-ad.php");
require_once(AWPCP_DIR . "/frontend/widget-categories.php");


class AWPCP {

    public $installer = null;

    public $admin = null; // Admin section
    public $panel = null; // User Ad Management panel
    public $pages = null; // Frontend pages

    public $modules_manager;
    public $modules_updater;
    public $settings = null;
    public $payments = null;
    public $js = null;

    public $flush_rewrite_rules = false;

    public function __construct() {
        global $awpcp_db_version;

        $this->version = $awpcp_db_version;

        // stored options are loaded when the settings API is instatiated
        $this->settings = AWPCP_Settings_API::instance();
        $this->js = AWPCP_JavaScript::instance();
        $this->installer = AWPCP_Installer::instance();
        $this->manual_upgrades = awpcp_manual_upgrade_tasks();
    }

    public function bootstrap() {
        $this->rewrite_rules = awpcp_plugin_rewrite_rules();

        if ( $this->settings->get_option( 'activatelanguages' ) ) {
            awpcp_load_plugin_textdomain( __FILE__, 'another-wordpress-classifieds-plugin' );
        }

        $this->modules_manager = awpcp_modules_manager();

        // register settings, this will define default values for settings
        // that have never been stored
        $this->settings->register_settings();

        $this->setup_runtime_options();

        awpcp_register_activation_hook( __FILE__, array( $this->installer, 'activate' ) );

        add_action('plugins_loaded', array($this, 'setup'), 10);

        // register rewrite rules when the plugin file is loaded.
        // generate_rewrite_rules or rewrite_rules_array hooks are
        // too late to add rules using add_rewrite_rule function
        add_action( 'page_rewrite_rules', array( $this->rewrite_rules, 'add_rewrite_rules' ) );
        add_filter('query_vars', 'awpcp_query_vars');
    }

    private function setup_runtime_options() {
        $this->settings->set_runtime_option( 'easy-digital-downloads-store-url', 'http://awpcp.com' );
        $this->settings->set_runtime_option( 'image-mime-types', array( 'image/png', 'image/jpeg', 'image/jpg', 'image/gif' ) );

        // TODO: see if we can call setup_runtime_options after awpcp_register_settings action has fired!
        $uploads_dir_name = $this->settings->get_option( 'uploadfoldername', 'uploads' );
        $uploads_dir = implode( DIRECTORY_SEPARATOR, array( rtrim( WP_CONTENT_DIR, DIRECTORY_SEPARATOR ), $uploads_dir_name, 'awpcp' ) );
        $uploads_url = implode( '/', array( rtrim( WP_CONTENT_URL, '/' ), $uploads_dir_name, 'awpcp' ) );

        $this->settings->set_runtime_option( 'awpcp-uploads-dir', $uploads_dir );
        $this->settings->set_runtime_option( 'awpcp-uploads-url', $uploads_url );
    }

    /**
     * Check if AWPCP DB version corresponds to current AWPCP plugin version.
     *
     * @deprecated since 3.0.2
     */
    public function updated() {
        _deprecated_function( __FUNCTION__, '3.0.2', 'AWPCP::is_updated()' );
        return false;
    }

    /**
     * Check if AWPCP DB version corresponds to current AWPCP plugin version.
     */
    public function is_up_to_date() {
        global $awpcp_db_version;
        $installed = get_option('awpcp_db_version', '');
        // if installed version is greater than plugin version
        // not sure what to do. Downgrade is not currently supported.
        return version_compare($installed, $awpcp_db_version) === 0;
    }

    /**
     * Single entry point for AWPCP plugin.
     *
     * This is functional but still a work in progress...
     */
    public function setup() {
        global $wpdb;

        if (!$this->is_up_to_date()) {
            $this->installer->install_or_upgrade();
            // we can't call flush_rewrite_rules() because
            // $wp_rewrite is not available yet. It is initialized
            // after plugins_load hook is executed.
            $this->flush_rewrite_rules = true;
        }

        if (!$this->is_up_to_date()) {
            return;
        }

        $this->setup_register_settings_handlers();

        // Ad metadata integration.
        $wpdb->awpcp_admeta = AWPCP_TABLE_AD_META;

        $this->settings->setup();
        $this->modules_updater = awpcp_modules_updater();
        $this->payments = awpcp_payments_api();
        $this->listings = awpcp_listings_api();

        $this->manual_upgrades->register_upgrade_tasks();

        $this->admin = new AWPCP_Admin();
        $this->panel = new AWPCP_User_Panel();

        $this->compatibility = new AWPCP_Compatibility();
        $this->compatibility->load_plugin_integrations();

        add_action( 'generate_rewrite_rules', array( $this, 'clear_categories_list_cache' ) );

        add_action( 'init', array( $this->compatibility, 'load_plugin_integrations_on_init' ) );
        add_action( 'init', array($this, 'init' ));
        add_action( 'init', array($this, 'register_custom_style'), AWPCP_LOWEST_FILTER_PRIORITY );

        add_action('admin_notices', array($this, 'admin_notices'));
        add_action( 'admin_notices', array( $this->modules_manager, 'show_admin_notices' ) );

        add_action('awpcp_register_settings', array($this, 'register_settings'));
        add_action( 'awpcp-register-payment-term-types', array( $this, 'register_payment_term_types' ) );
        add_action( 'awpcp-register-payment-methods', array( $this, 'register_payment_methods' ) );

        add_filter( 'pre_set_site_transient_update_plugins', array( $this->modules_updater, 'filter_plugins_version_information' ) );
        add_filter( 'plugins_api', array( $this->modules_updater, 'filter_detailed_plugin_information' ), 10, 3 );
        add_filter( 'http_request_args', array( $this->modules_updater, 'filter_http_request_args' ), 10, 2 );

        add_action( 'wp_enqueue_scripts', array( $this, 'enqueue_scripts' ), 1000 );
        add_action( 'admin_enqueue_scripts', array( $this, 'enqueue_scripts' ), 1000 );
        add_action( 'wp_footer', array( $this, 'localize_scripts' ), 15000 );
        add_action( 'admin_footer', array( $this, 'localize_scripts' ), 15000 );

        // some upgrade operations can't be done in background.
        // if one those is pending, we will disable all other features
        // until the user executes the upgrade operaton
        $has_pending_manual_upgrades = $this->manual_upgrades->has_pending_tasks();

        if ( ! $has_pending_manual_upgrades ) {
            $this->pages = new AWPCP_Pages();

            add_action( 'awpcp-process-payment-transaction', array( $this, 'process_transaction_update_payment_status' ) );
            add_action( 'awpcp-process-payment-transaction', array( $this, 'process_transaction_notify_wp_affiliate_platform' ) );

            add_action( 'wp_ajax_awpcp-get-regions-options', array( $this, 'get_regions_options' ) );
            add_action( 'wp_ajax_nopriv_awpcp-get-regions-options', array( $this, 'get_regions_options' ) );

            // actions and filters from functions_awpcp.php
            add_action('phpmailer_init','awpcp_phpmailer_init_smtp');

            add_action('widgets_init', array($this, 'register_widgets'));

            if (get_awpcp_option('awpcppagefilterswitch') == 1) {
                add_filter('wp_list_pages_excludes', 'exclude_awpcp_child_pages');
            }

            awpcp_schedule_activation();

            $this->modules_manager->load_modules();
        } else if ( $has_pending_manual_upgrades && get_option( 'awpcp-activated' ) ) {
            delete_option( 'awpcp-activated' );
            wp_redirect( awpcp_get_admin_upgrade_url() );
            exit;
        }
    }

    public function setup_register_settings_handlers() {
        add_action( 'awpcp_register_settings', array( new AWPCP_RegistrationSettings, 'register_settings' ) );

        $general_settings = awpcp_general_settings();
        add_action( 'awpcp_register_settings', array( $general_settings, 'register_settings' ) );
        add_filter( 'awpcp_validate_settings_general-settings', array( $general_settings, 'validate_group_settings' ), 10, 2 );

        $user_notifications_settings = awpcp_user_notifications_settings();
        add_action( 'awpcp_register_settings', array( $user_notifications_settings, 'register_settings' ) );

        $listings_moderation_settings = new AWPCP_ListingsModerationSettings;
        add_action( 'awpcp_register_settings', array( $listings_moderation_settings, 'register_settings' ) );
        add_filter( 'awpcp_validate_settings', array( $listings_moderation_settings, 'validate_all_settings' ), 10, 2 );
        add_filter( 'awpcp_validate_settings_listings-settings', array( $listings_moderation_settings, 'validate_group_settings' ), 10, 2 );

        $window_title_settings = awpcp_window_title_settings();
        add_action( 'awpcp_register_settings', array( $window_title_settings, 'register_settings' ) );

        $listing_url_settings = awpcp_listing_url_settings();
        add_action( 'awpcp_register_settings', array( $listing_url_settings, 'register_settings' ) );

        $credit_system_settings = awpcp_credit_system_settings();
        add_action( 'awpcp_register_settings', array( $credit_system_settings, 'register_settings' ) );
        add_filter( 'awpcp_validate_settings_payment-settings', array( $credit_system_settings, 'validate_credit_system_settings' ), 10, 2 );

        $payment_general_settings = new AWPCP_PaymentGeneralSettings;
        add_action( 'awpcp_register_settings', array( $payment_general_settings, 'register_settings' ) );
        add_filter( 'awpcp_validate_settings_payment-settings', array( $payment_general_settings, 'validate_group_settings' ), 10, 2 );

        $files_settings = awpcp_files_settings();
        add_action( 'awpcp_register_settings', array( $files_settings, 'register_settings') );

        $form_fields_settings = awpcp_form_fields_settings();
        add_action( 'awpcp_register_settings', array( $form_fields_settings, 'register_settings' ) );
        add_action( 'awpcp-admin-settings-page--form-field-settings', array( $form_fields_settings, 'settings_header' ) );
    }

    public function init() {
        // load resources always required
        $facebook_cache_helper = awpcp_facebook_cache_helper();
        add_action( 'awpcp-clear-ad-facebook-cache', array( $facebook_cache_helper, 'handle_clear_cache_event_hook' ), 10, 1 );

        $send_new_listings_to_facebook_helper = awpcp_send_listing_to_facebook_helper();
        add_action( 'awpcp-listing-facebook-cache-cleared', array( $send_new_listings_to_facebook_helper, 'schedule_listing_if_necessary' ) );
        add_action( 'awpcp-send-listing-to-facebook', array( $send_new_listings_to_facebook_helper, 'send_listing_to_facebook' ) );

        add_action( 'awpcp-place-ad', array( $this, 'clear_categories_list_cache' ) );
        add_action( 'awpcp_approve_ad', array( $this, 'clear_categories_list_cache' ) );
        add_action( 'awpcp_edit_ad', array( $this, 'clear_categories_list_cache' ) );
        add_action( 'awpcp_disable_ad', array( $this, 'clear_categories_list_cache' ) );
        add_action( 'awpcp_delete_ad', array( $this, 'clear_categories_list_cache' ) );
        add_action( 'awpcp-category-added', array( $this, 'clear_categories_list_cache' ) );
        add_action( 'awpcp-category-edited', array( $this, 'clear_categories_list_cache' ) );
        add_action( 'awpcp-category-deleted', array( $this, 'clear_categories_list_cache' ) );
        add_action( 'awpcp-pages-updated', array( $this, 'clear_categories_list_cache' ) );
        add_action( 'awpcp-listings-imported', array( $this, 'clear_categories_list_cache' ) );

        add_filter( 'awpcp-listing-actions', array( $this, 'register_listing_actions' ), 10, 2 );

        // load resources required both in front end and admin screens, but not during ajax calls.
        if ( ! defined( 'DOING_AJAX' ) || ! DOING_AJAX ) {
            $listing_payment_transaction_handler = awpcp_listing_payment_transaction_handler();
            add_action( 'awpcp-transaction-status-updated', array( $listing_payment_transaction_handler, 'transaction_status_updated' ), 10, 2 );
            add_filter( 'awpcp-process-payment-transaction', array( $listing_payment_transaction_handler, 'process_payment_transaction' ) );

            add_action( 'awpcp-place-ad', array( $facebook_cache_helper, 'on_place_ad' ) );
            add_action( 'awpcp_approve_ad', array( $facebook_cache_helper, 'on_approve_ad' ) );
            add_action( 'awpcp_edit_ad', array( $facebook_cache_helper, 'on_edit_ad' ) );
        }

        if ( defined( 'DOING_CRON' ) && DOING_CRON ) {
            $task_queue = awpcp_task_queue();
            add_action( 'awpcp-task-queue-event', array( $task_queue, 'task_queue_event' ) );
            add_action( 'awpcp-task-queue-cron', array( $task_queue, 'task_queue_event' ) );
        } else if ( defined( 'DOING_AJAX' ) && DOING_AJAX ) {
            $this->ajax_setup();
        } else if ( is_admin() ) {
            // load resources required in admin screens only
            $controller = awpcp_user_profile_contact_information_controller();
            add_action( 'show_user_profile', array( $controller, 'show_contact_information_fields' ) );
            add_action( 'edit_user_profile', array( $controller, 'show_contact_information_fields' ) );
            add_action( 'personal_options_update', array( $controller, 'save_contact_information' ) );
            add_action( 'edit_user_profile_update', array( $controller, 'save_contact_information' ) );

            $monitor = awpcp_page_name_monitor();
            add_action( 'post_updated', array( $monitor, 'flush_rewrite_rules_if_plugin_pages_name_changes' ), 10, 3 );

            $pointers_manager = awpcp_pointers_manager();
            add_action( 'admin_enqueue_scripts', array( $pointers_manager, 'register_pointers' ) );
            add_action( 'admin_enqueue_scripts', array( $pointers_manager, 'setup_pointers' ) );

            if ( awpcp_current_user_is_admin() ) {
                // load resources required in admin screens only, visible to admin users only.
                add_action( 'admin_notices', array( awpcp_fee_payment_terms_notices(), 'dispatch' ) );
                add_action( 'admin_notices', array( awpcp_credit_plans_notices(), 'dispatch' ) );

                // TODO: do we really need to execute this every time the plugin settings are saved?
                $handler = awpcp_license_settings_update_handler();
                add_action( 'update_option_' . $this->settings->setting_name, array( $handler, 'process_settings' ), 10, 2 );

                $handler = awpcp_license_settings_actions_request_handler();
                add_action( 'wp_redirect', array( $handler, 'dispatch' ) );
            } else {
                // load resources required in admin screens only, visible to non-admin users only.
            }
        } else {
            // load resources required in frontend screens only.
            add_action( 'template_redirect', array( awpcp_secure_url_redirection_handler(), 'dispatch' ) );
        }

        add_filter( 'awpcp-content-placeholders', array( $this, 'register_content_placeholders' ) );

        $listing_form_fields = awpcp_listing_form_fields();
        add_filter(  'awpcp-form-fields', array( $listing_form_fields, 'register_listing_form_fields' ), 5, 1 );

        if (!get_option('awpcp_installationcomplete', 0)) {
            update_option('awpcp_installationcomplete', 1);
            awpcp_create_pages( __( 'AWPCP', 'another-wordpress-classifieds-plugin' ) );
            $this->flush_rewrite_rules = true;
        }

        if ( get_option( 'awpcp-enable-fix-media-mime-type-upgrde' ) ) {
            awpcp_fix_empty_media_mime_type_upgrade_routine()->run();
        }

        if ( $this->flush_rewrite_rules || get_option( 'awpcp-flush-rewrite-rules' ) ) {
            add_action( 'wp_loaded', 'flush_rewrite_rules' );
            update_option( 'awpcp-flush-rewrite-rules', false );
        }

        if ( get_option( 'awpcp-installed-or-upgraded' ) ) {
            $roles_and_capabilities = awpcp_roles_and_capabilities();
            add_action( 'wp_loaded', array( $roles_and_capabilities, 'setup_roles_capabilities' ) );

            delete_option( 'awpcp-installed-or-upgraded' );
        }

        $this->register_scripts();
        $this->register_notification_handlers();
    }

    private function ajax_setup() {
        $this->manual_upgrades->register_upgrade_task_handlers();

        // load resources required to handle Ajax requests only.
        $handler = awpcp_users_autocomplete_ajax_handler();
        add_action( 'wp_ajax_awpcp-autocomplete-users', array( $handler, 'ajax' ) );
        add_action( 'wp_ajax_nopriv_awpcp-autocomplete-users', array( $handler, 'ajax' ) );

        $handler = awpcp_set_file_as_primary_ajax_handler();
        add_action( 'wp_ajax_awpcp-set-file-as-primary', array( $handler, 'ajax' ) );
        add_action( 'wp_ajax_nopriv_awpcp-set-file-as-primary', array( $handler, 'ajax' ) );

        $handler = awpcp_update_file_enabled_status_ajax_handler();
        add_action( 'wp_ajax_awpcp-update-file-enabled-status', array( $handler, 'ajax' ) );
        add_action( 'wp_ajax_nopriv_awpcp-update-file-enabled-status', array( $handler, 'ajax' ) );

        $handler = awpcp_delete_file_ajax_handler();
        add_action( 'wp_ajax_awpcp-delete-file', array( $handler, 'ajax' ) );
        add_action( 'wp_ajax_nopriv_awpcp-delete-file', array( $handler, 'ajax' ) );

        $handler = awpcp_update_file_status_ajax_handler();
        add_action( 'wp_ajax_awpcp-approve-file', array( $handler, 'ajax' ) );
        add_action( 'wp_ajax_nopriv_awpcp-approve-file', array( $handler, 'ajax' ) );
        add_action( 'wp_ajax_awpcp-reject-file', array( $handler, 'ajax' ) );
        add_action( 'wp_ajax_nopriv_awpcp-reject-file', array( $handler, 'ajax' ) );

        $handler = awpcp_upload_listing_media_ajax_handler();
        add_action( 'wp_ajax_awpcp-upload-listing-media', array( $handler, 'ajax' ) );
        add_action( 'wp_ajax_nopriv_awpcp-upload-listing-media', array( $handler, 'ajax' ) );

        $handler = awpcp_upload_generated_thumbnail_ajax_handler();
        add_action( 'wp_ajax_awpcp-upload-generated-thumbnail', array( $handler, 'ajax' ) );
        add_action( 'wp_ajax_nopriv_awpcp-upload-generated-thumbnail', array( $handler, 'ajax' ) );

        $handler = awpcp_update_form_fields_order_ajax_handler();
        add_action( 'wp_ajax_awpcp-update-form-fields-order', array( $handler, 'ajax' ) );

        add_action( 'awpcp-file-handlers', array( $this, 'register_file_handlers' ) );

        $handler = awpcp_drip_autoresponder_ajax_handler();
        add_action( 'wp_ajax_awpcp-autoresponder-user-subscribed', array( $handler, 'ajax' ) );
        add_action( 'wp_ajax_awpcp-autoresponder-dismissed', array( $handler, 'ajax' ) );
    }

    public function admin_notices() {
        foreach (awpcp_get_property($this, 'errors', array()) as $error) {
            echo awpcp_print_error($error);
        }

        if ( ! function_exists( 'imagecreatefrompng' ) ) {
            echo $this->missing_gd_library_notice();
        }
    }

    private function missing_gd_library_notice() {
        $message = __( "AWPCP requires the graphics processing library GD and it is not installed. Contact your web host to fix this.", 'another-wordpress-classifieds-plugin' );
        $message = sprintf( '<strong>%s</strong> %s', __( 'Warning', 'another-wordpress-classifieds-plugin' ), $message );
        return awpcp_print_error( $message );
    }

    /**
     * Returns information about available and installed
     * premium modules.
     *
     * @since  3.0
     */
    public function get_premium_modules_information() {
        static $modules = null;

        if ( is_null( $modules ) ) {
            $modules = array(
                'attachments' => array(
                    'name' => __( 'Attachments', 'another-wordpress-classifieds-plugin' ),
                    'url' => 'http://awpcp.com/downloads/attachments-module/?ref=panel',
                    'installed' => defined( 'AWPCP_ATTACHMENTS_MODULE' ),
                    'version' => 'AWPCP_ATTACHMENTS_MODULE_DB_VERSION',
                    'required' => '3.6',
                ),
                'authorize.net' => array(
                    'name' => __(  'Authorize.Net', 'another-wordpress-classifieds-plugin'  ),
                    'url' => 'http://awpcp.com/downloads/authorizenet-module/?ref=user-panel',
                    'installed' => defined( 'AWPCP_AUTHORIZE_NET_MODULE' ),
                    'version' => 'AWPCP_AUTHORIZE_NET_MODULE_DB_VERSION',
                    'required' => '3.6',
                ),
                'buddypress-listings' => array(
                    'name' => __( 'BuddyPress Listings', 'another-wordpress-classifieds-plugin' ),
                    'url' => 'http://awpcp.com/downloads/buddypress-module/?ref=panel',
                    'installed' => defined( 'AWPCP_BUDDYPRESS_LISTINGS_MODULE_DB_VERSION' ),
                    'version' => 'AWPCP_BUDDYPRESS_LISTINGS_MODULE_DB_VERSION',
                    'required' => '3.6',
                ),
                'campaign-manager' => array(
                    'name' => __( 'Campaign Manager', 'another-wordpress-classifieds-plugin' ),
                    'url' => 'http://awpcp.com/premium-modules/campaign-manager-module/?ref=panel',
                    'installed' => defined( 'AWPCP_CAMPAIGN_MANAGER_MODULE' ),
                    'version' => 'AWPCP_CAMPAIGN_MANAGER_MODULE_DB_VERSION',
                    'required' => '3.6.4',
                ),
                'category-icons' => array(
                    'name' => __( 'Category Icons', 'another-wordpress-classifieds-plugin' ),
                    'url' => 'http://awpcp.com/downloads/category-icons-module/?ref=panel',
                    'installed' => defined( 'AWPCP_CATEGORY_ICONS_MODULE_DB_VERSION' ),
                    'version' => 'AWPCP_CATEGORY_ICONS_MODULE_DB_VERSION',
                    'required' => '3.6',
                ),
                'comments' => array(
                    'name' => __(  'Comments & Ratings', 'another-wordpress-classifieds-plugin'  ),
                    'url' => 'http://awpcp.com/downloads/comments-ratings-module/?ref=panel',
                    'installed' => defined( 'AWPCP_COMMENTS_MODULE' ),
                    'version' => 'AWPCP_COMMENTS_MODULE_VERSION',
                    'required' => '3.6',
                ),
                'coupons' => array(
                    'name' => __( 'Coupons/Discount', 'another-wordpress-classifieds-plugin' ),
                    'url' => 'http://awpcp.com/downloads/coupons-module/?ref=panel',
                    'installed' => defined( 'AWPCP_COUPONS_MODULE' ),
                    'version' => 'AWPCP_COUPONS_MODULE_DB_VERSION',
                    'required' => '3.6',
                ),
                'extra-fields' => array(
                    'name' => __( 'Extra Fields', 'another-wordpress-classifieds-plugin' ),
                    'url' => 'http://awpcp.com/downloads/extra-fields-module/?ref=panel',
                    'installed' => defined( 'AWPCP_EXTRA_FIELDS_MODULE' ),
                    'version' => 'AWPCP_EXTRA_FIELDS_MODULE_DB_VERSION',
                    'required' => '3.6',
                ),
                'featured-ads' => array(
                    'name' => __( 'Featured Ads', 'another-wordpress-classifieds-plugin' ),
                    'url' => 'http://awpcp.com/downloads/featured-ads-module/?ref=panel',
                    'installed' => defined( 'AWPCP_FEATURED_ADS_MODULE' ),
                    'version' => 'AWPCP_FEATURED_ADS_MODULE_DB_VERSION',
                    'required' => '3.6',
                ),
                'fee-per-category' => array(
                    'name' => __( 'Fee per Category', 'another-wordpress-classifieds-plugin' ),
                    'url' =>'http://awpcp.com/downloads/fee-category-module/?ref=panel',
                    'installed' => function_exists( 'awpcp_price_cats' ),
                    'version' => 'AWPCP_FPC_MODULE_DB_VERSION',
                    'required' => '3.6',
                ),
                'google-checkout' => array(
                    'name' => __( 'Google Checkout', 'another-wordpress-classifieds-plugin' ),
                    'url' => 'http://www.awpcp.com/premium-modules/google-checkout-module/?ref=panel',
                    'installed' => defined( 'AWPCP_GOOGLE_CHECKOUT_MODULE' ),
                    'version' => 'AWPCP_GOOGLE_CHECKOUT_MODULE_DB_VERSION',
                    'required' => '3.6',
                    'private' => true,
                ),
                'mark-as-sold' => array(
                    'name' => __( 'Mark as Sold', 'another-wordpress-classifieds-plugin' ),
                    'url' => 'http://awpcp.com/downloads/mark-as-sold-module/?ref=panel',
                    'installed' => defined( 'AWPCP_MARK_AS_SOLD_MODULE' ),
                    'version' => 'AWPCP_MARK_AS_SOLD_MODULE_DB_VERSION',
                    'required' => '3.6',
                ),
                'paypal-pro' => array(
                    'name' => __(  'PayPal Pro', 'another-wordpress-classifieds-plugin'  ),
                    'url' => 'http://awpcp.com/downloads/paypal-pro-module/?ref=user-panel',
                    'installed' => defined( 'AWPCP_PAYPAL_PRO_MODULE' ),
                    'version' => 'AWPCP_PAYPAL_PRO_MODULE_DB_VERSION',
                    'required' => '3.6',
                ),
                'region-control' => array(
                    'name' => __( 'Regions Control', 'another-wordpress-classifieds-plugin' ),
                    'url' => 'http://awpcp.com/downloads/regions-module/?ref=panel',
                    'installed' => defined( 'AWPCP_REGION_CONTROL_MODULE' ),
                    'version' => 'AWPCP_REGION_CONTROL_MODULE_DB_VERSION',
                    'required' => '3.6',
                ),
                'restricted-categories' => array(
                    'name' => __( 'Restricted Categories', 'another-wordpress-classifieds-plugin' ),
                    'url' => 'http://awpcp.com/premium-modules/restricted-categories-module?ref=panel',
                    'installed' => defined( 'AWPCP_RESTRICTED_CATEGORIES_MODULE' ),
                    'version' => 'AWPCP_RESTRICTED_CATEGORIES_MODULE_DB_VERSION',
                    'required' => '3.6',
                ),
                'rss' => array(
                    'name' => __( 'RSS', 'another-wordpress-classifieds-plugin' ),
                    'url' => 'http://awpcp.com/downloads/rss-feeds-module/?ref=panel',
                    'installed' => defined( 'AWPCP_RSS_MODULE' ),
                    'version' => 'AWPCP_RSS_MODULE_DB_VERSION',
                    'required' => '3.6',
                ),
                'subscriptions' => array(
                    'name' => __( 'Subscriptions', 'another-wordpress-classifieds-plugin' ),
                    'url' => 'http://awpcp.com/downloads/subscriptions-module/ ?ref=panel',
                    'installed' => defined( 'AWPCP_SUBSCRIPTIONS_MODULE' ),
                    'version' => 'AWPCP_SUBSCRIPTIONS_MODULE_DB_VERSION',
                    'required' => '3.6'
                ),
                'videos' => array(
                    'name' => __( 'Videos', 'another-wordpress-classifieds-plugin' ),
                    'url' => 'http://www.awpcp.com/premium-modules/',
                    'installed' => defined( 'AWPCP_VIDEOS_MODULE' ),
                    'version' => 'AWPCP_VIDEOS_MODULE_DB_VERSION',
                    'required' => '3.6',
                    'private' => true,
                ),
                'xml-sitemap' => array(
                    'name' => __( 'XML Sitemap', 'another-wordpress-classifieds-plugin'  ),
                    'url' => 'http://www.awpcp.com/premium-modules/',
                    'installed' => function_exists( 'awpcp_generate_ad_entries' ),
                    'version' => 'AWPCP_XML_SITEMAP_MODULE_DB_VERSION',
                    'required' => '3.6',
                ),
                'zip-code-search' => array(
                    'name' => __( 'ZIP Code Search Module', 'another-wordpress-classifieds-plugin' ),
                    'url' => 'http://www.awpcp.com/premium-modules/',
                    'installed' => defined( 'AWPCP_ZIP_CODE_SEARCH_MODULE_DB_VERSION' ),
                    'version' => 'AWPCP_ZIP_CODE_SEARCH_MODULE_DB_VERSION',
                    'required' => '3.6',
                    'private' => true,
                ),
            );
        }

        return $modules;
    }

    /**
     * @since 3.0.2
     */
    public function is_compatible_with( $module, $version ) {
        $modules = $this->get_premium_modules_information();

        if ( ! isset( $modules[ $module ] ) ) {
            return false;
        }

        if ( version_compare( $version, $modules[ $module ]['required'], '<' ) ) {
            return false;
        }

        return true;
    }

    /**
     * A good place to register all AWPCP standard scripts that can be
     * used from other sections.
     */
    public function register_scripts() {
        global $wp_styles;
        global $wp_scripts;

        global $awpcp_db_version;

        $js = AWPCP_URL . '/resources/js';
        $css = AWPCP_URL . '/resources/css';
        $vendors = AWPCP_URL . '/resources/vendors';

        /* vendors */

        if (isset($wp_scripts->registered['jquery-ui-core'])) {
            $ui_version = $wp_scripts->registered['jquery-ui-core']->ver;
        } else {
            $ui_version = '1.9.2';
        }

        wp_register_style('awpcp-jquery-ui', "//ajax.googleapis.com/ajax/libs/jqueryui/$ui_version/themes/smoothness/jquery-ui.css", array(), $ui_version);

        wp_register_script('awpcp-jquery-validate', "{$js}/jquery-validate/all.js", array('jquery'), '1.10.0', true);
        wp_register_script( 'awpcp-knockout', "//ajax.aspnetcdn.com/ajax/knockout/knockout-3.1.0.js", array(), '3.1.0', true );
        wp_register_script( 'awpcp-momentjs-with-locales', '//cdnjs.cloudflare.com/ajax/libs/moment.js/2.10.6/moment-with-locales.min.js', array(), '2.10.6', true );
        wp_register_script( 'awpcp-jquery-breakpoints', "{$js}/jquery-breakpoints/jquery-breakpoints.min.js", array('jquery'), $awpcp_db_version, true );

        /* helpers */

        wp_register_script(
            'awpcp',
            "{$js}/awpcp.min.js",
            array( 'jquery', 'backbone', 'awpcp-knockout', 'awpcp-jquery-breakpoints' ),
            $awpcp_db_version,
            true
        );

        wp_register_script( 'awpcp-admin', "{$js}/awpcp-admin.min.js", array( 'awpcp', 'awpcp-jquery-validate' ), $awpcp_db_version, true );

        wp_register_script( 'awpcp-billing-form', "{$js}/awpcp-billing-form.js", array( 'awpcp' ), $awpcp_db_version, true );
        wp_register_script( 'awpcp-multiple-region-selector', "{$js}/awpcp-multiple-region-selector.js", array( 'awpcp', 'awpcp-jquery-validate' ), $awpcp_db_version, true );

        wp_register_script('awpcp-admin-wp-table-ajax', "{$js}/admin-wp-table-ajax.js", array('jquery-form'), $awpcp_db_version, true);

        // register again with old name too (awpcp-table-ajax-admin), for backwards compatibility
        wp_register_script('awpcp-table-ajax-admin', "{$js}/admin-wp-table-ajax.js", array('jquery-form'), $awpcp_db_version, true);

        wp_register_script('awpcp-toggle-checkboxes', "{$js}/checkuncheckboxes.js", array('jquery'), $awpcp_db_version, true);

        /* admin */

        wp_register_style('awpcp-admin-style', "{$css}/awpcp-admin.css", array(), $awpcp_db_version);

        wp_register_script('awpcp-admin-general', "{$js}/admin-general.js", array('awpcp'), $awpcp_db_version, true);
        wp_register_script('awpcp-admin-settings', "{$js}/admin-settings.js", array('awpcp-admin'), $awpcp_db_version, true);
        wp_register_script('awpcp-admin-fees', "{$js}/admin-fees.js", array('awpcp-admin-wp-table-ajax'), $awpcp_db_version, true);
        wp_register_script('awpcp-admin-credit-plans', "{$js}/admin-credit-plans.js", array('awpcp-admin-wp-table-ajax'), $awpcp_db_version, true);
        wp_register_script( 'awpcp-admin-listings', "{$js}/admin-listings.js", array( 'awpcp', 'awpcp-admin-wp-table-ajax', 'plupload-all' ), $awpcp_db_version, true );
        wp_register_script('awpcp-admin-users', "{$js}/admin-users.js", array('awpcp-admin-wp-table-ajax'), $awpcp_db_version, true);
        wp_register_script( 'awpcp-admin-attachments', "{$js}/admin-attachments.js", array( 'awpcp' ), $awpcp_db_version, true );
        wp_register_script( 'awpcp-admin-import', "{$js}/admin-import.js", array( 'awpcp', 'jquery-ui-datepicker', 'jquery-ui-autocomplete' ), $awpcp_db_version, true );
        wp_register_script( 'awpcp-admin-form-fields', "{$js}/admin-form-fields.js", array( 'awpcp', 'jquery-ui-sortable', 'jquery-effects-highlight', 'jquery-effects-core' ), $awpcp_db_version, true );
        wp_register_script( 'awpcp-admin-manual-upgrade', "{$js}/admin-manual-upgrade.js", array( 'awpcp', 'awpcp-momentjs-with-locales' ), $awpcp_db_version, true );

        wp_register_script(
            'awpcp-admin-pointers',
            "{$js}/admin-pointers.min.js",
            array( 'awpcp', 'wp-pointer' ),
            $awpcp_db_version,
            true
        );

        /* frontend */

        wp_register_style('awpcp-frontend-style', "{$css}/awpcpstyle.css", array(), $awpcp_db_version);

        wp_register_style('awpcp-frontend-style-ie-6', "{$css}/awpcpstyle-ie-6.css", array('awpcp-frontend-style'), $awpcp_db_version);
        $wp_styles->add_data( 'awpcp-frontend-style-ie-6', 'conditional', 'lte IE 6' );

        wp_register_style( 'awpcp-frontend-style-lte-ie-7', "{$css}/awpcpstyle-lte-ie-7.css", array( 'awpcp-frontend-style' ), $awpcp_db_version );
        $wp_styles->add_data( 'awpcp-frontend-style-lte-ie-7', 'conditional', 'lte IE 7' );

        $dependencies = array( 'awpcp', 'awpcp-multiple-region-selector', 'awpcp-jquery-validate', 'jquery-ui-datepicker', 'jquery-ui-autocomplete', 'plupload-all' );
        wp_register_script( 'awpcp-page-place-ad', "{$js}/page-place-ad.js", $dependencies, $awpcp_db_version, true );

        $dependencies = array('awpcp', 'awpcp-multiple-region-selector', 'awpcp-jquery-validate', 'jquery-ui-datepicker');
        wp_register_script('awpcp-page-search-listings', "{$js}/page-search-listings.js", $dependencies, $awpcp_db_version, true);

        wp_register_script('awpcp-page-reply-to-ad', "{$js}/page-reply-to-ad.js", array('awpcp', 'awpcp-jquery-validate'), $awpcp_db_version, true);
        wp_register_script('awpcp-page-show-ad', "{$js}/page-show-ad.js", array('awpcp'), $awpcp_db_version, true);
    }

    public function register_custom_style() {
        global $awpcp_db_version;

        // load custom stylesheet if one exists in the wp-content/plugins directory:
        if (file_exists(WP_PLUGIN_DIR . '/awpcp_custom_stylesheet.css')) {
            wp_register_style('awpcp-custom-css', plugins_url('awpcp_custom_stylesheet.css'), array('awpcp-frontend-style'), $awpcp_db_version, 'all');
        }
    }

    public function enqueue_scripts() {
        if (is_admin()) {
            wp_enqueue_style('awpcp-admin-style');
            wp_enqueue_script('awpcp-admin-general');
            wp_enqueue_script('awpcp-toggle-checkboxes');
        } else {
            wp_enqueue_style('awpcp-frontend-style');
            wp_enqueue_style('awpcp-frontend-style-ie-6');
            wp_enqueue_style('awpcp-frontend-style-lte-ie-7');
            wp_enqueue_style('awpcp-custom-css');
        }

        if (is_admin()) {
            // TODO: migrate the code below to use set_js_data to pass information to AWPCP scripts.
            $options = array('ajaxurl' => awpcp_ajaxurl());
            wp_localize_script('awpcp-admin-general', 'AWPCPAjaxOptions', $options);
        }
    }

    public function localize_scripts() {
        $scripts = awpcp_wordpress_scripts();

        // localize jQuery Validate messages
        $this->js->set( 'default-validation-messages', array(
            'required' => __( 'This field is required.', 'another-wordpress-classifieds-plugin' ),
            'email' => __( 'Please enter a valid email address.', 'another-wordpress-classifieds-plugin' ),
            'url' => __( 'Please enter a valid URL.', 'another-wordpress-classifieds-plugin' ),
            'classifiedsurl' => __( 'Please enter a valid URL.', 'another-wordpress-classifieds-plugin' ),
            'number' => __( 'Please enter a valid number.', 'another-wordpress-classifieds-plugin' ),
            'money' => __( 'Please enter a valid amount.', 'another-wordpress-classifieds-plugin' ),
        ) );

        global $wp_locale;

        $this->js->localize( 'datepicker', array(
            // 'clearText' => _x( 'Clear', '[UI Datepicker] Display text for clear link', 'another-wordpress-classifieds-plugin' ),
            // 'clearStatus' => _x( 'Erase the current date', '[UI Datepicker] Status text for clear link', 'another-wordpress-classifieds-plugin' ),
            // 'closeText' => _x( 'Close', '[UI Datepicker] Display text for close link', 'another-wordpress-classifieds-plugin' ),
            // 'closeStatus' => _x( 'Close without change', '[UI Datepicker] Status text for close link', 'another-wordpress-classifieds-plugin' ),
            'prevText' => _x( '&#x3c;Prev', '[UI Datepicker] Display text for previous month link', 'another-wordpress-classifieds-plugin' ),
            // 'prevStatus' => _x( 'Show the previous month', '[UI Datepicker] Status text for previous month link', 'another-wordpress-classifieds-plugin' ),
            'nextText' => _x( 'Next&#x3e;', '[UI Datepicker] Display text for next month link', 'another-wordpress-classifieds-plugin' ),
            // 'nextStatus' => _x( 'Show the next month', '[UI Datepicker] Status text for next month link', 'another-wordpress-classifieds-plugin' ),
            // 'currentText' => _x( 'Today', '[UI Datepicker] Display text for current month link', 'another-wordpress-classifieds-plugin' ),
            // 'currentStatus' => _x( 'Show the current month', '[UI Datepicker] Status text for current month link', 'another-wordpress-classifieds-plugin' ),
            'monthNames' => array_values( $wp_locale->month ), // Names of months for drop-down and formatting
            'monthNamesShort' => array_values( $wp_locale->month_abbrev ), // For formatting
            // 'monthStatus' => _x( 'Show a different month', '[UI Datepicker] Status text for selecting a month', 'another-wordpress-classifieds-plugin' ),
            // 'yearStatus' => _x( 'Show a different year', '[UI Datepicker] Status text for selecting a year', 'another-wordpress-classifieds-plugin' ),
            // 'weekHeader' => _x( 'Wk', '[UI Datepicker] Header for the week of the year column', 'another-wordpress-classifieds-plugin' ),
            // 'weekStatus' => _x( 'Week of the year', '[UI Datepicker] Status text for the week of the year column', 'another-wordpress-classifieds-plugin' ),
            'dayNames' => array_values( $wp_locale->weekday ),
            'dayNamesShort' => array_values( $wp_locale->weekday_abbrev ), // For formatting
            'dayNamesMin' => array_values( $wp_locale->weekday_initial ), // Column headings for days starting at Sunday
            // 'dayStatus' => _x( 'Set DD as first week day', '[UI Datepicker] Status text for the day of the week selection', 'another-wordpress-classifieds-plugin' ),
            // 'dateStatus' => _x( 'Select DD, M d', '[UI Datepicker] Status text for the date selection', 'another-wordpress-classifieds-plugin' ),
            'firstDay' => intval( _x( '0', '[UI Datepicker] The first day of the week, Sun = 0, Mon = 1, ...', 'another-wordpress-classifieds-plugin' ) ),
            // 'initStatus' => _x( 'Select a date', '[UI Datepicker] Initial Status text on opening', 'another-wordpress-classifieds-plugin' ),
            'isRTL' => $wp_locale->text_direction == 'ltr' ? false : true // True if right-to-left language, false if left-to-right
        ) );

        $this->js->localize( 'media-uploader-beforeunload', array(
            'files-are-being-uploaded' => __( 'There are files currently being uploaded.', 'another-wordpress-classifieds-plugin' ),
            'files-pending-to-be-uploaded' => __( 'There are files pending to be uploaded.', 'another-wordpress-classifieds-plugin' ),
            'no-files-were-uploaded' => __( "You haven't uploaded any images or files.", 'another-wordpress-classifieds-plugin' ),
        ) );

        if ( $scripts->script_will_be_printed( 'awpcp' ) ) {
            $this->js->set( 'ajaxurl', awpcp_ajaxurl() );
            $this->js->print_data();
        }
    }

    public function register_content_placeholders( $placeholders ) {
        $handler = awpcp_edit_listing_url_placeholder();
        $placeholders['edit_listing_url'] = array( 'callback' => array( $handler, 'do_placeholder' ) );

        $handler = awpcp_edit_listing_link_placeholder();
        $placeholders['edit_listing_link'] = array( 'callback' => array( $handler, 'do_placeholder' ) );

        return $placeholders;
    }

    /**
     * Register other AWPCP settings, normally for private use.
     */
    public function register_settings() {
        $this->settings->add_setting('private:notices', 'show-quick-start-guide-notice', '', 'checkbox', false, '');
    }

    /**
     * @since 2.2.2
     */
    public function register_payment_term_types($payments) {
        $payments->register_payment_term_type(new AWPCP_FeeType);
    }

    /**
     * @since  2.2.2
     */
    public function register_payment_methods($payments) {
        if (get_awpcp_option('activatepaypal')) {
            $payments->register_payment_method(new AWPCP_PayPalStandardPaymentGateway);
        }

        if (get_awpcp_option('activate2checkout')) {
            $payments->register_payment_method(new AWPCP_2CheckoutPaymentGateway);
        }
    }

    /**
     * @since 3.0-beta
     */
    public function register_widgets() {
        register_widget("AWPCP_LatestAdsWidget");
        register_widget('AWPCP_RandomAdWidget');
        register_widget('AWPCP_Search_Widget');
        register_widget( 'AWPCP_CategoriesWidget' );
    }

    public function register_notification_handlers() {
        add_action( 'awpcp-media-uploaded', 'awpcp_send_listing_media_uploaded_notifications', 10, 2 );
    }

    public function register_file_handlers( $file_handlers ) {
        $file_handlers['image'] = array(
            'mime_types' => $this->settings->get_runtime_option( 'image-mime-types' ),
            'constructor' => 'awpcp_image_file_handler',
        );

        return $file_handlers;
    }


    /**------------------------------------------------------------------------
     * Payment Transaction Integration
     */

    /**
     * Set payment status to Not Required in requiredtransactions made by
     * admin users.
     *
     * TODO: move this into one of the steps decorator, when steps decorators become widely used.
     *
     * @since  2.2.2
     */
    public function process_transaction_update_payment_status($transaction) {
        switch ($transaction->get_status()) {
            case AWPCP_Payment_Transaction::STATUS_OPEN:
                if (awpcp_current_user_is_admin()/* || get_awpcp_option('freepay') == 0*/)
                    $transaction->payment_status = AWPCP_Payment_Transaction::PAYMENT_STATUS_NOT_REQUIRED;
                break;
        }
    }

    /**
     * WP Affiliate Platform integration.
     *
     * Notifies WP Affiliate Platform plugin when a transaction
     * that involves money exchange has been completed.
     *
     * @since 3.0.2
     */
    public function process_transaction_notify_wp_affiliate_platform($transaction) {
        if ( ! ( $transaction->is_payment_completed() || $transaction->is_completed() ) ) {
            return;
        }

        if ( $transaction->payment_is_not_required() ) {
            return;
        }

        if ( ! $transaction->was_payment_successful() ) {
            return;
        }

        $allowed_context = array( 'add-credit', 'place-ad', 'renew-ad', 'buy-subscription' );
        $context = $transaction->get('context');

        if ( ! in_array( $context, $allowed_context ) ) {
            return;
        }

        $amount = $transaction->get_total_amount();

        if ( $amount <= 0 ) {
            return;
        }

        $unique_transaction_id = $transaction->id;
        $referrer = isset( $_COOKIE['ap_id'] ) ? $_COOKIE['ap_id'] : null;
        $email = '';

        if ( $transaction->get( 'ad_id' ) ) {
            $ad = AWPCP_Ad::find_by_id( $transaction->get( 'ad_id' ) );
            $email = $ad->ad_contact_email;
        } else if ( $transaction->user_id ) {
            $user = get_userdata( $transaction->user_id );
            $email = $user->user_email;
        }

        $data = array(
            'sale_amt' => $amount,
            'txn_id'=> $unique_transaction_id,
            'referrer' => $referrer,
            'buyer_email' => $email,
        );

        do_action( 'wp_affiliate_process_cart_commission', $data );
    }

    /**
     * Handler for AJAX request from the Multiple Region Selector to get new options
     * for a given field.
     *
     * @since 3.0.2
     */
    public function get_regions_options() {
        $type = awpcp_request_param( 'type', '', $_GET );
        $parent_type = awpcp_request_param( 'parent_type', '', $_GET );
        $parent = stripslashes( awpcp_request_param( 'parent', '', $_GET ) );
        $context = awpcp_request_param( 'context', '', $_GET );

        $options = apply_filters( 'awpcp-get-regions-options', false, $type, $parent_type, $parent, $context );

        if ( $options === false ) {
            $options = array();

            if ( $context === 'search' && get_awpcp_option( 'buildsearchdropdownlists' ) ) {
                $regions = awpcp_basic_regions_api()->find_by_parent_name( $parent, $parent_type, $type );
            } else {
                $regions = array();
            }

            $regions = array_filter( $regions, 'strlen' );

            foreach ( $regions as $key => $option ) {
                $options[] = array( 'id' => $option, 'name' => $option );
            }
        }

        $response = array( 'status' => 'ok', 'options' => $options );

        header( "Content-Type: application/json" );
        echo json_encode($response);
        die();
    }

    /**
     * XXX: Used in Region Control installer.
     */
    public function clear_categories_list_cache() {
        $transient_keys = get_option( 'awpcp-categories-list-cache-keys', array() );
        foreach ( $transient_keys as $transient_key ) {
            delete_transient( $transient_key );
        }
        delete_option( 'awpcp-categories-list-cache-keys' );
    }

    public function register_listing_actions( $actions, $listing ) {
        $this->maybe_add_listing_action( $actions, $listing, new AWPCP_DeleteListingAction() );

        return $actions;
    }

    private function maybe_add_listing_action( &$actions, $listing, $action ) {
        if ( $action->is_enabled_for_listing( $listing ) ) {
            $actions[ $action->get_slug() ] = $action;
        }
    }
}

function awpcp() {
    global $awpcp;

    if (!is_object($awpcp)) {
        $awpcp = new AWPCP();
        $awpcp->bootstrap();
    }

    return $awpcp;
}

awpcp();


$uploadfoldername = get_awpcp_option('uploadfoldername', "uploads");

define('MAINUPLOADURL', $wpcontenturl .'/' .$uploadfoldername);
define('MAINUPLOADDIR', $wpcontentdir .'/' .$uploadfoldername);
define('AWPCPUPLOADURL', $wpcontenturl .'/' .$uploadfoldername .'/awpcp');
define('AWPCPUPLOADDIR', $wpcontentdir .'/' .$uploadfoldername .'/awpcp/');
define('AWPCPTHUMBSUPLOADURL', $wpcontenturl .'/' .$uploadfoldername .'/awpcp/thumbs');
define('AWPCPTHUMBSUPLOADDIR', $wpcontentdir .'/' .$uploadfoldername .'/awpcp/thumbs/');
define('MENUICO', $awpcp_imagesurl .'/menuico.png');

global $awpcpthumbsurl;
global $hascaticonsmodule;
global $hasregionsmodule;
global $haspoweredbyremovalmodule;
global $hasgooglecheckoutmodule;
global $hasextrafieldsmodule;
global $hasrssmodule;
global $hasfeaturedadsmodule;

$hasextrafieldsmodule = $hasextrafieldsmodule ? true : false;
$hasregionsmodule = $hasregionsmodule ? true : false;
$hasfeaturedadsmodule = $hasfeaturedadsmodule ? true : false;
$hasrssmodule = $hasrssmodule ? true : false;

$awpcpthumbsurl = AWPCPTHUMBSUPLOADURL;
$hascaticonsmodule = 0;
$haspoweredbyremovalmodule = 0;
$hasgooglecheckoutmodule = 0;

if (!defined('AWPCP_REGION_CONTROL_MODULE') && file_exists(AWPCP_DIR . "/awpcp_region_control_module.php")) {
    require_once(AWPCP_DIR . "/awpcp_region_control_module.php");
    $hasregionsmodule = true;
}

if (!defined('AWPCP_EXTRA_FIELDS_MODULE') && file_exists(AWPCP_DIR . "/awpcp_extra_fields_module.php")) {
    require_once(AWPCP_DIR . "/awpcp_extra_fields_module.php");
    $hasextrafieldsmodule = true;
}

if (!defined('AWPCP_RSS_MODULE') && file_exists(AWPCP_DIR . "/awpcp_rss_module.php")) {
    require_once(AWPCP_DIR . "/awpcp_rss_module.php");
    $hasrssmodule = true;
}

if (!defined('AWPCP_GOOGLE_CHECKOUT_MODULE') && file_exists(AWPCP_DIR . "/awpcp_google_checkout_module.php")) {
    require_once(AWPCP_DIR . "/awpcp_google_checkout_module.php");
    $hasgooglecheckoutmodule = true;
}

if (file_exists(AWPCP_DIR . "/awpcp_category_icons_module.php")) {
    require_once(AWPCP_DIR . "/awpcp_category_icons_module.php");
    $hascaticonsmodule=1;
}

if (file_exists(AWPCP_DIR . "/awpcp_remove_powered_by_module.php")) {
    require_once(AWPCP_DIR . "/awpcp_remove_powered_by_module.php");
    $haspoweredbyremovalmodule=1;
}


/**
 * Returns the IDs of the pages used by the AWPCP plugin.
 */
function exclude_awpcp_child_pages($excluded=array()) {
    global $wpdb, $table_prefix;

    $awpcp_page_id = awpcp_get_page_id_by_ref('main-page-name');

    if (empty($awpcp_page_id)) {
        return array();
    }

    $query = "SELECT ID FROM {$table_prefix}posts ";
    $query.= "WHERE post_parent=$awpcp_page_id AND post_content LIKE '%AWPCP%'";

    $child_pages = $wpdb->get_col( $query );

    if ( is_array( $child_pages ) ) {
        return array_merge( $child_pages, $excluded );
    } else {
        return $excluded;
    }
}



// PROGRAM FUNCTIONS

/**
 * Return an array of refnames for pages associated with one or more
 * rewrite rules.
 *
 * @since 2.1.3
 * @return array Array of page refnames.
 */
function awpcp_pages_with_rewrite_rules() {
    return array(
        'main-page-name',
        'show-ads-page-name',
        'reply-to-ad-page-name',
        'edit-ad-page-name',
        'browse-categories-page-name',
        'payment-thankyou-page-name',
        'payment-cancel-page-name'
    );
}

/**
 * Register AWPCP query vars
 */
function awpcp_query_vars($query_vars) {
    $vars = array(
        // API
        'awpcpx',
        'awpcp-module',
        'awpcp-action',
        'module',
        'action',

        // Payments API
        'awpcp-txn',

        // Listings API
        'awpcp-ad',
        'awpcp-hash',

        // misc
        "cid",
        "i",
        "id",
        "layout",
        "regionid",
    );

    return array_merge($query_vars, $vars);
}

/**
 * @since 3.2.1
 */
function awpcp_rel_canonical_url() {
    global $wp_the_query;

    if ( ! is_singular() )
        return false;

    if ( ! $page_id = $wp_the_query->get_queried_object_id() ) {
        return false;
    }

    if ( $page_id != awpcp_get_page_id_by_ref( 'show-ads-page-name' ) ) {
        return false;
    }

    $ad_id = intval( awpcp_request_param( 'id', '' ) );
    $ad_id = empty( $ad_id ) ? intval( get_query_var( 'id' ) ) : $ad_id;

    if ( empty( $ad_id ) ) {
        $url = get_permalink( $page_id );
    } else {
        $url = url_showad( $ad_id );
    }

    return $url;
}

/**
 * Set canonical URL to the Ad URL when in viewing on of AWPCP Ads.
 *
 * @since unknown
 * @since 3.2.1 logic moved to awpcp_rel_canonical_url()
 */
function awpcp_rel_canonical() {
    $url = awpcp_rel_canonical_url();

    if ( $url ) {
        echo "<link rel='canonical' href='$url' />\n";
    } else {
        rel_canonical();
    }
}


/**
 * Overwrittes WP canonicalisation to ensure our rewrite rules
 * work, even when the main AWPCP page is also the front page or
 * when the requested page slug is 'awpcp'.
 *
 * Required for the View Categories and Classifieds RSS rules to work
 * when AWPCP main page is also the front page.
 *
 * http://wordpress.stackexchange.com/questions/51530/rewrite-rules-problem-when-rule-includes-homepage-slug
 */
function awpcp_redirect_canonical($redirect_url, $requested_url) {
    global $wp_query;

    $awpcp_rewrite = false;
    $ids = awpcp_get_page_ids_by_ref(awpcp_pages_with_rewrite_rules());

    // do not redirect requests to AWPCP pages with rewrite rules
    if (is_page() && in_array(awpcp_request_param('page_id', 0), $ids)) {
        $awpcp_rewrite = true;

    // do not redirect requests to the front page, if any of the AWPCP pages
    // with rewrite rules is the front page
    } else if (is_page() && !is_feed() && isset($wp_query->queried_object) &&
              'page' == get_option('show_on_front') && in_array($wp_query->queried_object->ID, $ids) &&
               $wp_query->queried_object->ID == get_option('page_on_front'))
    {
        $awpcp_rewrite = true;
    }

    if ( $awpcp_rewrite ) {
        // Fix for #943.
        $requested_host = parse_url( $requested_url, PHP_URL_HOST );
        $redirect_host = parse_url( $redirect_url, PHP_URL_HOST );

        if ( $requested_host != $redirect_host ) {
            if ( strtolower( $redirect_host ) == ( 'www.' . $requested_host ) ) {
                return str_replace( $requested_host, 'www.' . $requested_host, $requested_url );
            } elseif ( strtolower( $requested_host ) == ( 'www.' . $redirect_host ) ) {
                return str_replace( 'www.', '', $requested_url );
            }
        }

        return $requested_url;
    }

    // $id = awpcp_get_page_id_by_ref('main-page-name');

    // // do not redirect direct requests to AWPCP main page
    // if (is_page() && !empty($_GET['page_id']) && $id == $_GET['page_id']) {
    //  $redirect_url = $requested_url;

    // // do not redirect request to the front page, if AWPCP main page is
    // // the front page
    // } else if (is_page() && !is_feed() && isset($wp_query->queried_object) &&
    //        'page' == get_option('show_on_front') && $id == $wp_query->queried_object->ID &&
    //         $wp_query->queried_object->ID == get_option('page_on_front'))
    // {
    //  $redirect_url = $requested_url;
    // }

    return $redirect_url;
}
add_filter('redirect_canonical', 'awpcp_redirect_canonical', 10, 2);
