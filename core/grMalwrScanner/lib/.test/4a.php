<?php
// Exit if accessed directly
if (!defined('ABSPATH'))
    exit;

class BP_Group_Documents_Template {

    //category filtering
    public $category;
    public $parent_id;
    //Sorting
    public $order;
    private $sql_sort;
    private $sql_order;
    //Paging
    private $total_records;
    private $total_pages;
    private $page = 1;
    private $start_record = 1;
    private $end_record;
    private $items_per_page;
    //Misc
    public $action_link;
    //Top display - "list view"
    public $document_list;
    //bottom display - "detail view"
    public $show_detail = 0;
    public $name = '';
    public $description = '';
    public $group_categories = array();
    public $doc_categories = array();
    public $operation = 'add';
    public $featured;
    public $id = '';
    public $header;

    public function __construct() {
        $bp = buddypress();

    //the parent category id is used sometimes used in post_logic, but always in category_logic so we get it first
        $this->parent_id = self::get_parent_category_id();

        $this->do_post_logic();

        $this->do_url_logic();

        $this->do_category_logic();

        $this->do_sorting_logic();

        $this->do_paging_logic();

        $this->document_list = BP_Group_Documents::get_list_by_group($bp->groups->current_group->id, $this->category, $this->sql_sort, $this->sql_order, $this->start_record, $this->items_per_page);
    }

    /**
     *
     * @return type
     */
    public static function get_parent_category_id() {
        $bp = buddypress();
    $parent_info = term_exists("g" . $bp->groups->current_group->id, 'group-documents-category');

        if (!$parent_info) {
            $parent_info = wp_insert_term("g" . $bp->groups->current_group->id, 'group-documents-category');
        }
        return $parent_info['term_id'];
    }

    /**
     * do_post_logic()
     *
     * checks the POST array to see if user has submitted either a new document
     * or has updated a current document.  Creates objects, and used database methods to process
     * @version 1.2.2, 3/10/2013 stergatu, sanitize_text_field, add wp_verify
     */
    private function do_post_logic() {
        $bp = buddypress();
    if (isset($_POST['bp_group_documents_operation'])) {
            $nonce = $_POST['bp_group_document_save'];
            if ((!isset($nonce)) || (!wp_verify_nonce($nonce, 'bp_group_document_save_' . $_POST['bp_group_documents_operation']))) {
                bp_core_add_message(__('There was a security problem', 'bp-group-documents'), 'error');
                return false;
            }

            do_action('bp_group_documents_template_do_post_action');

            if (get_magic_quotes_gpc()) {
                $_POST = array_map('stripslashes_deep', $_POST);
            }

            switch ($_POST['bp_group_documents_operation']) {
                case 'add':
                    $document = new BP_Group_Documents();
                    $document->user_id = get_current_user_id();
                    $document->group_id = $bp->groups->current_group->id;
                    $document->name = sanitize_text_field($_POST['bp_group_documents_name']);
                    if (BP_GROUP_DOCUMENTS_ALLOW_WP_EDITOR)
                        $document->description = wp_filter_post_kses(wpautop($_POST['bp_group_documents_description']));
                    else
                        $document->description = wp_filter_post_kses(wpautop($_POST['bp_group_documents_description']));
                    $document->featured = apply_filters('bp_group_documents_featured_in', $_POST['bp_group_documents_featured']);
                    if ($document->save()) {
                        self::update_categories($document);
                        do_action('bp_group_documents_add_success', $document);
                        bp_core_add_message(__('Document successfully uploaded', 'bp-group-documents'));
                    }
                    break;
                case 'edit':
                    $document = new BP_Group_Documents($_POST['bp_group_documents_id']);
                    $document->name = sanitize_text_field($_POST['bp_group_documents_name']);
                    if (BP_GROUP_DOCUMENTS_ALLOW_WP_EDITOR)
                        $document->description = wp_filter_post_kses(wpautop($_POST['bp_group_documents_description']));
                    else
                        $document->description = wp_filter_post_kses(wpautop($_POST['bp_group_documents_description']));
                    $document->featured = apply_filters('bp_group_documents_featured_in', $_POST['bp_group_documents_featured']);
                    self::update_categories($document);
                    if ($document->save()) {
                        do_action('bp_group_documents_edit_success', $document);
                        bp_core_add_message(__('Document successfully edited', 'bp-group-documents'));
                    }
                    break;
            } //end switch
        } //end if operation
    }
}
