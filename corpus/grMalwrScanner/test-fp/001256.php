<?php

// Make sure class does not already exist (Playing safe) and that the get function exists
if(!class_exists('BhittaniPlugin_kkStarRatings_Widget') && function_exists('kk_star_ratings_get')) :

class BhittaniPlugin_kkStarRatings_Widget extends WP_Widget
{
    // Runs when OBJECT DECLARED (Instanciated)
    public function __construct()
    {
        $widget_options = array(
        'classname' => 'kk-star-ratings-widget',
        'description' => 'Show top rated posts'
        );
        parent::__construct('BhittaniPlugin_kkStarRatings_Widget', 'kk Star Ratings', $widget_options);
    }
    // Outputs USER INTERFACE
    public function widget($args, $instance)
    {
        extract( $args, EXTR_SKIP );
        $title = ( !empty($instance['title']) ) ? $instance['title'] : 'Top Posts';
        $total = ( !empty($instance['noofposts']) ) ? $instance['noofposts'] : '5';
        $category = ( $instance['category'] ) ? $instance['category'] : false;
        $sr = ($instance['showrating']) ? true : false;

        echo $before_widget;
        echo $before_title . $title . $after_title;

        // OUTPUT starts
        $posts = kk_star_ratings_get($total, $category);
        echo '<ul>';
        foreach ($posts as $post)
        {
           echo "<li><a href='".get_permalink($post->ID)."'>".$post->post_title."</a>";
           if($sr)
           {
               echo " <span style='font-size:10px;'>(".$post->ratings."/5)</span>";
           }
           echo "</li>";
        }
        echo '</ul>';
        // OUTPUT ends

        echo $after_widget;
    }
    // Updates OPTIONS
    /*
    public function update()
    {

    }
    */
    // The option FORM
    public function form( $instance )
    {
        ?>
        <p>
            <label for="<?php echo $this->get_field_id('title'); ?>">Title:
            <input id="<?php echo $this->get_field_id('title'); ?>" name="<?php echo $this->get_field_name('title'); ?>" type="text" value="<?php echo esc_attr(!empty($instance['title'])?$instance['title']: 'Top Posts'); ?>" /></label>
        </p>
        <p>
            <label for="<?php echo $this->get_field_id('noofposts'); ?>">No of Posts:
            <input id="<?php echo $this->get_field_id('noofposts'); ?>" name="<?php echo $this->get_field_name('noofposts'); ?>" type="text" value="<?php echo esc_attr(!empty($instance['noofposts'])?$instance['noofposts']: '5'); ?>" size="3" /></label>
        </p>
        <p>
            <label for="<?php echo $this->get_field_id('showrating'); ?>">Show Average?:
            <select id="<?php echo $this->get_field_id('showrating'); ?>" name="<?php echo $this->get_field_name('showrating'); ?>">
                <option value="0" <?php if(isset($instance['showrating']) && !esc_attr($instance['showrating'])){echo "selected='selected'";} ?>>No</option>
                <option value="1" <?php if(isset($instance['showrating']) && esc_attr($instance['showrating'])){echo "selected='selected'";} ?>>Yes</option>
            </select>
            </label>
        </p>
        <p>
            <label for="<?php echo $this->get_field_id('category'); ?>">Filter by Category:
            <select id="<?php echo $this->get_field_id('category'); ?>" name="<?php echo $this->get_field_name('category'); ?>">
            <option value="0">Select</option>
            <?php
                foreach(get_categories(array()) as $category)
                {
                    echo '<option value="'.$category->term_id.'"';
                    if(isset($instance['category']) && esc_attr($instance['category'])==$category->term_id)
                    echo ' selected="selected"';
                    echo '>'.$category->name.'</option>';
                }
            ?>
            </select>
            </label>
        </p>
        <?php
    }
}

if(!function_exists('kk_star_ratings_widget_init'))
{
    function kk_star_ratings_widget_init()
    {
        register_widget('BhittaniPlugin_kkStarRatings_Widget');
    }
    add_action('widgets_init', 'kk_star_ratings_widget_init');
}

endif;
